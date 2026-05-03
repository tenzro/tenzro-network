#!/usr/bin/env bash
set -euo pipefail

# Tenzro Testnet Deployment Script
# Deploys the full testnet to GCP project tenzro-infra

PROJECT_ID="tenzro-infra"
REGION="us-central1"
ZONE="us-central1-a"
CLUSTER_NAME="tenzro-testnet"
REGISTRY="us-central1-docker.pkg.dev/${PROJECT_ID}/tenzro"
IMAGE_NAME="tenzro-node"
TERRAFORM_DIR="deploy/terraform"
K8S_DIR="deploy/kubernetes"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[DEPLOY]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    command -v gcloud >/dev/null 2>&1 || error "gcloud CLI not installed"
    command -v kubectl >/dev/null 2>&1 || error "kubectl not installed"
    command -v terraform >/dev/null 2>&1 || error "terraform not installed"
    command -v docker >/dev/null 2>&1 || error "docker not installed"

    # Verify authenticated
    gcloud auth print-access-token >/dev/null 2>&1 || error "Not authenticated. Run: gcloud auth login"

    # Force project to tenzro-infra — never deploy to the wrong project
    log "Setting active project to ${PROJECT_ID}..."
    gcloud config set project "$PROJECT_ID" --quiet

    # Double-check the project is correct
    ACTIVE_PROJECT=$(gcloud config get-value project 2>/dev/null)
    if [ "$ACTIVE_PROJECT" != "$PROJECT_ID" ]; then
        error "Failed to set project to ${PROJECT_ID}. Active project is '${ACTIVE_PROJECT}'"
    fi

    log "Prerequisites OK — project confirmed: ${PROJECT_ID}"
}

# Create Terraform state bucket if it doesn't exist
setup_terraform_state() {
    log "Setting up Terraform state bucket..."
    if ! gsutil ls "gs://tenzro-infra-terraform-state" >/dev/null 2>&1; then
        gsutil mb -p "$PROJECT_ID" -l "$REGION" "gs://tenzro-infra-terraform-state"
        gsutil versioning set on "gs://tenzro-infra-terraform-state"
        log "Created Terraform state bucket"
    else
        log "Terraform state bucket already exists"
    fi
}

# Enable required GCP APIs
enable_apis() {
    log "Enabling required GCP APIs..."
    gcloud services enable \
        container.googleapis.com \
        artifactregistry.googleapis.com \
        compute.googleapis.com \
        --project="$PROJECT_ID" \
        --quiet
    log "APIs enabled"
}

# Run Terraform
run_terraform() {
    log "Running Terraform..."
    cd "$TERRAFORM_DIR"

    terraform init -input=false
    terraform plan -out=tfplan
    terraform apply -input=false tfplan
    rm -f tfplan

    cd - >/dev/null
    log "Terraform apply complete"
}

# Configure kubectl
configure_kubectl() {
    log "Configuring kubectl..."
    gcloud container clusters get-credentials "$CLUSTER_NAME" \
        --zone "$ZONE" \
        --project "$PROJECT_ID"
    log "kubectl configured for cluster $CLUSTER_NAME"
}

# Build and push Docker image
build_and_push() {
    log "Building Docker image..."

    # Configure Docker for Artifact Registry (explicit project)
    gcloud auth configure-docker us-central1-docker.pkg.dev --quiet --project="$PROJECT_ID"

    # Build
    docker build -t "${REGISTRY}/${IMAGE_NAME}:latest" .

    # Tag with git SHA if available
    if command -v git >/dev/null 2>&1 && git rev-parse HEAD >/dev/null 2>&1; then
        GIT_SHA=$(git rev-parse --short HEAD)
        docker tag "${REGISTRY}/${IMAGE_NAME}:latest" "${REGISTRY}/${IMAGE_NAME}:${GIT_SHA}"
        log "Tagged image with SHA: ${GIT_SHA}"
    fi

    # Push
    log "Pushing Docker image..."
    docker push "${REGISTRY}/${IMAGE_NAME}:latest"
    if [ -n "${GIT_SHA:-}" ]; then
        docker push "${REGISTRY}/${IMAGE_NAME}:${GIT_SHA}"
    fi

    log "Docker image pushed to ${REGISTRY}/${IMAGE_NAME}"
}

# Deploy Kubernetes manifests
deploy_k8s() {
    log "Deploying Kubernetes manifests..."

    # Apply in dependency order
    kubectl apply -f "${K8S_DIR}/namespace.yaml"
    kubectl apply -f "${K8S_DIR}/configmap.yaml"
    kubectl apply -f "${K8S_DIR}/caddy-configmap.yaml"
    kubectl apply -f "${K8S_DIR}/services.yaml"
    kubectl apply -f "${K8S_DIR}/pdb.yaml"
    kubectl apply -f "${K8S_DIR}/network-policy.yaml"
    kubectl apply -f "${K8S_DIR}/caddy-deployment.yaml"
    kubectl apply -f "${K8S_DIR}/validator-statefulset.yaml"
    kubectl apply -f "${K8S_DIR}/rpc-deployment.yaml"

    log "Kubernetes manifests applied"
}

# Wait for rollouts
wait_for_rollouts() {
    log "Waiting for validator rollout (timeout: 10m)..."
    kubectl rollout status statefulset/tenzro-validator \
        -n tenzro-testnet --timeout=600s

    log "Waiting for RPC rollout (timeout: 5m)..."
    kubectl rollout status deployment/tenzro-rpc \
        -n tenzro-testnet --timeout=300s

    log "Waiting for Caddy rollout (timeout: 2m)..."
    kubectl rollout status deployment/caddy \
        -n tenzro-testnet --timeout=120s

    log "All rollouts complete"
}

# Print deployment info
print_info() {
    echo ""
    echo "============================================"
    echo "  Tenzro Testnet Deployment Complete"
    echo "============================================"
    echo ""

    # Get Caddy LoadBalancer external IP
    log "Fetching external IP (may take 1-2 minutes for LB provisioning)..."
    for i in $(seq 1 24); do
        EXTERNAL_IP=$(kubectl get svc caddy-lb -n tenzro-testnet \
            -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
        if [ -n "$EXTERNAL_IP" ] && [ "$EXTERNAL_IP" != "<pending>" ]; then
            break
        fi
        sleep 5
    done

    if [ -n "$EXTERNAL_IP" ] && [ "$EXTERNAL_IP" != "<pending>" ]; then
        echo -e "${GREEN}External IP: ${EXTERNAL_IP}${NC}"
        echo ""
        echo "DNS Configuration (name.com):"
        echo "  Add the following A records:"
        echo "    rpc.tenzro.network    → ${EXTERNAL_IP}"
        echo "    api.tenzro.network    → ${EXTERNAL_IP}"
        echo "    faucet.tenzro.network → ${EXTERNAL_IP}"
        echo ""
        echo "After DNS propagation, endpoints will be:"
        echo "  JSON-RPC:  https://rpc.tenzro.network"
        echo "  Web API:   https://api.tenzro.network"
        echo "  Faucet:    https://faucet.tenzro.network/faucet"
    else
        warn "LoadBalancer IP not yet available. Check with:"
        echo "  kubectl get svc caddy-lb -n tenzro-testnet"
    fi

    echo ""
    echo "Cluster status:"
    kubectl get pods -n tenzro-testnet
    echo ""
    kubectl get svc -n tenzro-testnet
    echo ""
}

# Main
main() {
    case "${1:-all}" in
        all)
            check_prerequisites
            enable_apis
            setup_terraform_state
            run_terraform
            configure_kubectl
            build_and_push
            deploy_k8s
            wait_for_rollouts
            print_info
            ;;
        infra)
            check_prerequisites
            enable_apis
            setup_terraform_state
            run_terraform
            configure_kubectl
            ;;
        build)
            check_prerequisites
            configure_kubectl
            build_and_push
            ;;
        deploy)
            check_prerequisites
            configure_kubectl
            deploy_k8s
            wait_for_rollouts
            print_info
            ;;
        status)
            configure_kubectl
            kubectl get pods -n tenzro-testnet
            echo ""
            kubectl get svc -n tenzro-testnet
            ;;
        ip)
            configure_kubectl
            kubectl get svc caddy-lb -n tenzro-testnet \
                -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
            echo ""
            ;;
        *)
            echo "Usage: $0 {all|infra|build|deploy|status|ip}"
            echo ""
            echo "  all    - Full deployment (infra + build + deploy)"
            echo "  infra  - Terraform only (GKE cluster + networking)"
            echo "  build  - Build and push Docker image only"
            echo "  deploy - Apply K8s manifests only"
            echo "  status - Show pod and service status"
            echo "  ip     - Show Caddy LoadBalancer external IP"
            exit 1
            ;;
    esac
}

main "$@"
