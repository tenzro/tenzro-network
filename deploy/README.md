# Tenzro Network Deployment

> **Start here:** [`validator-deployment.md`](validator-deployment.md) — the
> IaC-agnostic operator guide for running a Tenzro validator fleet on any
> cloud (GCE, EC2, Azure, Hetzner, bare metal, mixed). Covers sizing, port
> requirements, container image build, per-VM systemd layout, key generation,
> rolling upgrades, and observability.
>
> For per-node config reference, key rotation, snapshot/state-sync, and
> incident response, see [`../docs/operators/OPERATOR_GUIDE.md`](../docs/operators/OPERATOR_GUIDE.md).
>
> The Kubernetes manifests and GKE Terraform under this directory are
> **legacy reference material** retained as an example for operators who
> prefer Kubernetes. They are not required, and most validator deployments
> use plain VMs + systemd as described in `validator-deployment.md`.

## Legacy GKE Deployment (reference, not current)

This directory contains Kubernetes manifests and Terraform infrastructure-as-code
for an example GKE-based Tenzro deployment. The text below describes that
example, not the live testnet.

**GCP Project:** `tenzro-infra`
**GKE Cluster (example):** `tenzro-testnet` in `us-central1-a`
**Container Registry:** `us-central1-docker.pkg.dev/tenzro-infra/tenzro/tenzro-node`
**External IP:** `35.224.150.186` (LoadBalancer via Caddy)

**Exposed Services:**
- HTTPS (443) - Caddy reverse proxy (all traffic entry point)
- P2P (9000) - Validator networking (direct to pods)

**Internal Services:**
- JSON-RPC (8545) - Proxied via `rpc.tenzro.network`
- Web API (8080) - Proxied via `api.tenzro.network` (also serves `/faucet`)
- MCP (3001) - Proxied via `mcp.tenzro.network`
- A2A (3002) - Proxied via `a2a.tenzro.network`
- Solana MCP (3003) - Proxied via `solana-mcp.tenzro.network`
- Ethereum MCP (3004) - Proxied via `ethereum-mcp.tenzro.network`
- Canton MCP (3005) - Proxied via `canton-mcp.tenzro.network`
- LayerZero MCP (3006) - Proxied via `layerzero-mcp.tenzro.network`
- Chainlink MCP (3007) - Proxied via `chainlink-mcp.tenzro.network`
- Li.Fi MCP (3008) - Proxied via `lifi-mcp.tenzro.network`
- Metrics (9090) - Internal only

## Architecture

```
                         Internet
                            |
                            v
                    ┌──────────────┐
                    │ GCP LoadBalancer│ (35.224.150.186)
                    │   80/443      │
                    └───────┬───────┘
                            |
                    ┌───────▼───────┐
                    │     Caddy      │ (HTTPS termination + reverse proxy)
                    │   Deployment   │
                    └───────┬───────┘
                            |
            ┌───────────────┼───────────────┐
            |               |               |
    ┌───────▼────────┐  ┌──▼───────┐  ┌───▼─────────┐
    │  tenzro-rpc-   │  │ tenzro-  │  │  tenzro-    │
    │    internal    │  │validator │  │  validator  │
    │   (ClusterIP)  │  │ (Headless│  │ (Headless)  │
    └────────┬───────┘  │  Service)│  └─────────────┘
             |          └────┬─────┘
             |               |
    ┌────────▼─────────┐  ┌──▼────────────────────┐
    │   RPC Pod        │  │    Validator Nodes    │
    │  (Deployment)    │  │    (StatefulSet)      │
    │  1 replica       │  │    3 replicas         │
    │                  │  │                       │
    │ - Role: validator│  │ - Role: validator     │
    │ - persistent     │  │ - persistent 20Gi     │
    │   storage        │  │   volumes             │
    │ - MCP/A2A ports  │  │ - consensus           │
    │ - 6 ecosystem    │  │                       │
    │   MCP servers    │  │                       │
    └──────────────────┘  └───────────────────────┘
```

**Traffic Flow:**
1. External requests hit GCP LoadBalancer (35.224.150.186:443)
2. LoadBalancer forwards to Caddy pod
3. Caddy terminates TLS and routes by hostname:
   - `rpc.tenzro.network` -> `tenzro-rpc-internal:8545` (JSON-RPC)
   - `api.tenzro.network` -> `tenzro-rpc-internal:8080` (Web API + `/faucet`)
   - `mcp.tenzro.network` -> `tenzro-rpc-internal:3001` (Tenzro MCP)
   - `a2a.tenzro.network` -> `tenzro-rpc-internal:3002` (A2A protocol)
   - `solana-mcp.tenzro.network` -> `tenzro-rpc-internal:3003`
   - `ethereum-mcp.tenzro.network` -> `tenzro-rpc-internal:3004`
   - `canton-mcp.tenzro.network` -> `tenzro-rpc-internal:3005`
   - `layerzero-mcp.tenzro.network` -> `tenzro-rpc-internal:3006`
   - `chainlink-mcp.tenzro.network` -> `tenzro-rpc-internal:3007`
   - `lifi-mcp.tenzro.network` -> `tenzro-rpc-internal:3008`
4. RPC service forwards to RPC deployment pods
5. Validator P2P traffic (9000) bypasses Caddy and connects directly to validator headless service

**RPC pod role:** the RPC pod runs the same `tenzro-node` binary with `--role validator` and is effectively a 4th validator that also exposes the MCP, A2A, and ecosystem MCP surfaces. There is no "RPC-only" mode. When deploying a new image, all 4 pods (3 StatefulSet + 1 Deployment) need rolling.

**Security Model:**
- All RPC/API/metrics ports are firewalled at GCP level (deny external access)
- Only P2P port 9000 allows direct external access (for decentralized networking)
- All public traffic MUST go through Caddy LoadBalancer
- Caddy handles HTTPS termination with automatic Let's Encrypt certificates
- Internal services use ClusterIP (no external exposure)

## Directory Structure

```
deploy/
├── kubernetes/           # Kubernetes manifests
│   ├── namespace.yaml
│   ├── configmap.yaml           # Genesis configuration
│   ├── validator-statefulset.yaml
│   ├── rpc-deployment.yaml
│   ├── caddy-deployment.yaml    # Reverse proxy + HTTPS termination
│   ├── caddy-configmap.yaml     # Caddy routing configuration
│   ├── services.yaml
│   ├── pdb.yaml
│   └── network-policy.yaml
├── terraform/            # Terraform GCP infrastructure
│   ├── main.tf              # Backend configuration
│   ├── variables.tf
│   ├── terraform.tfvars     # Current deployment values
│   ├── gke.tf               # GKE cluster + node pools
│   ├── network.tf           # VPC, subnets, firewall rules
│   ├── registry.tf          # Artifact Registry
│   └── outputs.tf
├── monitoring/           # Monitoring configurations
│   ├── prometheus.yml
│   ├── grafana-dashboard.json
│   └── alerts.yml
└── README.md            # This file
```

## Infrastructure Overview

### GCP Resources (Terraform)

The Terraform configuration provisions:

- **GKE Cluster** (`tenzro-testnet`) in `us-central1-a`
- **VPC Network** (`tenzro-testnet-vpc`) with:
  - Primary subnet: `10.0.0.0/20`
  - Pod secondary range: `10.4.0.0/14`
  - Service secondary range: `10.8.0.0/20`
- **Node Pools:**
  - Validator pool: nodes for the 3-replica StatefulSet
  - RPC pool: 1 node for the RPC Deployment (which also runs `--role validator`)
  - Optional TEE pool: AMD SEV confidential VMs (disabled by default)
- **Artifact Registry** (`tenzro`) for Docker images
- **Firewall Rules:**
  - Allow P2P (9000) from internet
  - Allow RPC/API (8545, 8080, 9090) only from within VPC
  - Deny RPC/API from internet (enforced at priority 1000)
- **Terraform State:** GCS bucket `tenzro-infra-terraform-state`

### Kubernetes Resources

- **Namespace:** `tenzro-testnet`
- **ConfigMap:** Genesis configuration (validators, funded accounts, faucet)
- **StatefulSet:** 3 validator nodes (`tenzro-validator`) with persistent 20GB volumes
- **Deployment:** 1 RPC pod (`tenzro-rpc`) running `--role validator` and exposing the 6 ecosystem MCP servers (3003-3008) alongside Tenzro MCP (3001) and A2A (3002)
- **Deployment:** 1 Caddy reverse proxy with persistent 1GB volume (TLS certs)
- **Services:**
  - `tenzro-validator` (Headless) - P2P discovery
  - `tenzro-rpc-internal` (ClusterIP) - Internal RPC access
  - `tenzro-rpc-public` (ClusterIP) - Caddy backend
  - `caddy-lb` (LoadBalancer) - External traffic entry point
- **PodDisruptionBudget:** Ensures minimum 2 validators during updates
- **NetworkPolicies:** Restrict traffic between components

### Docker Image

The multi-stage Dockerfile builds the `tenzro-node` binary:

**Stage 1: Builder** (`rust:1.85-slim-bookworm`)
- Installs build dependencies: pkg-config, libssl-dev, clang, cmake, protobuf-compiler
- Uses clang as C/C++ compiler (required by llama-cpp-sys-2)
- Builds only `tenzro-node` crate (excludes desktop app)
- Output: `/build/target/release/tenzro-node`

**Stage 2: Runtime** (`debian:bookworm-slim`)
- Minimal runtime with ca-certificates, libssl3, curl
- Non-root user `tenzro` (UID/GID set by Kubernetes fsGroup)
- Exposes ports: 9000 (P2P), 8545 (RPC), 8080 (Web), 9090 (Metrics), 3001 (MCP), 3002 (A2A), 3003-3008 (ecosystem MCP)
- Health check on `http://localhost:8080/verify/health`
- Default data directory: `/data/tenzro`

## Prerequisites

### Required Tools

1. **gcloud CLI** (>= 469.0.0)
   ```bash
   # Install
   curl https://sdk.cloud.google.com | bash
   exec -l $SHELL

   # Verify
   gcloud version
   ```

2. **kubectl** (>= 1.28)
   ```bash
   # Install via gcloud
   gcloud components install kubectl

   # Verify
   kubectl version --client
   ```

3. **terraform** (>= 1.5)
   ```bash
   # macOS (Homebrew)
   brew tap hashicorp/tap
   brew install hashicorp/tap/terraform

   # Verify
   terraform version
   ```

4. **Docker** (optional, for local image builds)
   ```bash
   # macOS (Homebrew)
   brew install --cask docker
   ```

### GCP Project Setup

```bash
# Authenticate
gcloud auth login
gcloud auth application-default login

# Set project
gcloud config set project tenzro-infra

# Enable required APIs
gcloud services enable container.googleapis.com
gcloud services enable artifactregistry.googleapis.com
gcloud services enable compute.googleapis.com
gcloud services enable cloudresourcemanager.googleapis.com

# Verify
gcloud services list --enabled
```

### Terraform State Bucket (First-Time Setup)

The Terraform state is stored in GCS: `gs://tenzro-infra-terraform-state/testnet/`

If the bucket doesn't exist, create it:

```bash
gsutil mb -p tenzro-infra -l us-central1 gs://tenzro-infra-terraform-state
gsutil versioning set on gs://tenzro-infra-terraform-state
```

## Deployment Workflow

### Step 1: Provision Infrastructure

```bash
cd deploy/terraform

# Review current configuration
cat terraform.tfvars

# Initialize Terraform (downloads providers, connects to GCS backend)
terraform init

# Review planned changes
terraform plan

# Apply infrastructure changes
terraform apply

# Note the outputs
# - cluster_name: tenzro-testnet
# - registry_url: us-central1-docker.pkg.dev/tenzro-infra/tenzro
# - kubeconfig_command: gcloud container clusters get-credentials ...
```

**What Gets Created:**
- GKE cluster with validator pool + RPC pool
- VPC network with firewall rules
- Artifact Registry repository
- All resources tagged with `terraform:true`

**Typical Duration:** 5-10 minutes

### Step 2: Configure kubectl

```bash
# Get cluster credentials (output from terraform)
gcloud container clusters get-credentials tenzro-testnet \
  --zone us-central1-a \
  --project tenzro-infra

# Verify connection
kubectl cluster-info
kubectl get nodes
```

### Step 3: Build Docker Image

**Cloud Build (canonical path)**

Cloud Build uses a high-CPU machine for fast compilation. `n1-highcpu-32` is the largest `--machine-type` value accepted without a private worker pool; a typical release build completes in roughly 18 minutes.

```bash
# From repository root
cd /Users/hilarl/AI/tenzronetwork

TAG=$(date +%Y%m%d-%H%M%S)

gcloud builds submit \
  --tag us-central1-docker.pkg.dev/tenzro-infra/tenzro/tenzro-node:$TAG \
  --project=tenzro-infra \
  --machine-type=n1-highcpu-32 \
  --disk-size=200 \
  --timeout=3600s \
  .
```

**Image Tagging Strategy:**
- Timestamp tags `YYYYMMDD-HHMMSS` are the canonical scheme for direct deploys from the dev tree
- Git SHA tags (e.g. `:a36a421`) are produced when the image is built from a git checkout that has a meaningful commit
- Manifests reference an explicit tag — never `:latest`

### Step 4: Deploy Kubernetes Manifests

```bash
cd deploy/kubernetes

# Deploy in order (dependencies matter)

# 1. Create namespace
kubectl apply -f namespace.yaml

# 2. Deploy genesis configuration
kubectl apply -f configmap.yaml

# 3. Deploy Caddy configuration
kubectl apply -f caddy-configmap.yaml

# 4. Deploy validators (StatefulSet with persistent volumes)
kubectl apply -f validator-statefulset.yaml

# 5. Deploy RPC nodes (Deployment with ephemeral storage)
kubectl apply -f rpc-deployment.yaml

# 6. Deploy Caddy reverse proxy
kubectl apply -f caddy-deployment.yaml

# 7. Deploy services (headless, ClusterIP, LoadBalancer)
kubectl apply -f services.yaml

# 8. Deploy PodDisruptionBudget
kubectl apply -f pdb.yaml

# 9. Deploy NetworkPolicies
kubectl apply -f network-policy.yaml
```

**Or apply all at once:**

```bash
kubectl apply -f deploy/kubernetes/
```

**Note:** The LoadBalancer service (`caddy-lb`) will provision a GCP external IP. This may take 2-5 minutes.

### Step 5: Verify Deployment

```bash
# Check all resources
kubectl get all -n tenzro-testnet

# Watch validator pods come up (wait for 3/3 Running)
kubectl get pods -n tenzro-testnet -l component=validator -w

# Check validator logs
kubectl logs -n tenzro-testnet tenzro-validator-0 --tail=50
kubectl logs -n tenzro-testnet tenzro-validator-1 --tail=50

# Check RPC pod
kubectl get pods -n tenzro-testnet -l component=rpc

# Check Caddy pod
kubectl get pods -n tenzro-testnet -l component=caddy

# Get LoadBalancer external IP (should be 35.224.150.186)
kubectl get svc -n tenzro-testnet caddy-lb
```

**Expected Output:**
```
NAME      TYPE           CLUSTER-IP    EXTERNAL-IP      PORT(S)
caddy-lb  LoadBalancer   10.8.x.x      35.224.150.186   80:xxxxx/TCP,443:xxxxx/TCP
```

### Step 6: Test Endpoints

**Test via LoadBalancer IP (HTTP, Caddy not yet configured for domain):**

```bash
EXTERNAL_IP=$(kubectl get svc -n tenzro-testnet caddy-lb \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

# Health check (should work via IP until domains are configured)
curl http://$EXTERNAL_IP/verify/health

# Note: Domain-based routing requires DNS A records pointing to EXTERNAL_IP:
# rpc.tenzro.network -> 35.224.150.186
# api.tenzro.network -> 35.224.150.186
# mcp.tenzro.network -> 35.224.150.186
# a2a.tenzro.network -> 35.224.150.186
# solana-mcp.tenzro.network    -> 35.224.150.186
# ethereum-mcp.tenzro.network  -> 35.224.150.186
# canton-mcp.tenzro.network    -> 35.224.150.186
# layerzero-mcp.tenzro.network -> 35.224.150.186
# chainlink-mcp.tenzro.network -> 35.224.150.186
# lifi-mcp.tenzro.network      -> 35.224.150.186
```

**Test via domains (requires DNS configuration):**

```bash
# JSON-RPC
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Web API health
curl https://api.tenzro.network/verify/health

# Status endpoint
curl https://api.tenzro.network/status

# Faucet (POST request body) — served on api.tenzro.network at /faucet (no /api/ prefix)
curl -X POST https://api.tenzro.network/faucet \
  -H "Content-Type: application/json" \
  -d '{"address":"0x..."}'

# MCP protocol
curl -X POST https://mcp.tenzro.network/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'

# A2A agent discovery
curl https://a2a.tenzro.network/.well-known/agent.json
```

## Configuration

### Genesis Configuration

Edit `kubernetes/configmap.yaml` to customize:

```toml
chain_id = 1337
timestamp = 0

[[validators]]
public_key = "000...001"
stake = 10000

[[accounts]]
address = "000...010"
balance = 10000000

[faucet]
address = "000...ffffff"
amount_per_request = 100
cooldown_seconds = 86400  # 24 hours
enabled = true
```

After editing, redeploy:

```bash
kubectl apply -f kubernetes/configmap.yaml
kubectl rollout restart statefulset/tenzro-validator -n tenzro-testnet
kubectl rollout restart deployment/tenzro-rpc -n tenzro-testnet
```

### Resource Allocation

**Validators (per pod):**
- CPU: 500m (request), 1500m (limit)
- Memory: 1Gi (request), 3Gi (limit)
- Storage: 20Gi persistent SSD

**RPC Nodes (per pod):**
- CPU: 250m (request), 1 core (limit)
- Memory: 512Mi (request), 2Gi (limit)
- Storage: 20Gi ephemeral

**Caddy (per pod):**
- CPU: 100m (request), 500m (limit)
- Memory: 128Mi (request), 256Mi (limit)
- Storage: 1Gi persistent (TLS certificates)

Adjust in `validator-statefulset.yaml`, `rpc-deployment.yaml`, `caddy-deployment.yaml`:

```yaml
resources:
  requests:
    cpu: "1"
    memory: 2Gi
  limits:
    cpu: "2"
    memory: 4Gi
```

### Scaling

**Validators (maintain BFT quorum: 2f+1 where f is max faults):**

```bash
# Scale to 5 validators (tolerates 2 failures)
kubectl scale statefulset/tenzro-validator -n tenzro-testnet --replicas=5

# Update genesis configmap to match validator count
# Edit configmap.yaml to add validators 3 and 4
kubectl apply -f kubernetes/configmap.yaml
```

**RPC Nodes:**

```bash
# Scale to 2 RPC nodes
kubectl scale deployment/tenzro-rpc -n tenzro-testnet --replicas=2
```

**Caddy (single replica recommended for TLS cert consistency):**

Caddy should remain at 1 replica to avoid Let's Encrypt rate limits and cert synchronization issues. For HA, use a StatefulSet with shared PVC or external cert management.

### Caddy Routing

Edit `kubernetes/caddy-configmap.yaml` to add/modify routes:

```
# Example: Add new subdomain
new-service.tenzro.network {
  reverse_proxy tenzro-rpc-internal:8000

  log {
    output stdout
    format console
  }
}
```

After editing:

```bash
kubectl apply -f kubernetes/caddy-configmap.yaml
kubectl rollout restart deployment/caddy -n tenzro-testnet
```

### DNS Configuration

Point your domains to the LoadBalancer IP:

```
Type  Name                              Value
A     rpc.tenzro.network                35.224.150.186
A     api.tenzro.network                35.224.150.186
A     mcp.tenzro.network                35.224.150.186
A     a2a.tenzro.network                35.224.150.186
A     solana-mcp.tenzro.network         35.224.150.186
A     ethereum-mcp.tenzro.network       35.224.150.186
A     canton-mcp.tenzro.network         35.224.150.186
A     layerzero-mcp.tenzro.network      35.224.150.186
A     chainlink-mcp.tenzro.network      35.224.150.186
A     lifi-mcp.tenzro.network           35.224.150.186
```

Caddy will automatically provision Let's Encrypt TLS certificates for all domains.

### TEE Nodes (Optional)

Enable AMD SEV confidential computing for TEE providers:

```hcl
# In terraform/terraform.tfvars
enable_confidential_nodes = true
```

Then apply:

```bash
cd deploy/terraform
terraform apply
```

This creates a separate node pool with n2d-standard-4 confidential VMs.

## Monitoring and Troubleshooting

### GCP Cloud Console

- **Cluster Overview:** GKE > Clusters > tenzro-testnet
- **Workloads:** GKE > Workloads (view pods, deployments, statefulsets)
- **Services:** GKE > Services & Ingress
- **Logs:** GKE > Workloads > [select pod] > Logs
- **Metrics:** GKE > Clusters > tenzro-testnet > Monitoring

### kubectl Commands

**Pod Status:**

```bash
# All pods
kubectl get pods -n tenzro-testnet

# Validators only
kubectl get pods -n tenzro-testnet -l component=validator

# RPC nodes only
kubectl get pods -n tenzro-testnet -l component=rpc

# Caddy only
kubectl get pods -n tenzro-testnet -l component=caddy

# Watch pod status
kubectl get pods -n tenzro-testnet -w
```

**Logs:**

```bash
# Specific pod
kubectl logs -n tenzro-testnet tenzro-validator-0

# Last 100 lines
kubectl logs -n tenzro-testnet tenzro-validator-0 --tail=100

# Follow logs
kubectl logs -n tenzro-testnet tenzro-validator-0 -f

# Previous crashed container
kubectl logs -n tenzro-testnet tenzro-validator-0 --previous

# All validators
kubectl logs -n tenzro-testnet -l component=validator --all-containers=true

# RPC node
kubectl logs -n tenzro-testnet -l component=rpc

# Caddy access logs
kubectl logs -n tenzro-testnet -l component=caddy
```

**Describe Resources:**

```bash
# Pod details and events
kubectl describe pod -n tenzro-testnet tenzro-validator-0

# StatefulSet
kubectl describe statefulset -n tenzro-testnet tenzro-validator

# Service
kubectl describe svc -n tenzro-testnet caddy-lb

# PersistentVolumeClaim
kubectl describe pvc -n tenzro-testnet data-tenzro-validator-0
```

**Exec into Pod:**

```bash
# Get shell in validator pod
kubectl exec -it -n tenzro-testnet tenzro-validator-0 -- /bin/sh

# Run command
kubectl exec -n tenzro-testnet tenzro-validator-0 -- ls -la /data/tenzro
```

**Resource Usage:**

```bash
# Pod resource usage
kubectl top pods -n tenzro-testnet

# Node resource usage
kubectl top nodes
```

**Port Forwarding:**

```bash
# Forward validator RPC to localhost:8545
kubectl port-forward -n tenzro-testnet tenzro-validator-0 8545:8545

# Forward metrics to localhost:9090
kubectl port-forward -n tenzro-testnet tenzro-validator-0 9090:9090

# Access in another terminal
curl http://localhost:8545
curl http://localhost:9090/metrics
```

### Prometheus Metrics

Metrics are exposed on port 9090 of each node. To query:

```bash
# Port-forward to a validator
kubectl port-forward -n tenzro-testnet tenzro-validator-0 9090:9090

# In another terminal, fetch metrics
curl http://localhost:9090/metrics
```

Metrics include:
- Block height and finality
- Transaction throughput
- Consensus round duration
- P2P peer count
- VM execution time
- Memory and CPU usage

### Common Issues

**1. Pods in CrashLoopBackOff**

```bash
# Check logs of crashed container
kubectl logs -n tenzro-testnet <pod-name> --previous

# Check pod events
kubectl describe pod -n tenzro-testnet <pod-name>
```

Common causes:
- Genesis mismatch (all nodes must use same genesis)
- Insufficient resources (check node limits)
- Boot nodes unreachable (verify DNS resolution)
- Permission issues (check fsGroup and volume mounts)

**2. Validators Not Forming Consensus**

```bash
# Check validator logs for consensus messages
kubectl logs -n tenzro-testnet -l component=validator | grep -i "consensus\|vote\|prepare"

# Verify P2P connectivity between validators
kubectl exec -n tenzro-testnet tenzro-validator-0 -- netstat -an | grep 9000

# Check if all validators see each other as peers
kubectl logs -n tenzro-testnet tenzro-validator-0 | grep -i "peer\|connected"
```

Troubleshooting:
- Ensure StatefulSet replicas match genesis validator count
- Verify boot nodes environment variable is correct
- Check network policies aren't blocking P2P traffic
- Ensure at least 2f+1 validators are running (quorum)

**3. LoadBalancer Pending**

```bash
# Check service status
kubectl describe svc -n tenzro-testnet caddy-lb

# Verify GCP LoadBalancer provisioning
gcloud compute forwarding-rules list --project=tenzro-infra

# Check GCP quotas
gcloud compute project-info describe --project=tenzro-infra
```

If stuck:
- Verify GCP LoadBalancer quota (default: 5 per region)
- Check firewall rules aren't blocking LoadBalancer health checks
- Ensure GKE has `http_load_balancing` addon enabled

**4. Caddy Not Getting TLS Certificates**

```bash
# Check Caddy logs
kubectl logs -n tenzro-testnet -l component=caddy

# Common issues:
# - DNS not pointing to LoadBalancer IP
# - Rate limit hit (5 certs per domain per week)
# - Port 443 not accessible from internet
```

Workaround: Use HTTP for testing until DNS is properly configured.

**5. Image Pull Errors**

```bash
# Check pod events
kubectl describe pod -n tenzro-testnet <pod-name> | grep -i pull

# Verify image exists
gcloud artifacts docker images list \
  us-central1-docker.pkg.dev/tenzro-infra/tenzro/tenzro-node

# Ensure GKE nodes have permission to pull from Artifact Registry
gcloud projects get-iam-policy tenzro-infra
```

**6. Storage Issues**

```bash
# Check PVC status
kubectl get pvc -n tenzro-testnet

# Check PV status
kubectl get pv

# Describe PVC for events
kubectl describe pvc -n tenzro-testnet data-tenzro-validator-0
```

Common issues:
- StorageClass `standard-rwo` not available (should be default on GKE)
- Zone mismatch (PVC in one zone, node in another)
- Quota exceeded for persistent disks

## Maintenance

### Rolling Updates

When deploying a new image, all 4 pods (3 StatefulSet + 1 Deployment) need to be rolled — the RPC pod runs the same `tenzro-node` binary with `--role validator`.

```bash
TAG=<the same tag built above>

kubectl set image statefulset/tenzro-validator \
  -n tenzro-testnet \
  tenzro-node=us-central1-docker.pkg.dev/tenzro-infra/tenzro/tenzro-node:$TAG

kubectl set image deployment/tenzro-rpc \
  -n tenzro-testnet \
  tenzro-node=us-central1-docker.pkg.dev/tenzro-infra/tenzro/tenzro-node:$TAG

# Watch rollouts (StatefulSet rolls in reverse ordinal: 2 → 1 → 0)
kubectl rollout status statefulset/tenzro-validator -n tenzro-testnet --timeout=600s
kubectl rollout status deployment/tenzro-rpc -n tenzro-testnet --timeout=300s

# Rollback if needed
kubectl rollout undo statefulset/tenzro-validator -n tenzro-testnet
kubectl rollout undo deployment/tenzro-rpc -n tenzro-testnet
```

**Update Manifests:**

```bash
# Edit manifest file
vim deploy/kubernetes/validator-statefulset.yaml

# Apply changes
kubectl apply -f deploy/kubernetes/validator-statefulset.yaml

# Force restart if the manifest didn't change but a config did
kubectl rollout restart statefulset/tenzro-validator -n tenzro-testnet
```

### Backup and Restore

**Backup Validator Data:**

```bash
# Backup validator-0 data directory
kubectl exec -n tenzro-testnet tenzro-validator-0 -- \
  tar czf /tmp/backup.tar.gz /data/tenzro

# Copy to local machine
kubectl cp tenzro-testnet/tenzro-validator-0:/tmp/backup.tar.gz \
  ./validator-0-backup-$(date +%Y%m%d).tar.gz

# Upload to GCS for long-term storage
gsutil cp ./validator-0-backup-*.tar.gz \
  gs://tenzro-infra-backups/validators/
```

**Restore Validator Data:**

```bash
# Download backup from GCS
gsutil cp gs://tenzro-infra-backups/validators/validator-0-backup-20260319.tar.gz \
  ./backup.tar.gz

# Copy to pod
kubectl cp ./backup.tar.gz \
  tenzro-testnet/tenzro-validator-0:/tmp/backup.tar.gz

# Extract (pod must be stopped or data-dir unmounted)
kubectl exec -n tenzro-testnet tenzro-validator-0 -- \
  tar xzf /tmp/backup.tar.gz -C /
```

**Automated Backups with CronJob:**

Create a Kubernetes CronJob to backup validator data daily:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: validator-backup
  namespace: tenzro-testnet
spec:
  schedule: "0 2 * * *"  # 2 AM daily
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: google/cloud-sdk:alpine
            command:
            - /bin/sh
            - -c
            - |
              kubectl exec tenzro-validator-0 -- tar czf - /data/tenzro | \
              gsutil cp - gs://tenzro-infra-backups/validators/backup-$(date +%Y%m%d-%H%M).tar.gz
          restartPolicy: OnFailure
```

### Disaster Recovery

**Total Cluster Loss:**

1. Restore Terraform infrastructure: `terraform apply`
2. Restore genesis config: `kubectl apply -f kubernetes/configmap.yaml`
3. Restore validator data from backups (above)
4. Deploy all manifests: `kubectl apply -f kubernetes/`
5. Verify consensus resumes

**Validator Corruption:**

1. Scale down corrupted validator: `kubectl scale sts/tenzro-validator --replicas=2`
2. Delete corrupted PVC: `kubectl delete pvc data-tenzro-validator-2 -n tenzro-testnet`
3. Scale back up (recreates PVC): `kubectl scale sts/tenzro-validator --replicas=3`
4. Validator will resync from peers

### Cost Optimization

**Reduce Node Sizes:**

Edit `terraform/terraform.tfvars`:

```hcl
validator_machine_type = "e2-small"    # Instead of e2-medium
rpc_machine_type = "e2-micro"          # Instead of e2-small
```

Apply changes:

```bash
terraform apply
```

**Use Preemptible Nodes (RPC only):**

Add to `terraform/gke.tf` RPC node pool:

```hcl
node_config {
  preemptible  = true
  # ... other config
}
```

Note: Never use preemptible nodes for validators (consensus requires stability).

**Reduce Storage:**

Edit `kubernetes/validator-statefulset.yaml`:

```yaml
volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      resources:
        requests:
          storage: 10Gi  # Instead of 20Gi
```

Redeploy StatefulSet (requires recreating pods).

## Security Considerations

1. **Network Isolation:**
   - RPC/API/Metrics ports firewalled at GCP level
   - Only P2P port 9000 accessible from internet
   - All public traffic must go through Caddy LoadBalancer
   - Network policies restrict pod-to-pod communication

2. **RBAC (Role-Based Access Control):**
   ```bash
   # Create read-only user
   kubectl create clusterrolebinding viewer-binding \
     --clusterrole=view \
     --user=readonly@tenzro.network
   ```

3. **Secrets Management:**
   - Use Google Secret Manager for sensitive data
   - Enable Workload Identity for GKE pods
   - Never commit secrets to git

4. **Image Security:**
   - Enable vulnerability scanning in Artifact Registry
   - Use minimal base images (debian:bookworm-slim)
   - Run containers as non-root (user `tenzro`)

5. **TLS/HTTPS:**
   - Caddy automatically provisions Let's Encrypt certificates
   - HTTPS enforced for all public endpoints
   - Internal traffic uses Kubernetes service DNS

6. **Private GKE Cluster (Production):**
   - Enable private nodes (no public IPs)
   - Enable private endpoint (control plane not internet-accessible)
   - Use Cloud NAT for outbound traffic

7. **Audit Logging:**
   ```bash
   # Enable GKE audit logs
   gcloud container clusters update tenzro-testnet \
     --enable-cloud-logging \
     --logging=SYSTEM,WORKLOAD \
     --zone us-central1-a
   ```

## Cost Estimation

Indicative monthly cost drivers (us-central1):

| Resource | Notes |
|----------|-------|
| GKE cluster management fee | Flat per-cluster |
| Validator + RPC nodes | Sized to the workload; 4 pods total (3 StatefulSet + 1 Deployment) |
| Persistent disks | 20GB SSD per StatefulSet validator + 1GB SSD for Caddy |
| LoadBalancer | One regional LB fronting Caddy |
| Egress | Variable; most testnet traffic is small JSON-RPC payloads |

**Cost varies by:**
- Region (us-central1 is mid-priced)
- Node uptime (preemptible nodes 80% cheaper but may be terminated)
- Egress bandwidth (first 1GB/month free)
- Persistent disk type (standard cheaper than SSD)

Use [GCP Pricing Calculator](https://cloud.google.com/products/calculator) for accurate estimates.

**Reduce costs:**
- Use e2-small or e2-micro for validators
- Use standard persistent disks instead of SSD
- Use preemptible nodes for RPC (not validators)
- Delete unused snapshots and logs

## Next Steps

1. **Configure DNS:** Point `*.tenzro.network` domains to LoadBalancer IP (35.224.150.186)
2. **Enable Monitoring:** Set up Prometheus/Grafana dashboards (see `deploy/monitoring/`)
3. **Set up Alerting:** Create PagerDuty/Slack alerts for pod failures, high resource usage
4. **Implement Backups:** Deploy automated backup CronJob for validator data
5. **Multi-Region HA:** Deploy clusters in `us-east1`, `europe-west1` for geographic redundancy
6. **Custom Domains:** Add more subdomains in Caddy config as needed
7. **Rate Limiting:** Add rate limiting in Caddy or via Cloud Armor
8. **WAF:** Enable Cloud Armor for DDoS protection on LoadBalancer
9. **Secrets Management:** Migrate to Google Secret Manager for validator keys
10. **Production Hardening:** Enable private GKE cluster, Binary Authorization, Pod Security Policies

## Cleanup

### Delete Kubernetes Resources

```bash
# Delete all resources in namespace
kubectl delete namespace tenzro-testnet

# Or delete individually
cd deploy/kubernetes
kubectl delete -f .
```

**Warning:** This deletes all validator data. Back up first if needed.

### Destroy GCP Infrastructure

```bash
cd deploy/terraform
terraform destroy
```

**What Gets Deleted:**
- GKE cluster (all nodes, volumes)
- VPC network and firewall rules
- LoadBalancer and external IP
- Note: Artifact Registry and images are retained (manual deletion required)

**Estimated Costs After Deletion:**
- Artifact Registry storage: ~$0.10/GB/month
- Terraform state bucket: ~$0.02/GB/month

**Complete Cleanup:**

```bash
# Delete Artifact Registry
gcloud artifacts repositories delete tenzro \
  --location=us-central1 \
  --project=tenzro-infra

# Delete Terraform state bucket (optional)
gsutil rm -r gs://tenzro-infra-terraform-state
```

## Support and Documentation

- **Main Documentation:** [`README.md`](../README.md), [`GUIDE.md`](../GUIDE.md)
- **Crate Documentation:** `cargo doc --open` (from repo root)
- **GKE Documentation:** https://cloud.google.com/kubernetes-engine/docs
- **Terraform GCP Provider:** https://registry.terraform.io/providers/hashicorp/google/latest/docs
- **Caddy Documentation:** https://caddyserver.com/docs/

## Contributing

When making infrastructure changes:

1. Test in a separate GCP project first
2. Update Terraform variables and documentation
3. Run `terraform plan` and review changes carefully
4. Update this README if adding new components
5. Tag infrastructure changes with version numbers

---

**Last Updated:** 2026-05-04
**Deployment Version:** v0.1.0 (pre-alpha)
**GKE Cluster:** tenzro-testnet (us-central1-a)
**Project:** tenzro-infra
