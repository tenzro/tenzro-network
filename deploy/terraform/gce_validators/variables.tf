variable "project_id" {
  description = "GCP project ID (must be tenzro-operator-project)"
  type        = string
  default     = "tenzro-operator-project"
}

variable "primary_region" {
  description = "Primary region for provider/state"
  type        = string
  default     = "us-central1"
}

variable "image_tag" {
  description = "tenzro-node container image tag (must include #129 snapshot/state-sync code)"
  type        = string
  # Bumped by operator each rollout — no default beyond the most recent good tag.
  default     = "20260513-192247"
}

variable "registry_host" {
  description = "Artifact Registry host"
  type        = string
  default     = "us-central1-docker.pkg.dev"
}

variable "image_repo" {
  description = "Artifact Registry repo path"
  type        = string
  default     = "tenzro-operator-project/tenzro"
}

variable "machine_type" {
  description = "GCE machine type for validators"
  type        = string
  default     = "n2-standard-4"
}

variable "disk_size_gb" {
  description = "Persistent disk size for /var/lib/tenzro"
  type        = number
  default     = 100
}

variable "disk_type" {
  description = "Persistent disk type"
  type        = string
  default     = "pd-balanced"
}

# Validator topology — 10 VMs across three continents for geographic diversity.
# Indices match genesis ordering. The bootstrap flag picks the node that other
# validators dial on cold start. Setting `rpc_public = true` also opens the
# RPC + MCP + A2A ports to the internet (only validator-0 should have this).
variable "validators" {
  description = "Per-validator placement and role flags"
  type = list(object({
    index      = number
    zone       = string
    bootstrap  = bool
    rpc_public = bool
  }))
  # Tri-continental: 4 NA (us-central1) + 3 EU (europe-west1) + 3 APAC
  # (asia-southeast1). Provides real geographic diversity for a public testnet
  # while keeping the 7-of-10 quorum reachable from any continent.
  #
  # The libp2p connection_idle_timeout=600s + GCE host sysctl TCP keepalives
  # (deploy/terraform/gce_validators/cloud-init.yaml) make inter-region links
  # stable against the 10-min VPC conntrack eviction that broke the mesh on
  # 2026-05-14.
  #
  # Cost note: cross-region GCP egress runs $0.05-0.12/GB. Gossipsub +
  # HotStuff-2 traffic at testnet load is a few GB/day; budget ~$100/mo extra
  # vs single-region for the diversity.
  default = [
    { index = 0, zone = "us-central1-a", bootstrap = true, rpc_public = true },
    { index = 1, zone = "us-central1-b", bootstrap = false, rpc_public = false },
    { index = 2, zone = "us-central1-c", bootstrap = false, rpc_public = false },
    { index = 3, zone = "us-central1-f", bootstrap = false, rpc_public = false },
    { index = 4, zone = "europe-west1-b", bootstrap = false, rpc_public = false },
    { index = 5, zone = "europe-west1-c", bootstrap = false, rpc_public = false },
    { index = 6, zone = "europe-west1-d", bootstrap = false, rpc_public = false },
    { index = 7, zone = "asia-southeast1-a", bootstrap = false, rpc_public = false },
    { index = 8, zone = "asia-southeast1-b", bootstrap = false, rpc_public = false },
    { index = 9, zone = "asia-southeast1-c", bootstrap = false, rpc_public = false },
  ]
}

variable "bootstrap_peer_id" {
  description = "Libp2p peer ID for validator-0, derived from the offline-generated p2p key. Must be set before apply; empty string is rejected."
  type        = string
  default     = ""

  validation {
    condition     = length(var.bootstrap_peer_id) > 0
    error_message = "bootstrap_peer_id must be set — run tools/genkeys/ first and copy the validator-0 peer ID."
  }
}

variable "genesis_toml_path" {
  description = "Path to the production genesis file (read on plan, embedded into instance metadata)"
  type        = string
  default     = "../../../config/genesis-prod.toml"
}
