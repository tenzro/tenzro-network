variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone"
  type        = string
  default     = "us-central1-a"
}

variable "cluster_name" {
  description = "GKE cluster name"
  type        = string
  default     = "tenzro-testnet"
}

variable "validator_count" {
  description = "Number of validator nodes"
  type        = number
  default     = 5
}

variable "validator_machine_type" {
  description = "Machine type for validator nodes"
  type        = string
  default     = "e2-medium"
}

variable "rpc_machine_type" {
  description = "Machine type for RPC nodes"
  type        = string
  default     = "e2-small"
}

variable "enable_confidential_nodes" {
  description = "Enable AMD SEV confidential computing for TEE nodes"
  type        = bool
  default     = false
}
