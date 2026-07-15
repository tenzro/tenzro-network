output "bootstrap_external_ip" {
  description = "Public IP of validator-0 (other validators dial this)"
  value       = google_compute_address.validator_0.address
}

output "bootstrap_multiaddr" {
  description = "Libp2p multiaddr for validator-0; used as --boot-nodes by external participants"
  value       = "/ip4/${google_compute_address.validator_0.address}/tcp/9000/p2p/${var.bootstrap_peer_id}"
}

output "rpc_endpoint" {
  description = "Public JSON-RPC endpoint (validator-0)"
  value       = "http://${google_compute_address.validator_0.address}:8545"
}

output "validator_ips" {
  description = "Per-validator external IPs"
  value = {
    for v in var.validators : v.index =>
      v.bootstrap ? google_compute_address.validator_0.address : google_compute_address.validator_other[v.index].address
  }
}

output "validator_service_accounts" {
  description = "Per-validator service account emails (for ad-hoc IAM grants)"
  value = {
    for v in var.validators : v.index => google_service_account.validator[v.index].email
  }
}

output "consensus_secret_ids" {
  description = "Secret Manager secret IDs for consensus (Ed25519) keys"
  value = [
    for v in var.validators : google_secret_manager_secret.consensus[v.index].secret_id
  ]
}

output "dns_repoint_targets" {
  description = "Reminder: after apply, repoint these DNS records to bootstrap_external_ip"
  value = [
    "rpc.tenzro.xyz",
    "api.tenzro.xyz",
    "mcp.tenzro.xyz",
    "a2a.tenzro.xyz",
    "solana-mcp.tenzro.xyz",
    "ethereum-mcp.tenzro.xyz",
    "canton-mcp.tenzro.xyz",
    "layerzero-mcp.tenzro.xyz",
    "chainlink-mcp.tenzro.xyz",
    "lifi-mcp.tenzro.xyz",
  ]
}
