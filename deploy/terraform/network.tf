resource "google_compute_network" "tenzro" {
  name                    = "tenzro-testnet-vpc"
  auto_create_subnetworks = false
  project                 = var.project_id
}

resource "google_compute_subnetwork" "tenzro" {
  name          = "tenzro-testnet-subnet"
  ip_cidr_range = "10.0.0.0/20"
  region        = var.region
  network       = google_compute_network.tenzro.id
  project       = var.project_id

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = "10.4.0.0/14"
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = "10.8.0.0/20"
  }
}

# P2P port open to internet — required for external validators/participants
resource "google_compute_firewall" "allow_p2p" {
  name    = "tenzro-allow-p2p"
  network = google_compute_network.tenzro.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["9000"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["tenzro-node"]
}

# RPC/Web API only accessible within the VPC (Caddy proxies public traffic)
resource "google_compute_firewall" "allow_rpc_internal" {
  name     = "tenzro-allow-rpc-internal"
  network  = google_compute_network.tenzro.name
  project  = var.project_id
  priority = 900

  allow {
    protocol = "tcp"
    ports    = ["8545", "8080", "9090"]
  }

  # Only from within the VPC subnet and pod/service ranges
  source_ranges = ["10.0.0.0/20", "10.4.0.0/14", "10.8.0.0/20"]
}

# Default-deny RPC/API/metrics access from internet. Priority 2000 (lower
# than the per-tag allow rules at priority 1000) so tagged VMs that
# explicitly need public RPC exposure — e.g. `tenzro-validator-rpc` on the
# Phase A GCE bootstrap — bypass this rule via the higher-priority allow.
# Anything not tagged gets denied.
resource "google_compute_firewall" "deny_rpc_external" {
  name     = "tenzro-deny-rpc-external"
  network  = google_compute_network.tenzro.name
  project  = var.project_id
  priority = 2000

  deny {
    protocol = "tcp"
    ports    = ["8545", "8080", "9090"]
  }

  source_ranges = ["0.0.0.0/0"]
}
