# Reuse the existing tenzro-testnet-vpc network created by the GKE module.
# Topology is tri-continental (us-central1 + europe-west1 + asia-southeast1).
# us-central1 already has `tenzro-testnet-subnet` from the GKE module; we look
# it up. EU and APAC get fresh /20 subnetworks here.

data "google_compute_network" "tenzro" {
  name    = "tenzro-testnet-vpc"
  project = var.project_id
}

data "google_compute_subnetwork" "us_central1" {
  name    = "tenzro-testnet-subnet"
  region  = "us-central1"
  project = var.project_id
}

resource "google_compute_subnetwork" "europe_west1" {
  name          = "tenzro-testnet-subnet-europe-west1"
  ip_cidr_range = "10.1.0.0/20"
  region        = "europe-west1"
  network       = data.google_compute_network.tenzro.id
  project       = var.project_id

  private_ip_google_access = true
}

resource "google_compute_subnetwork" "asia_southeast1" {
  name          = "tenzro-testnet-subnet-asia-southeast1"
  ip_cidr_range = "10.2.0.0/20"
  region        = "asia-southeast1"
  network       = data.google_compute_network.tenzro.id
  project       = var.project_id

  private_ip_google_access = true
}

# P2P port 9000 is open to internet for all validators — required for
# external participants to dial in. Tag-scoped so it only applies to the
# 10 GCE instances.
resource "google_compute_firewall" "p2p_external" {
  name    = "tenzro-gce-allow-p2p"
  network = data.google_compute_network.tenzro.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["9000"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["tenzro-validator"]
}

# Validator-0 doubles as the RPC node; opens 8545 (RPC), 8080 (web verify),
# 3001 (MCP), 3002 (A2A), and 3003–3008 (ecosystem MCPs) to internet.
# Other validators only expose 9000 publicly.
resource "google_compute_firewall" "rpc_external" {
  name    = "tenzro-gce-allow-rpc-public"
  network = data.google_compute_network.tenzro.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["8545", "8080", "3001", "3002", "3003", "3004", "3005", "3006", "3007", "3008"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["tenzro-validator-rpc"]
}

# Internal-only traffic between validators on the readiness/health and metrics
# ports. Scoped to the three subnet CIDRs.
resource "google_compute_firewall" "internal" {
  name    = "tenzro-gce-allow-internal"
  network = data.google_compute_network.tenzro.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["8545", "8080", "9090"]
  }

  source_ranges = [
    data.google_compute_subnetwork.us_central1.ip_cidr_range,
    google_compute_subnetwork.europe_west1.ip_cidr_range,
    google_compute_subnetwork.asia_southeast1.ip_cidr_range,
  ]
  target_tags = ["tenzro-validator"]
}

# Allow IAP SSH for operator access without exposing :22 to the internet.
resource "google_compute_firewall" "iap_ssh" {
  name    = "tenzro-gce-allow-iap-ssh"
  network = data.google_compute_network.tenzro.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"] # GCP IAP range
  target_tags   = ["tenzro-validator"]
}

locals {
  subnet_for_zone = {
    "us-central1-a"     = data.google_compute_subnetwork.us_central1.self_link
    "us-central1-b"     = data.google_compute_subnetwork.us_central1.self_link
    "us-central1-c"     = data.google_compute_subnetwork.us_central1.self_link
    "us-central1-f"     = data.google_compute_subnetwork.us_central1.self_link
    "europe-west1-b"    = google_compute_subnetwork.europe_west1.self_link
    "europe-west1-c"    = google_compute_subnetwork.europe_west1.self_link
    "europe-west1-d"    = google_compute_subnetwork.europe_west1.self_link
    "asia-southeast1-a" = google_compute_subnetwork.asia_southeast1.self_link
    "asia-southeast1-b" = google_compute_subnetwork.asia_southeast1.self_link
    "asia-southeast1-c" = google_compute_subnetwork.asia_southeast1.self_link
  }
}

# Static external IP for validator-0 (other validators must dial a stable
# address). Lives in the same region as validator-0.
resource "google_compute_address" "validator_0" {
  name    = "tenzro-validator-0-ip"
  region  = "us-central1"
  project = var.project_id
}

# Per-validator ephemeral external IPs for validators 1–9. They only need
# outbound NAT + inbound 9000 from peers — operator can rebuild without
# worrying about IP stability.
resource "google_compute_address" "validator_other" {
  for_each = { for v in var.validators : v.index => v if !v.bootstrap }

  name    = "tenzro-validator-${each.value.index}-ip"
  region  = regex("^([a-z0-9-]+)-[a-z]$", each.value.zone)[0]
  project = var.project_id
}
