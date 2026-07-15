resource "google_container_cluster" "tenzro" {
  name     = var.cluster_name
  location = var.zone
  project  = var.project_id

  # Use separately managed node pools
  remove_default_node_pool = true
  initial_node_count       = 1

  networking_mode = "VPC_NATIVE"
  network         = google_compute_network.tenzro.name
  subnetwork      = google_compute_subnetwork.tenzro.name

  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }

  release_channel {
    channel = "REGULAR"
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  addons_config {
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = false
    }
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
  }

  logging_config {
    enable_components = ["SYSTEM_COMPONENTS"]
  }

  # Allow Terraform to destroy the cluster (testnet only)
  deletion_protection = false
}

# Validator node pool
resource "google_container_node_pool" "validators" {
  name       = "validator-pool"
  location   = var.zone
  cluster    = google_container_cluster.tenzro.name
  node_count = var.validator_count

  node_config {
    machine_type = var.validator_machine_type
    disk_size_gb = 20
    disk_type    = "pd-standard"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = {
      role = "validator"
    }

    taint {
      key    = "role"
      value  = "validator"
      effect = "PREFER_NO_SCHEDULE"
    }

    confidential_nodes {
      enabled = var.enable_confidential_nodes
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}

# RPC node pool
resource "google_container_node_pool" "rpc" {
  name       = "rpc-pool"
  location   = var.zone
  cluster    = google_container_cluster.tenzro.name
  node_count = 1

  node_config {
    machine_type = var.rpc_machine_type
    disk_size_gb = 20
    disk_type    = "pd-ssd"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = {
      role = "rpc"
    }

    confidential_nodes {
      enabled = var.enable_confidential_nodes
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}

# Optional: Confidential VM node pool for TEE
resource "google_container_node_pool" "tee" {
  count      = var.enable_confidential_nodes ? 1 : 0
  name       = "tee-pool"
  location   = var.zone
  cluster    = google_container_cluster.tenzro.name
  node_count = 1

  node_config {
    machine_type = "n2d-standard-4"
    disk_size_gb = 100
    disk_type    = "pd-ssd"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = {
      role = "tee-provider"
    }

    confidential_nodes {
      enabled = true
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}
