# Per-validator data disk. Lives in the validator's zone and is independent
# of the boot disk so we can rebuild the VM without losing the chain state.
resource "google_compute_disk" "data" {
  for_each = { for v in var.validators : v.index => v }

  name    = "tenzro-validator-${each.value.index}-data"
  type    = var.disk_type
  zone    = each.value.zone
  size    = var.disk_size_gb
  project = var.project_id

  labels = {
    component = "validator"
    index     = tostring(each.value.index)
  }
}

# Read the genesis file once at plan time and base64-encode it for embedding
# in cloud-init. Plan fails if the file is missing — operator must run
# `tools/genkeys/` first to generate it.
data "local_file" "genesis" {
  filename = var.genesis_toml_path
}

resource "google_compute_instance" "validator" {
  for_each = { for v in var.validators : v.index => v }

  name         = "tenzro-validator-${each.value.index}"
  machine_type = var.machine_type
  zone         = each.value.zone
  project      = var.project_id

  tags = each.value.rpc_public ? ["tenzro-validator", "tenzro-validator-rpc"] : ["tenzro-validator"]

  boot_disk {
    initialize_params {
      image = "projects/cos-cloud/global/images/family/cos-stable"
      size  = 20
      type  = "pd-balanced"
    }
  }

  attached_disk {
    source      = google_compute_disk.data[each.value.index].id
    device_name = "tenzro-data"
    mode        = "READ_WRITE"
  }

  network_interface {
    subnetwork = local.subnet_for_zone[each.value.zone]

    access_config {
      nat_ip = each.value.bootstrap ? google_compute_address.validator_0.address : google_compute_address.validator_other[each.value.index].address
    }
  }

  service_account {
    email = google_service_account.validator[each.value.index].email
    scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]
  }

  metadata = {
    user-data = templatefile("${path.module}/cloud-init.yaml", {
      validator_index       = each.value.index
      bootstrap             = tostring(each.value.bootstrap)
      rpc_public            = tostring(each.value.rpc_public)
      registry_host         = var.registry_host
      image_repo            = var.image_repo
      image_tag             = var.image_tag
      bootstrap_peer_id     = var.bootstrap_peer_id
      bootstrap_external_ip = google_compute_address.validator_0.address
      # The GCE-assigned external IP for THIS validator. Passed to the node
      # binary as `--external-p2p-addr /ip4/<ip>/tcp/9000` so Identify only
      # advertises this routable address (the listen-addr enumeration is
      # hidden in libp2p; see tenzro-network/src/behaviour.rs). Without this,
      # peers see the docker0 bridge / VPC-only addresses and either dial
      # unreachable destinations or hit their own local docker bridge.
      external_p2p_ip       = each.value.bootstrap ? google_compute_address.validator_0.address : google_compute_address.validator_other[each.value.index].address
      genesis_b64           = base64encode(data.local_file.genesis.content)
    })
    # Block project-wide SSH keys so only operator+IAP SSH works.
    block-project-ssh-keys = "TRUE"
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
    preemptible         = false
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  labels = {
    component = "validator"
    index     = tostring(each.value.index)
    role      = each.value.rpc_public ? "validator-rpc" : "validator"
  }

  depends_on = [
    google_secret_manager_secret_iam_member.consensus_accessor,
    google_secret_manager_secret_iam_member.pq_accessor,
    google_secret_manager_secret_iam_member.p2p_accessor,
    google_project_iam_member.artifact_reader,
  ]
}
