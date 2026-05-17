# Secret Manager: 3 secrets per validator (consensus / pq / p2p).
#
# Terraform manages the *secret container resources only* — never the secret
# payloads. Operators must populate the payloads out-of-band before any VM
# boots, via:
#
#   gcloud secrets versions add tenzro-validator-${i}-consensus \
#       --data-file=keys/validator-${i}/consensus.seed \
#       --project=tenzro-infra
#
#   gcloud secrets versions add tenzro-validator-${i}-pq \
#       --data-file=keys/validator-${i}/pq.seed \
#       --project=tenzro-infra
#
#   gcloud secrets versions add tenzro-validator-${i}-p2p \
#       --data-file=keys/validator-${i}/p2p.seed \
#       --project=tenzro-infra
#
# Putting key bytes in Terraform state would leak them into the GCS state
# bucket (and any operator with state-read access). The offline key generator
# at tools/genkeys/ writes the seeds to a local directory; the operator
# uploads them with the commands above before running `terraform apply`.

resource "google_secret_manager_secret" "consensus" {
  for_each = { for v in var.validators : v.index => v }

  secret_id = "tenzro-validator-${each.value.index}-consensus"
  project   = var.project_id

  replication {
    auto {}
  }

  labels = {
    component = "validator"
    key_kind  = "ed25519-consensus"
    index     = tostring(each.value.index)
  }
}

resource "google_secret_manager_secret" "pq" {
  for_each = { for v in var.validators : v.index => v }

  secret_id = "tenzro-validator-${each.value.index}-pq"
  project   = var.project_id

  replication {
    auto {}
  }

  labels = {
    component = "validator"
    key_kind  = "ml-dsa-65"
    index     = tostring(each.value.index)
  }
}

resource "google_secret_manager_secret" "p2p" {
  for_each = { for v in var.validators : v.index => v }

  secret_id = "tenzro-validator-${each.value.index}-p2p"
  project   = var.project_id

  replication {
    auto {}
  }

  labels = {
    component = "validator"
    key_kind  = "libp2p-ed25519"
    index     = tostring(each.value.index)
  }
}

# Per-validator service account. cloud-init runs as this identity and pulls
# only its own three secrets via IAM bindings below.
resource "google_service_account" "validator" {
  for_each = { for v in var.validators : v.index => v }

  account_id   = "tenzro-validator-${each.value.index}"
  display_name = "Tenzro validator ${each.value.index}"
  project      = var.project_id
}

resource "google_secret_manager_secret_iam_member" "consensus_accessor" {
  for_each = { for v in var.validators : v.index => v }

  project   = var.project_id
  secret_id = google_secret_manager_secret.consensus[each.value.index].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.validator[each.value.index].email}"
}

resource "google_secret_manager_secret_iam_member" "pq_accessor" {
  for_each = { for v in var.validators : v.index => v }

  project   = var.project_id
  secret_id = google_secret_manager_secret.pq[each.value.index].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.validator[each.value.index].email}"
}

resource "google_secret_manager_secret_iam_member" "p2p_accessor" {
  for_each = { for v in var.validators : v.index => v }

  project   = var.project_id
  secret_id = google_secret_manager_secret.p2p[each.value.index].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.validator[each.value.index].email}"
}

# Artifact Registry read access — every validator pulls the tenzro-node image.
resource "google_project_iam_member" "artifact_reader" {
  for_each = { for v in var.validators : v.index => v }

  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.validator[each.value.index].email}"
}

# Logging + Monitoring writes for operator observability.
resource "google_project_iam_member" "log_writer" {
  for_each = { for v in var.validators : v.index => v }

  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.validator[each.value.index].email}"
}

resource "google_project_iam_member" "metric_writer" {
  for_each = { for v in var.validators : v.index => v }

  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.validator[each.value.index].email}"
}
