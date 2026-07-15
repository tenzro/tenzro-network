resource "google_artifact_registry_repository" "tenzro" {
  location      = var.region
  repository_id = "tenzro"
  format        = "DOCKER"
  project       = var.project_id

  description = "Tenzro Network Docker images"
}
