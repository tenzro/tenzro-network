output "cluster_name" {
  value = google_container_cluster.tenzro.name
}

output "cluster_endpoint" {
  value     = google_container_cluster.tenzro.endpoint
  sensitive = true
}

output "registry_url" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.tenzro.repository_id}"
}

output "kubeconfig_command" {
  value = "gcloud container clusters get-credentials ${google_container_cluster.tenzro.name} --zone ${var.zone} --project ${var.project_id}"
}
