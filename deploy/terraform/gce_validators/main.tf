terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  backend "gcs" {
    bucket = "tenzro-infra-terraform-state"
    prefix = "gce-validators"
  }
}

provider "google" {
  project = var.project_id
  region  = var.primary_region
}
