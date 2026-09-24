terraform {
  required_version = ">= 1.0.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# 1. Ingestion Bucket (Drop zone for suspicious files)
resource "google_storage_bucket" "threat_ingest_bucket" {
  name                     = "${var.project_id}-threat-ingest"
  location                 = var.region
  force_destroy            = true
  public_access_prevention = "enforced"
}

# 2. Quarantine Bucket (Isolated storage for detected malware)
resource "google_storage_bucket" "quarantine_bucket" {
  name                     = "${var.project_id}-malware-quarantine"
  location                 = var.region
  force_destroy            = true
  public_access_prevention = "enforced"
}

# 3. Zip Cloud Function Source Code
data "archive_file" "function_source" {
  type        = "zip"
  source_dir  = "${path.module}/.."
  output_path = "${path.module}/source.zip"
  excludes    = ["terraform", "docs", ".git"]
}

# 4. Storage Bucket for Function Deployment Code
resource "google_storage_bucket" "function_bucket" {
  name     = "${var.project_id}-function-source"
  location = var.region
}

resource "google_storage_bucket_object" "zip_object" {
  name   = "source-${data.archive_file.function_source.output_md5}.zip"
  bucket = google_storage_bucket.function_bucket.name
  source = data.archive_file.function_source.output_path
}

# 5. Cloud Function Trigger
resource "google_cloudfunctions_function" "threat_sandbox_fn" {
  name                  = "threat-intel-sandbox"
  description           = "Automated Static Analysis & Threat Intel Pipeline"
  runtime               = "python310"
  available_memory_mb   = 256
  source_archive_bucket = google_storage_bucket.function_bucket.name
  source_archive_object = google_storage_bucket_object.zip_object.name
  entry_point           = "process_file"

  event_trigger {
    event_type = "google.storage.object.finalize"
    resource   = google_storage_bucket.threat_ingest_bucket.name
  }

  environment_variables = {
    VIRUSTOTAL_API_KEY = var.virustotal_api_key
    QUARANTINE_BUCKET  = google_storage_bucket.quarantine_bucket.name
  }
}
