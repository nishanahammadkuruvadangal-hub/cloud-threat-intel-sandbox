output "ingest_bucket_name" {
  value       = google_storage_bucket.threat_ingest_bucket.name
  description = "Upload suspicious files here to trigger analysis"
}

output "quarantine_bucket_name" {
  value       = google_storage_bucket.quarantine_bucket.name
  description = "Malicious files automatically isolated here"
}
