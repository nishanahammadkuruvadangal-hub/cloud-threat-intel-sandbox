variable "project_id" {
  description = "Google Cloud Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "virustotal_api_key" {
  description = "VirusTotal API Key"
  type        = string
  sensitive   = true
}
