# ⚡ How It Works & Practical Applications

The **Cloud Threat Intel Sandbox** is an event-driven, cloud-native security automation system built on Google Cloud Platform (GCP). It acts as a **first line of defense** against malicious file uploads by performing instant static analysis, threat intelligence enrichment, and automated quarantine—all within seconds of a file arriving.

---

## ⚙️ How It Works (Step-by-Step Architecture)
### 1. Ingestion & Event Trigger
* A user, system, or application uploads an untrusted file to the designated **Cloud Storage Ingestion Bucket**.
* Google Cloud Storage immediately triggers a serverless **GCP Cloud Function** via an event payload (`google.storage.object.finalize`).

### 2. In-Memory Static Analysis
* The Cloud Function downloads the file bytes directly into memory (preventing disk execution).
* It computes **MD5, SHA-1, and SHA-256** cryptographic hashes.
* It passes the raw file bytes through compiled **YARA Rules** to scan for malicious strings, obfuscated commands, webshells, or PE header anomalies.

### 3. API Threat Intelligence Lookup
* The SHA-256 hash is queried against the **VirusTotal v3 API** to check global antivirus engine vendor verdicts without uploading sensitive file contents.

### 4. Automated SOAR Response & Telemetry
* **If Malicious:** The function automatically revokes access, moves the file to an isolated **Quarantine Bucket**, and deletes the original file from the ingestion bucket.
* **Telemetry Output:** Generates a structured JSON log containing all IoCs (Indicators of Compromise) and sends it to **GCP Cloud Logging / Elastic SIEM** for immediate analyst triage.

---

## 🎯 Practical Use Cases & Real-World Value

### 🛡️ 1. Securing Web Applications & Enterprise Uploads
* **Problem:** Web portals (e.g., job application forms, customer support desks) allow users to upload files, risking malware drops or webshell uploads.
* **Solution:** Route all incoming uploads through this pipeline to automatically scan and isolate threats before files hit core databases or internal servers.

### 🤖 2. Automated SOC Triage (SOAR Pipeline)
* **Problem:** Security Analysts spend hours manually downloading suspicious email attachments and checking hashes on VirusTotal.
* **Solution:** Automates 90% of initial file triage, reducing response times from **minutes to under 5 seconds**.

### ☁️ 3. Infrastructure-as-Code (IaC) Demonstration
* **Problem:** Manual security setups are hard to replicate and error-prone.
* **Solution:** The entire architecture (Buckets, IAM permissions, Cloud Functions) is codified using **Terraform** (`terraform apply`), allowing security teams to spin up an identical sandbox in minutes.

---

## 📊 Sample SIEM Log Output

When a malicious file is processed, the system outputs the following standardized telemetry for SOC Analysts:

```json
{
  "event_type": "THREAT_ANALYSIS_COMPLETED",
  "file_info": {
    "name": "invoice_pdf_exec.cmd",
    "size_bytes": 1024,
    "source_bucket": "threat-ingest-bucket"
  },
  "hashes": {
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "yara_detections": ["Suspicious_PowerShell_EncodedCommand"],
  "virustotal": {
    "status": "success",
    "malicious_score": 48
  },
  "verdict": "MALICIOUS",
  "action_taken": "QUARANTINED"
}