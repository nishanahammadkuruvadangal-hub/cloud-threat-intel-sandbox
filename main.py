import os
import io
import json
import logging
import hashlib
import urllib.request
import urllib.parse
from google.cloud import storage
import yara

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cloud-threat-sandbox")

# Environment Variables
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
QUARANTINE_BUCKET_NAME = os.environ.get("QUARANTINE_BUCKET", "")

def calculate_hashes(file_bytes: bytes) -> dict:
    """Computes MD5, SHA1, and SHA256 hashes of input bytes."""
    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest()
    }

def scan_yara(file_bytes: bytes) -> list:
    """Scans file bytes against compiled YARA rules."""
    rule_path = os.path.join(os.path.dirname(__file__), "rules", "malware_rules.yar")
    if not os.path.exists(rule_path):
        logger.warning(f"YARA rules file not found at {rule_path}")
        return []
    
    try:
        rules = yara.compile(filepath=rule_path)
        matches = rules.match(data=file_bytes)
        return [match.rule for match in matches]
    except Exception as e:
        logger.error(f"YARA scanning failed: {e}")
        return []

def query_virustotal(sha256: str) -> dict:
    """Queries VirusTotal v3 API for hash analysis summary."""
    if not VIRUSTOTAL_API_KEY:
        return {"status": "skipped", "reason": "No API Key configured"}

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "status": "success",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "not_found", "reason": "Hash not seen by VirusTotal"}
        logger.error(f"VirusTotal API HTTP Error: {e.code}")
    except Exception as e:
        logger.error(f"VirusTotal query failed: {e}")

    return {"status": "error", "reason": "API request failed"}

def quarantine_file(storage_client, source_bucket_name, file_name):
    """Moves malicious file to isolated quarantine bucket."""
    if not QUARANTINE_BUCKET_NAME:
        logger.warning("Quarantine bucket not specified. File left in source bucket.")
        return
    
    source_bucket = storage_client.bucket(source_bucket_name)
    source_blob = source_bucket.blob(file_name)
    destination_bucket = storage_client.bucket(QUARANTINE_BUCKET_NAME)

    # Copy to quarantine & delete original
    source_bucket.copy_blob(source_blob, destination_bucket, file_name)
    source_blob.delete()
    logger.info(f"File {file_name} moved to quarantine bucket: {QUARANTINE_BUCKET_NAME}")

def process_file(event, context):
    """GCP Cloud Function entry point triggered by GCS object creation."""
    bucket_name = event['bucket']
    file_name = event['name']

    logger.info(f"Triggered analysis for gs://{bucket_name}/{file_name}")

    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(file_name)

    # Download file into memory
    file_bytes = blob.download_as_bytes()

    # 1. Static Analysis & Hashing
    hashes = calculate_hashes(file_bytes)
    
    # 2. YARA Rule Match
    yara_matches = scan_yara(file_bytes)

    # 3. Threat Intel Query
    vt_result = query_virustotal(hashes["sha256"])

    # 4. Determine Verdict
    is_malicious = (
        len(yara_matches) > 0 or 
        (vt_result.get("status") == "success" and vt_result.get("malicious", 0) > 2)
    )

    verdict = "MALICIOUS" if is_malicious else "CLEAN"

    # 5. Build Telemetry Payload
    telemetry = {
        "event_type": "THREAT_ANALYSIS_COMPLETED",
        "file_info": {
            "name": file_name,
            "size_bytes": len(file_bytes),
            "source_bucket": bucket_name
        },
        "hashes": hashes,
        "yara_detections": yara_matches,
        "virustotal": vt_result,
        "verdict": verdict
    }

    # Output structured JSON log for SIEM (Elastic / Splunk / Cloud Logging)
    print(json.dumps(telemetry))

    # 6. Automatic Isolation
    if is_malicious:
        quarantine_file(storage_client, bucket_name, file_name)

    return ("Analysis complete", 200)