import base64, datetime, hashlib, hmac, json, os, sys, time
import requests

WORKSPACE_ID = os.environ.get("SENTINEL_WORKSPACE_ID", "")
SHARED_KEY   = os.environ.get("SENTINEL_SHARED_KEY", "")
LOG_TYPE     = os.environ.get("SENTINEL_LOG_TYPE", "OpenShieldFindings")

def build_signature(date, content_length):
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"POST\n{content_length}\napplication/json\n{x_headers}\n/api/logs"
    decoded_key  = base64.b64decode(SHARED_KEY)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, string_to_hash.encode("utf-8"), digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {WORKSPACE_ID}:{encoded_hash}"

def normalise(raw, scan_id):
    sev_map = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0}
    sev = str(raw.get("severity","MEDIUM")).upper()
    return {
        "ScanId": scan_id,
        "FindingId": raw.get("id",""),
        "TimeGenerated": raw.get("detected_at", datetime.datetime.utcnow().isoformat()+"Z"),
        "ResourceId": raw.get("resource_id",""),
        "ResourceType": raw.get("resource_type",""),
        "ResourceName": raw.get("resource_name",""),
        "SubscriptionId": raw.get("subscription_id",""),
        "ResourceGroup": raw.get("resource_group",""),
        "Region": raw.get("region",""),
        "RuleId": raw.get("rule_id",""),
        "RuleName": raw.get("rule_name",""),
        "Severity": sev.capitalize(),
        "SeverityScore": sev_map.get(sev,0),
        "Description": raw.get("description",""),
        "Remediation": raw.get("remediation",""),
        "CisControl": raw.get("compliance",{}).get("cis",""),
        "NistControl": raw.get("compliance",{}).get("nist",""),
        "Source": "OpenShield",
        "ToolVersion": raw.get("tool_version","0.1.0"),
    }

def send(records):
    body     = json.dumps(records).encode("utf-8")
    rfc_date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    sig      = build_signature(rfc_date, len(body))
    url      = f"https://{WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    headers  = {
        "Content-Type": "application/json",
        "Authorization": sig,
        "Log-Type": LOG_TYPE,
        "x-ms-date": rfc_date,
        "time-generated-field": "TimeGenerated",
    }
    for attempt in range(1, 4):
        try:
            r = requests.post(url, data=body, headers=headers, timeout=30)
            if r.status_code == 200:
                print(f"[OK] Ingested {len(records)} findings → {LOG_TYPE}_CL")
                return True
            print(f"[WARN] Attempt {attempt} — HTTP {r.status_code}: {r.text}")
        except Exception as e:
            print(f"[WARN] Attempt {attempt} — {e}")
        time.sleep(2 ** attempt)
    print("[ERROR] Failed after 3 attempts")
    return False

def main():
    path    = sys.argv[1] if len(sys.argv) > 1 else "scanner/output/test_findings.json"
    scan_id = sys.argv[2] if len(sys.argv) > 2 else datetime.datetime.utcnow().strftime("scan-%Y%m%d-%H%M")
    print(f"[INFO] Scan ID: {scan_id}")
    with open(path) as f:
        data = json.load(f)
    findings = data if isinstance(data, list) else data.get("findings", [])
    print(f"[INFO] Loaded {len(findings)} findings")
    records = [normalise(f, scan_id) for f in findings]
    send(records)

if __name__ == "__main__":
    main()
