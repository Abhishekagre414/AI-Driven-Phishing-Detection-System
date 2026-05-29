import urllib.request
import urllib.parse
import json
import sys
import time

API_URL = "http://localhost:8000"

# Mock raw email representing a credential harvesting attack
MOCK_EMAIL = (
    "Authentication-Results: mx.google.com; spf=softfail dkim=none dmarc=none\n"
    "From: \"Microsoft Office 365 Support\" <no-reply@security-office365-updates.com>\n"
    "To: <cfo@enterprise.com>\n"
    "Subject: ACTION REQUIRED: Unusual Sign-in Detected for Security Alert\n"
    "Date: Sat, 23 May 2026 15:20:00 +0000\n"
    "\n"
    "Your Microsoft Office 365 account has experienced an unusual sign-in attempt from Russia.\n"
    "To prevent lockout and permanent deletion of your account, you must verify your identity immediately.\n"
    "Please update your password here: http://microsoft.com-update.security-checkpoint.xyz/login.php\n"
    "\n"
    "Microsoft Security Team"
)

def make_request(path: str, data: dict = None, method: str = "GET"):
    url = f"{API_URL}{path}"
    headers = {"Content-Type": "application/json"}
    
    req_data = None
    if data is not None:
        req_data = json.dumps(data).encode("utf-8")
        
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    
    try:
        with urllib.request.urlopen(req) as response:
            res_data = response.read().decode("utf-8")
            return json.loads(res_data)
    except Exception as e:
        print(f"Request failed: {url} - {e}")
        return None

def run_tests():
    print("Starting APDS API Verification Tests...")
    
    # 1. Test Root Endpoint
    root = make_request("/")
    if root and root.get("status") == "online":
        print("[PASS] Root endpoint is online.")
    else:
        print("[FAIL] Root endpoint is offline. Ensure FastAPI server is running on port 8000.")
        sys.exit(1)
        
    # 2. Test Get Thresholds
    thresholds = make_request("/api/v1/settings/thresholds")
    if thresholds and "thresholds" in thresholds:
        print(f"[PASS] Successfully fetched policy thresholds: {thresholds['thresholds']}")
    else:
        print("[FAIL] Failed to fetch policy thresholds.")
        sys.exit(1)

    # 3. Test Scoring Endpoint
    print("Testing live email scoring endpoint...")
    payload = {
        "raw_email": MOCK_EMAIL,
        "recipient_group": "Executive",
        "recipient": "cfo@enterprise.com"
    }
    
    score_res = make_request("/api/v1/score", data=payload, method="POST")
    if score_res and "fusion_result" in score_res:
        fusion = score_res["fusion_result"]
        verdict = fusion["verdict"]
        confidence = fusion["confidence_score"]
        explanations = fusion["explanations"]
        
        print(f"[PASS] Scoring API returned successfully.")
        print(f"       Verdict: {verdict.upper()} (Confidence: {confidence})")
        print(f"       Category: {score_res['threat_category']}")
        print(f"       Explanations count: {len(explanations)}")
        for exp in explanations:
            print(f"         - {exp}")
            
        assert verdict == "phishing", f"Expected phishing verdict, got {verdict}"
        assert confidence > 0.70, f"Expected high confidence, got {confidence}"
        print("[PASS] Scoring engine correctly classified the threat.")
    else:
        print("[FAIL] Scoring API did not return expected response structure.")
        sys.exit(1)
        
    # 4. Test Fetch Alerts
    alerts = make_request("/api/v1/alerts")
    if alerts and len(alerts) > 0:
        print(f"[PASS] Fetched alert queue successfully. Count: {len(alerts)}")
        
        # Verify our newly scored alert is at the top
        newest = alerts[0]
        if newest["subject"] == "ACTION REQUIRED: Unusual Sign-in Detected for Security Alert":
            print("[PASS] Newest alert correctly pushed to the log queue.")
        else:
            print(f"[FAIL] Unexpected alert at the top of the queue: {newest['subject']}")
    else:
        print("[FAIL] Failed to fetch alert queue.")
        sys.exit(1)

    # 5. Test Campaign Clustering
    campaigns = make_request("/api/v1/campaigns")
    if campaigns and len(campaigns) > 0:
        print(f"[PASS] Fetched campaign clusters. Found {len(campaigns)} active campaigns.")
        for c in campaigns:
            print(f"       - Cluster '{c['name']}': {c['count']} occurrences (Max Score: {c['max_score']})")
    else:
        print("[FAIL] Failed to fetch campaign clusters.")
        sys.exit(1)

    print("\nAll APDS API Verification Tests Completed Successfully!")

if __name__ == "__main__":
    run_tests()
