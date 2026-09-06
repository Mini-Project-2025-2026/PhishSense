#!/usr/bin/env python3
import json
import os
import subprocess

TEST_URLS = [
    # Category 1: Legitimate
    "https://google.com",
    "https://github.com",
    "https://wikipedia.org",

    # Category 2: Typosquatting / Brand Impersonation
    "https://paypa1.com/",
    "https://pinteresl.com/",
    "https://accounts-google-verify.com/login",

    # Category 3: Suspicious Structure & IP Hostnames
    "http://192.168.1.100/paypal/login.html",
    "https://login.verify.account.update.secure.paypal.auth-check.com/signin",
    "https://secure-login-account-verify.xyz/signin",

    # Category 4: Obfuscation & Phishing Indicators
    "https://bit.ly/3xYzP89_paypal_login",
    "https://paypal.com@security-update-checkpoint.net/login"
]

def main():
    print("=== Running PhishSense Integrated Test Suite ===")
    results = []

    for url in TEST_URLS:
        node_cmd = f"const ds = require('./backend/services/detectionService'); ds.performAnalysis('{url}').then(r => console.log(JSON.stringify(r))).catch(e => console.error(e));"
        res = subprocess.run(["node", "-e", node_cmd], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout.strip():
            # Find JSON line
            lines = res.stdout.strip().split('\n')
            json_str = [l for l in lines if l.startswith('{') and l.endswith('}')][-1]
            data = json.loads(json_str)
            ai = data.get('details', {}).get('aiAnalysis', {})
            vt = data.get('details', {}).get('threatIntel', {}).get('virusTotal', {})

            intel_str = vt.get('status', 'NOT CONFIGURED')
            if vt.get('configured'):
                intel_str = f"VT: {vt.get('detections', 0)}/{vt.get('total', 0)}"

            results.append({
                "url": url,
                "ai_pred": ai.get('prediction', 'N/A'),
                "ai_prob": f"{ai.get('confidence', 0)}%",
                "heuristic_pts": f"{data.get('details', {}).get('scoringModel', {}).get('heuristicComponent', 0)}/40",
                "intel_result": intel_str,
                "final_score": f"{data.get('score', 0)}/100 ({data.get('classification', 'N/A')})"
            })
        else:
            print(f"Error testing {url}: {res.stderr}")

    print("\n| URL | AI Prediction | Probability | Heuristic Score | Threat Intel | Final Score |")
    print("| --- | ------------- | ----------: | --------------: | ------------ | ----------: |")
    for r in results:
        print(f"| `{r['url']}` | {r['ai_pred']} | {r['ai_prob']} | {r['heuristic_pts']} | {r['intel_result']} | {r['final_score']} |")

if __name__ == '__main__':
    main()
