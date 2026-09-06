#!/usr/bin/env python3
import csv
import os

def generate_dataset():
    dataset_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(dataset_dir, 'phishing_urls.csv')

    legitimate_urls = [
        # Major search & portals
        "https://www.google.com",
        "https://www.google.com/search?q=cybersecurity+best+practices",
        "https://www.google.com/maps",
        "https://www.google.com/drive",
        "https://www.bing.com",
        "https://www.bing.com/search?q=machine+learning+models",
        "https://duckduckgo.com",
        "https://duckduckgo.com/?q=python+programming",
        "https://www.yahoo.com",
        "https://news.yahoo.com/tech",

        # Development & Technology
        "https://github.com",
        "https://github.com/torvalds/linux",
        "https://github.com/facebook/react",
        "https://github.com/golang/go/issues/102",
        "https://stackoverflow.com",
        "https://stackoverflow.com/questions/123456/how-to-fix-python-import-error",
        "https://stackexchange.com",
        "https://pypi.org/project/requests/",
        "https://npm.js.org/package/express",
        "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
        "https://docs.python.org/3/library/stdtypes.html",
        "https://react.dev/learn",
        "https://nodejs.org/en/docs/",
        "https://kubernetes.io/docs/concepts/",
        "https://docker.com/products/docker-desktop",

        # E-commerce & Retail
        "https://www.amazon.com",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://www.amazon.com/gp/bestsellers",
        "https://www.ebay.com",
        "https://www.ebay.com/itm/1234567890",
        "https://www.walmart.com",
        "https://www.target.com",
        "https://www.bestbuy.com",
        "https://www.shopify.com",

        # Social & Entertainment
        "https://www.facebook.com",
        "https://www.facebook.com/help",
        "https://www.instagram.com",
        "https://www.twitter.com",
        "https://x.com/explore",
        "https://www.linkedin.com",
        "https://www.linkedin.com/jobs",
        "https://www.reddit.com/r/cybersecurity",
        "https://www.reddit.com/r/programming",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.netflix.com/browse",
        "https://www.spotify.com/us/premium/",

        # News & Media
        "https://www.wikipedia.org",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://en.wikipedia.org/wiki/Machine_learning",
        "https://www.bbc.com/news",
        "https://www.cnn.com/world",
        "https://www.nytimes.com",
        "https://www.reuters.com/technology",
        "https://www.theguardian.com/international",
        "https://techcrunch.com",
        "https://arstechnica.com",

        # Cloud & Corporate
        "https://www.microsoft.com/en-us/",
        "https://azure.microsoft.com/en-us/products/",
        "https://aws.amazon.com/console/",
        "https://cloud.google.com/docs",
        "https://www.apple.com/iphone/",
        "https://support.apple.com/kb/HT201222",
        "https://www.cloudflare.com/learning/access-management/what-is-zero-trust/",
        "https://www.salesforce.com",
        "https://www.zoom.us",
        "https://www.cisco.com",

        # Finance & Banking (Official)
        "https://www.paypal.com/us/home",
        "https://www.chase.com",
        "https://www.wellsfargo.com",
        "https://www.bankofamerica.com",
        "https://www.citigroup.com",
        "https://www.stripe.com",
        "https://www.coinbase.com",
        "https://www.binance.com"
    ]

    phishing_urls = [
        # Typosquatting & Brand Impersonation
        "https://paypa1.com/cgi-bin/webscr-login",
        "https://pinteresl.com/auth/login",
        "https://paypal-security-update.com/signin/account-verify",
        "https://paypal-account-verification-service.com/login.php",
        "https://accounts-google-verify.com/login",
        "https://google-drive-security-check.xyz/login.html",
        "https://microsoft-online-auth.top/signin",
        "https://login-microsoftonline-account.club/auth",
        "https://amazon-order-verification.info/update-payment",
        "https://amazon-security-alert.work/account/login",
        "https://appleid-apple-support.com/verify-identity",
        "https://apple-icloud-login-check.gq/auth",
        "https://facebook-security-checkpoint.cf/login.php",
        "https://instagram-verify-badge-claim.online/claim",
        "https://netflix-billing-update-required.site/account",
        "https://linkedin-job-application-auth.buzz/signin",
        "https://github-account-security-alert.icu/auth",
        "https://twitter-blue-verification-free.tk/verify",
        "https://binance-wallet-verification.monster/login",
        "https://coinbase-account-unlock-support.best/auth",

        # IP Address Hostnames
        "http://192.168.1.100/paypal/login.html",
        "http://45.33.22.11/secure/chase-bank/login",
        "http://185.220.101.5/apple/verify.php",
        "http://103.253.144.12/netflix/account-billing",
        "http://91.240.118.168/wellsfargo/auth",
        "http://198.51.100.23/amazon/update-card.html",
        "http://203.0.113.42/google/signin-prompt",

        # Suspicious TLDs + Keywords
        "https://secure-login-account-verify.xyz/signin",
        "https://update-billing-info-now.top/account",
        "https://verify-credential-access.club/login",
        "https://passcode-auth-verification.online/webscr",
        "https://banking-security-checkpoint.site/relogin",
        "https://authorize-wallet-confirm.buzz/checkpoint",
        "https://secure-passcode-update.icu/billing",
        "https://account-relogin-validation.tk/security",

        # Excessive Subdomains & Long Obfuscated URLs
        "https://login.verify.account.update.secure.paypal.auth-check.com/signin",
        "https://secure.banking.chase.com.customer-verification-portal.net/login.php",
        "https://signin.amazon.com.account-update-services-online.info/verify",
        "https://auth.google.com.user-security-checkpoint-verification.org/login",
        "https://appleid.apple.com.identity-verification-support-center.xyz/auth",

        # URL Shorteners hiding malicious destinations
        "https://bit.ly/3xYzP89_paypal_login",
        "https://tinyurl.com/secure-bank-verify-2026",
        "https://t.co/XyZ901AbCd_update",
        "https://is.gd/chase_security_update",
        "https://cutt.ly/netflix_free_subscription_claim",
        "https://rb.gy/binance_wallet_claim_bonus",

        # Suspicious Symbols & Special Characters
        "https://paypal.com@security-update-checkpoint.net/login",
        "https://google.com@auth-login-verify.xyz/account",
        "https://microsoft.com//auth//login//verify.php",
        "https://amazon.com?redirect=http://malicious-phish-site.com/login"
    ]

    # Expand the lists to reach 600 benign and 600 phishing URLs deterministically with varied paths, parameters, and query combinations
    full_legitimate = []
    base_legit_count = len(legitimate_urls)
    for i in range(600):
        base_url = legitimate_urls[i % base_legit_count]
        if i >= base_legit_count:
            # Vary path or query parameter
            cycle = i // base_legit_count
            if '?' in base_url:
                full_legitimate.append(f"{base_url}&ref=page_{cycle}&id={i}")
            else:
                full_legitimate.append(f"{base_url}/section/{cycle}?id={i}")
        else:
            full_legitimate.append(base_url)

    full_phishing = []
    base_phish_count = len(phishing_urls)
    for i in range(600):
        base_url = phishing_urls[i % base_phish_count]
        if i >= base_phish_count:
            cycle = i // base_phish_count
            if '?' in base_url:
                full_phishing.append(f"{base_url}&token=phish_session_{cycle}_{i}&action=verify")
            else:
                full_phishing.append(f"{base_url}/secure/step_{cycle}.php?user_id={i}")
        else:
            full_phishing.append(base_url)

    # Write to CSV
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'label'])
        for u in full_legitimate:
            writer.writerow([u, 0])
        for u in full_phishing:
            writer.writerow([u, 1])

    print(f"Dataset created successfully at {csv_path} with {len(full_legitimate)} benign and {len(full_phishing)} phishing samples (Total: {len(full_legitimate) + len(full_phishing)}).")

if __name__ == '__main__':
    generate_dataset()
