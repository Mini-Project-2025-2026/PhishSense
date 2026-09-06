#!/usr/bin/env python3
"""
PhishSense Feature Extractor Module
Extracts 25 numerical features from URL strings for machine learning phishing detection.
Integrates domain impersonation, security protocol analysis, and lexical indicators.
"""

import re
from urllib.parse import urlparse

# List of suspicious TLDs frequently abused in phishing campaigns
SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.club', '.info', '.work', '.gq', '.cf', '.ml', '.ga',
    '.online', '.site', '.buzz', '.icu', '.tk', '.monster', '.fit', '.kim',
    '.racing', '.surf', '.cc', '.space', '.best'
]

# Known URL shorteners
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly',
    'ow.ly', 'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'bc.vc',
    'v.gd', 'qr.ae', 'adf.ly'
]

# Protected brand targets for typosquatting / Levenshtein similarity analysis
PROTECTED_BRANDS = [
    {'name': 'Google', 'sld': 'google', 'domain': 'google.com'},
    {'name': 'PayPal', 'sld': 'paypal', 'domain': 'paypal.com'},
    {'name': 'Microsoft', 'sld': 'microsoft', 'domain': 'microsoft.com'},
    {'name': 'Amazon', 'sld': 'amazon', 'domain': 'amazon.com'},
    {'name': 'Apple', 'sld': 'apple', 'domain': 'apple.com'},
    {'name': 'Facebook', 'sld': 'facebook', 'domain': 'facebook.com'},
    {'name': 'Instagram', 'sld': 'instagram', 'domain': 'instagram.com'},
    {'name': 'Netflix', 'sld': 'netflix', 'domain': 'netflix.com'},
    {'name': 'LinkedIn', 'sld': 'linkedin', 'domain': 'linkedin.com'},
    {'name': 'Pinterest', 'sld': 'pinterest', 'domain': 'pinterest.com'},
    {'name': 'GitHub', 'sld': 'github', 'domain': 'github.com'},
    {'name': 'Twitter', 'sld': 'twitter', 'domain': 'twitter.com'},
    {'name': 'Binance', 'sld': 'binance', 'domain': 'binance.com'},
    {'name': 'Coinbase', 'sld': 'coinbase', 'domain': 'coinbase.com'},
    {'name': 'Steam', 'sld': 'steam', 'domain': 'steampowered.com'},
    {'name': 'Chase', 'sld': 'chase', 'domain': 'chase.com'},
    {'name': 'WellsFargo', 'sld': 'wellsfargo', 'domain': 'wellsfargo.com'}
]

# High-risk keywords
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'update', 'account',
    'banking', 'secure', 'security', 'webscr', 'cmd', 'password',
    'credential', 'wallet', 'confirm', 'authenticate', 'billing',
    'authorize', 'validation', 'checkpoint', 'relogin', 'passcode'
]

def levenshtein_distance(str1, str2):
    """Calculates Levenshtein edit distance between two strings."""
    m, n = len(str1), len(str2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if str1[i - 1] == str2[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,      # Deletion
                dp[i][j - 1] + 1,      # Insertion
                dp[i - 1][j - 1] + cost # Substitution
            )
    return dp[m][n]

def normalize_substitutions(s):
    """Normalizes common character substitutions in typosquatting."""
    return (s.replace('0', 'o')
             .replace('1', 'l')
             .replace('3', 'e')
             .replace('4', 'a')
             .replace('5', 's')
             .replace('8', 'b')
             .replace('@', 'a')
             .replace('$', 's')
             .replace('vv', 'w'))

def extract_features(url_str):
    """
    Extracts 25 numerical features from a URL string.
    Returns a dictionary mapping feature names to numerical values (float/int).
    """
    url_clean = url_str.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url_clean):
        url_clean = 'https://' + url_clean

    try:
        parsed = urlparse(url_clean)
        host = parsed.netloc.split(':')[0].lower()
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment
    except Exception:
        host = ""
        path = ""
        query = ""
        fragment = ""

    url_lower = url_clean.lower()
    url_len = len(url_clean)
    host_len = len(host)
    path_len = len(path)

    dots_count = url_clean.count('.')
    hyphens_count = url_clean.count('-')
    underscores_count = url_clean.count('_')
    slashes_count = url_clean.count('/')
    special_chars_count = len(re.findall(r'[@?=%&!~$+#]', url_clean))
    digits_count = len(re.findall(r'\d', url_clean))
    digit_ratio = round(digits_count / max(1, url_len), 4)

    query_params_count = len(query.split('&')) if query else 0
    fragments_count = 1 if fragment else 0

    host_parts = host.split('.')
    subdomains_count = max(0, len(host_parts) - 2)

    has_https = 1 if parsed.scheme == 'https' else 0
    has_http = 1 if parsed.scheme == 'http' else 0

    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^\[?[0-9a-fA-F:]+\]?$'
    has_ip_host = 1 if re.match(ip_pattern, host) else 0

    suspicious_tld = 1 if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0
    url_shortener = 1 if any(host == s or host.endswith('.' + s) for s in URL_SHORTENERS) else 0
    excessive_subdomains = 1 if subdomains_count > 3 else 0

    keyword_login = 1 if any(kw in url_lower for kw in ['login', 'signin']) else 0
    keyword_secure = 1 if any(kw in url_lower for kw in ['secure', 'security']) else 0
    keyword_verify = 1 if any(kw in url_lower for kw in ['verify', 'verification']) else 0
    keyword_account = 1 if 'account' in url_lower else 0
    keyword_update = 1 if 'update' in url_lower else 0
    keyword_password = 1 if any(kw in url_lower for kw in ['password', 'passcode', 'credential']) else 0
    keyword_payment = 1 if any(kw in url_lower for kw in ['payment', 'billing', 'banking', 'wallet']) else 0
    suspicious_keywords_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # Brand similarity & typosquatting analysis
    candidate_sld = host_parts[-2] if len(host_parts) >= 2 else host
    norm_sld = normalize_substitutions(candidate_sld)
    brand_similarity_detected = 0

    for brand in PROTECTED_BRANDS:
        is_legit = (host == brand['domain']) or host.endswith('.' + brand['domain']) or ('steampowered' in brand['domain'] and host.endswith('steamcommunity.com'))
        if is_legit:
            continue
        sld_contains = brand['sld'] in candidate_sld or brand['sld'] in norm_sld or brand['sld'] in host
        dist_raw = levenshtein_distance(candidate_sld, brand['sld'])
        dist_norm = levenshtein_distance(norm_sld, brand['sld'])
        min_dist = min(dist_raw, dist_norm)
        is_typo = len(candidate_sld) >= 4 and (min_dist == 1 or (min_dist == 2 and len(brand['sld']) >= 6))
        if sld_contains or is_typo:
            brand_similarity_detected = 1
            break

    # Homoglyph / IDN detection
    has_non_ascii = 1 if any(ord(c) > 127 for c in url_clean) else 0
    has_punycode = 1 if 'xn--' in host else 0
    homoglyph_idn_indicator = 1 if (has_non_ascii or has_punycode) else 0

    features = {
        "url_length": float(url_len),
        "hostname_length": float(host_len),
        "path_length": float(path_len),
        "dots_count": float(dots_count),
        "hyphens_count": float(hyphens_count),
        "underscores_count": float(underscores_count),
        "slashes_count": float(slashes_count),
        "special_chars_count": float(special_chars_count),
        "digits_count": float(digits_count),
        "digit_ratio": float(digit_ratio),
        "query_params_count": float(query_params_count),
        "fragments_count": float(fragments_count),
        "subdomains_count": float(subdomains_count),
        "has_https": float(has_https),
        "has_http": float(has_http),
        "has_ip_host": float(has_ip_host),
        "suspicious_tld": float(suspicious_tld),
        "url_shortener": float(url_shortener),
        "excessive_subdomains": float(excessive_subdomains),
        "keyword_login": float(keyword_login),
        "keyword_secure": float(keyword_secure),
        "keyword_verify": float(keyword_verify),
        "keyword_account": float(keyword_account),
        "keyword_update": float(keyword_update),
        "keyword_password": float(keyword_password),
        "keyword_payment": float(keyword_payment),
        "suspicious_keywords_count": float(suspicious_keywords_count),
        "brand_similarity_detected": float(brand_similarity_detected),
        "homoglyph_idn_indicator": float(homoglyph_idn_indicator)
    }

    return features

def get_feature_names():
    """Returns standard ordered list of feature names."""
    dummy = extract_features("https://example.com")
    return list(dummy.keys())

def generate_explainable_indicators(features):
    """
    Generates human-readable explainability bullet points corresponding to actual extracted features.
    """
    indicators = []
    if features.get('brand_similarity_detected', 0) > 0:
        indicators.append("Brand impersonation / typosquatting similarity detected")
    if features.get('has_ip_host', 0) > 0:
        indicators.append("Raw IP address used as hostname")
    if features.get('suspicious_tld', 0) > 0:
        indicators.append("High-risk / suspicious TLD extension")
    if features.get('has_http', 0) > 0:
        indicators.append("Unencrypted HTTP protocol transport")
    if features.get('url_shortener', 0) > 0:
        indicators.append("URL shortener domain obfuscation")
    if features.get('excessive_subdomains', 0) > 0:
        indicators.append(f"Excessive subdomain complexity ({int(features.get('subdomains_count', 0))} levels)")
    if features.get('suspicious_keywords_count', 0) > 0:
        indicators.append(f"Suspicious authentication keywords detected ({int(features.get('suspicious_keywords_count', 0))} keywords)")
    if features.get('url_length', 0) > 75:
        indicators.append(f"Excessive URL length ({int(features.get('url_length', 0))} characters)")
    if features.get('digit_ratio', 0) > 0.15:
        indicators.append(f"High numeric character ratio ({int(features.get('digit_ratio', 0) * 100)}% digits)")
    if features.get('homoglyph_idn_indicator', 0) > 0:
        indicators.append("IDN homoglyph / non-ASCII character spoofing")
    if features.get('hyphens_count', 0) > 2:
        indicators.append(f"Excessive hyphenation ({int(features.get('hyphens_count', 0))} hyphens)")

    if not indicators:
        indicators.append("Standard URL structure with low risk indicators")

    return indicators
