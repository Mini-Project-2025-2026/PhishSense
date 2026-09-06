# PhishSense ML Dataset Documentation

## Dataset Metadata

- **Dataset Name**: PhishSense Cybersecurity URL Benchmark Dataset (v1.0)
- **Primary Sources**:
  1. **Phishing/Malicious URLs**: Verified threat feeds from PhishTank (phishtank.org), OpenPhish (openphish.com), and URLhaus (urlhaus.abuse.ch).
  2. **Legitimate/Benign URLs**: Top 1M global domain benchmarks from Tranco List (tranco-list.eu) and legitimate multi-path web pages (Google, GitHub, Wikipedia, Microsoft, AWS, Apple, etc.).
- **Source URLs**:
  - PhishTank: `https://phishtank.org/phish_search.php`
  - URLhaus: `https://urlhaus.abuse.ch/api/`
  - OpenPhish: `https://openphish.com/feed.txt`
  - Tranco List: `https://tranco-list.eu/`
- **Total Sample Count**: 1,200 URLs
  - Legitimate (`0`): 600 URLs (50.0%)
  - Phishing (`1`): 600 URLs (50.0%)
- **Label Format**:
  - `url`: String representing the normalized target URL
  - `label`: Integer (`0` = Legitimate / Benign, `1` = Phishing / Malicious)

---

## Data Preprocessing & Sanitization Pipeline

Before model training, the raw dataset underwent the following verification steps:

1. **URL Format Validation**: Sanitized protocol headers (`http://`, `https://`) and removed malformed strings.
2. **Deduplication**: Removed duplicate URL strings to prevent data leakage between training and test sets.
3. **Class Imbalance Verification**: Maintained a balanced 50:50 distribution (600 benign, 600 phishing) to ensure unbiased evaluation metrics.
4. **Data Splitting**: Stratified 80/20 train/test split:
   - **Training Set**: 960 URLs (480 Benign, 480 Phishing)
   - **Test Set**: 240 URLs (120 Benign, 120 Phishing)
