# PhishSense – Explainable Intelligent Phishing Detection System

PhishSense is a multi-layered, explainable cybersecurity web application engineered to analyze web addresses (URLs) and detect phishing threats in real time. It combines deterministic heuristic inspection, global threat intelligence feeds, deep learning sequence classification, and safe headless website rendering with strict Server-Side Request Forgery (SSRF) defenses.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Key Features](#key-features)
3. [System Architecture](#system-architecture)
4. [Detection Layers & Scoring Logic](#detection-layers--scoring-logic)
   - [Layer 1: Heuristic Rule Engine (0–40 Points)](#layer-1-heuristic-rule-engine-040-points)
   - [Layer 2: Threat Intelligence Feeds (-10 to 60 Points)](#layer-2-threat-intelligence-feeds--10-to-60-points)
   - [Layer 3: AI & Machine Learning Classification (0–30 Points)](#layer-3-ai--machine-learning-classification-030-points)
   - [Layer 4: Isolated Preview & SSRF Defense Boundary](#layer-4-isolated-preview--ssrf-defense-boundary)
   - [Layer 5: Composite Risk Scoring Formula & Ranges](#layer-5-composite-risk-scoring-formula--ranges)
   - [Layer 6: Explainability Architecture](#layer-6-explainability-architecture)
5. [Machine Learning Subsystem](#machine-learning-subsystem)
   - [Production Runtime Model (URLBERT v4 ONNX)](#production-runtime-model-urlbert-v4-onnx)
   - [Research & Feature Engineering Baseline (Random Forest)](#research--feature-engineering-baseline-random-forest)
   - [Benchmark Dataset Specifications](#benchmark-dataset-specifications)
   - [Fail-Safe AI Execution](#fail-safe-ai-execution)
6. [Threat Intelligence Integrations](#threat-intelligence-integrations)
7. [Project Structure](#project-structure)
8. [Installation & Local Setup](#installation--local-setup)
   - [Prerequisites](#prerequisites)
   - [1. Backend Setup](#1-backend-setup)
   - [2. Frontend Setup](#2-frontend-setup)
   - [3. Machine Learning Setup (Optional Training/Evaluation)](#3-machine-learning-setup-optional-trainingevaluation)
   - [Environment Variables Configuration](#environment-variables-configuration)
9. [API Endpoints Reference](#api-endpoints-reference)
10. [Authentication & History Management](#authentication--history-management)
11. [System Limitations](#system-limitations)
12. [License & Academic Attribution](#license--academic-attribution)

---

## Project Overview

Phishing attacks remain the leading vector for credential theft, ransomware deployment, and financial fraud. Modern phishing campaigns frequently employ tactics that defeat single-point detection mechanisms:

* **Zero-day phishing kits** on newly registered domains that have not yet appeared on threat blacklists.
* **Typosquatting and Unicode homoglyph spoofing** designed to visually impersonate trusted brands (`paypa1.com`, `pinteresl.com`, `apple-login-security.xyz`).
* **Subdomain nesting, link shorteners, and obfuscated query strings** to evade perimeter firewalls.

PhishSense solves these challenges through a **defense-in-depth, multi-layered pipeline**. Rather than presenting users with an opaque binary verdict or confusing technical logs, PhishSense correlates signals across static heuristics, real-time threat intelligence, and transformer-based neural sequence analysis to generate an **explainable risk score (0–100%)** accompanied by plain-English verdicts and actionable security recommendations.

---

## Key Features

* **Multi-Layered Detection Engine**: Evaluates URLs concurrently across deterministic heuristics, live threat intelligence feeds, and machine learning models.
* **AI-Powered URL Sequence Classification**: Employs an in-process **URLBERT v4** transformer classifier running on ONNX Runtime for sub-20ms neural inference.
* **13 Deterministic Heuristic Security Checks**: Detects typosquatting, Levenshtein brand distance, homoglyphs, IP hostnames, suspicious TLDs, excessive subdomains, shorteners, unencrypted HTTP, and authentication keywords.
* **Live Threat Intelligence Integration**: Connects to the **VirusTotal API v3**, **URLhaus API (abuse.ch)**, and **OpenPhish Community Feed** with in-memory caching.
* **Safe Isolated Website Preview**: Probes server reachability and renders visual website screenshots inside a hardened headless sandbox with DNS pinning and SSRF protection.
* **Strict SSRF Defenses**: Inspects all resolved IPv4/IPv6 addresses against private, loopback, link-local, carrier-grade NAT, and cloud metadata ranges before making outbound connections.
* **Explainable Human-Centered Interface**: Features a two-tiered UI: an **Executive Summary** for everyday browsing guidance and **Advanced Security Details** with interactive forensic breakdowns.
* **Authentication & Scan History**: Built-in user account management supporting 6-digit email OTP verification via SMTP (Nodemailer), password reset tokens, and persistent per-user scan records.
* **Guest Quota & Dark/Light Theme**: Built-in 3-scan guest allowance, instant sign-up unlock, and responsive Dark/Light UI styled with Tailwind CSS and GSAP micro-animations.

---

## System Architecture

```text
                                  ┌───────────────────────────────┐
                                  │      React 18 / Vite Client   │
                                  │ (Executive Summary + Forensics)│
                                  └───────────────┬───────────────┘
                                                  │ HTTP POST (JSON)
                                                  ▼
                                  ┌───────────────────────────────┐
                                  │    Express.js Backend API     │
                                  │  (Security Headers, Rate Limit│
                                  │   SSRF Guard, Auth/History)   │
                                  └───────────────┬───────────────┘
                                                  │
                ┌─────────────────────────────────┼─────────────────────────────────┐
                │                                 │                                 │
                ▼                                 ▼                                 ▼
┌───────────────────────────────┐ ┌───────────────────────────────┐ ┌───────────────────────────────┐
│     Layer 1: Heuristics       │ │     Layer 2: Threat Intel     │ │       Layer 3: AI / ML        │
│   (13 Deterministic Rules)    │ │ (VirusTotal, URLhaus, OpenPh) │ │ (URLBERT v4 ONNX Transformer) │
│        [0 – 40 Points]        │ │       [-10 – 60 Points]       │ │        [0 – 30 Points]        │
└───────────────┬───────────────┘ └───────────────┬───────────────┘ └───────────────┬───────────────┘
                │                                 │                                 │
                └─────────────────────────────────┼─────────────────────────────────┘
                                                  │
                                                  ▼
                                  ┌───────────────────────────────┐
                                  │      Risk Scoring Engine      │
                                  │   Final = clamp[0, 100](Sum)  │
                                  └───────────────┬───────────────┘
                                                  │
                                                  ▼
                                  ┌───────────────────────────────┐
                                  │     Explainable Response      │
                                  │  (Score, Verdict, Evidence,   │
                                  │   Safe Screenshot, Telemetry) │
                                  └───────────────────────────────┘
```

### Data Flow

1. **User Submission**: The user submits a raw URL string via the React frontend.
2. **Sanitization & SSRF Validation**: The Express backend normalizes the protocol, parses the WHATWG URL object, strips HTML tags, and validates destination IP addresses against private network ranges.
3. **Concurrent Detection Execution**:
   - The **Rule Engine** evaluates 13 lexical and domain structural checks synchronously.
   - The **Threat Intelligence Hub** queries VirusTotal, URLhaus, and OpenPhish concurrently (`Promise.all`).
   - The **AI Service** tokenizes the URL and executes in-process ONNX sequence classification.
4. **Isolated Preview Dispatch**: In parallel, the backend safely probes destination reachability and generates an isolated screenshot using headless Chromium/Edge.
5. **Score Aggregation**: The risk scoring engine computes weighted component points, strictly bounds the result between 0 and 100, assigns the risk category, and compiles human-readable security reasons.
6. **Result Presentation**: The frontend renders the Executive Summary and expandable Advanced Security Details.

---

## Detection Layers & Scoring Logic

### Layer 1: Heuristic Rule Engine (0–40 Points)

Implemented in [`backend/ruleEngine/engine.js`](file:///C:/Users/ADMIN/Desktop/PhishSense/backend/ruleEngine/engine.js), the rule engine analyzes lexical structure, character distributions, domain-level attributes, and known phishing patterns across 13 deterministic rules.

| Rule Key | Rule Name | Description & Detection Condition | Raw Points |
| :--- | :--- | :--- | :---: |
| `hasIpHost` | IP Hostname Risk | Hostname is an IPv4 or IPv6 literal (e.g. `http://192.168.1.1/login`) | +30 |
| `lookalikeDomain` | Brand Typosquatting | Levenshtein distance ($1-2$) or character substitution against 17 protected brands (`google`, `paypal`, `microsoft`, `amazon`, `apple`, `facebook`, `instagram`, `netflix`, `linkedin`, `pinterest`, `github`, `twitter`, `binance`, `coinbase`, `steam`, `chase`, `wellsfargo`) on non-official domains | +25 |
| `unicodeLookalikeDomain` | Homoglyph / IDN Spoofing | Domain contains Punycode prefix (`xn--`), non-ASCII characters, or Cyrillic/Greek homoglyphs | +25 |
| `suspiciousTld` | High-Risk TLD | Domain uses known high-abuse TLD (`.xyz`, `.top`, `.club`, `.info`, `.work`, `.gq`, `.cf`, `.ml`, `.ga`, `.online`, `.site`, `.buzz`, `.icu`, `.tk`, `.monster`, `.fit`, `.kim`, `.racing`, `.surf`, `.cc`, `.space`, `.best`) | +20 |
| `noHttps` | Protocol Security (HTTP) | Unencrypted plaintext HTTP protocol used | +15 |
| `urlShortener` | URL Shortener Masking | Domain belongs to known shortening services (`bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `is.gd`, `cutt.ly`, `rb.gy`, etc.) | +15 |
| `excessiveSubdomains` | Subdomain Complexity | Subdomain hierarchy exceeds 3 levels | +15 |
| `suspiciousKeywords` | Security Keywords | URL contains high-risk credential keywords (`login`, `signin`, `verify`, `account`, `secure`, `banking`, `password`, `wallet`, `checkpoint`, etc.) | +10 |
| `excessiveHyphens` | Hyphenation Abuse | Hostname contains more than 2 hyphens | +10 |
| `excessiveUrlLength` | Excessive URL Length | Total character count exceeds 75 characters | +10 |
| `suspiciousSymbols` | Suspicious Symbols | URL contains embedded `@` signs, double slashes `//` in path, `~`, `$`, or `*` | +10 |
| `excessiveNumbers` | Numeric Pattern Risk | Non-IP hostname contains more than 3 numeric digits | +10 |
| `deepUrlPath` | Deep Directory Path | Directory path exceeds 3 nested segments | +10 |

$$\text{Heuristics}_{\text{pts}} = \min\left(40, \sum \text{Triggered Rule Points}\right)$$

---

### Layer 2: Threat Intelligence Feeds (-10 to 60 Points)

Implemented in [`backend/threatIntel/intelProvider.js`](file:///C:/Users/ADMIN/Desktop/PhishSense/backend/threatIntel/intelProvider.js), PhishSense aggregates signals across three real-time threat intelligence sources:

1. **VirusTotal API v3** (`https://www.virustotal.com/api/v3/urls/{id}`):
   - Uses URL-safe Base64 encoding without padding (RFC 4648).
   - Multi-vendor consensus scoring:
     - $\ge 5$ malicious vendors: **+60 points** (Maximum threat signal)
     - $3 – 4$ malicious vendors: **+45 points**
     - $2$ malicious vendors: **+30 points** (or **+15 points** if established domain with $\ge 20$ harmless vendors)
     - $1$ malicious vendor: **+25 points** (or **+3 points** outlier flag if $\ge 20$ harmless vendors)
     - Suspicious-only vendors: **+10 to +15 points** (or **+2 to +5 points** if established clean domain)
     - Verified clean consensus ($\ge 20$ harmless, $0$ malicious, $0$ suspicious): **-10 points** (Clean reputation discount)
2. **URLhaus API (abuse.ch)** (`https://urlhaus-api.abuse.ch/v1/url/`):
   - Direct query against active malware/phishing repository.
   - Malicious record found: **+30 points**.
3. **OpenPhish Community Feed** (`https://openphish.com/feed.txt`):
   - Active phishing feed downloaded and cached in memory for 5 minutes.
   - Matching active phishing URL: **+30 points**.
4. **Google Safe Browsing**:
   - Documented and structured as an architected interface (`status: 'FUTURE INTEGRATION'`).

$$\text{ThreatIntel}_{\text{pts}} = \min\left(60, \max\left(-10, \text{Raw Intel Points}\right)\right)$$

---

### Layer 3: AI & Machine Learning Classification (0–30 Points)

Implemented in [`backend/services/aiService.js`](file:///C:/Users/ADMIN/Desktop/PhishSense/backend/services/aiService.js), PhishSense performs neural sequence classification directly in-process within Node.js using ONNX Runtime.

* **Model Architecture**: **URLBERT Tiny v4** (8 Transformer layers, 8 attention heads, hidden dimension 192, intermediate dimension 768, max sequence length 64).
* **Tokenizer**: Custom in-process WordPiece tokenizer parsing subwords against `ml/urlbert/tokenizer.json` (vocabulary size 400).
* **Domain Calibration**: Applies authentic brand apex domain verification on recognized domains (e.g. `google.com`, `paypal.com`, `microsoft.com`) to prevent sequence transformer token-bias false positives on legitimate high-traffic brands.
* **AI Scoring Points**:
  - If $P(\text{phishing}) \ge 0.50$: $\text{AI}_{\text{pts}} = \min(30, \max(0, \text{round}(P(\text{phishing}) \times 30)))$
  - If $P(\text{phishing}) < 0.50$: $\text{AI}_{\text{pts}} = 0$
* **Prediction Categories**:
  - $P \ge 0.70$: `PHISHING`
  - $0.40 \le P < 0.70$: `SUSPICIOUS`
  - $P < 0.40$: `BENIGN`

$$\text{AI}_{\text{pts}} \in [0, 30]$$

---

### Layer 4: Isolated Preview & SSRF Defense Boundary

Implemented in [`backend/services/previewService.js`](file:///C:/Users/ADMIN/Desktop/PhishSense/backend/services/previewService.js) and [`backend/utils/ssrfValidator.js`](file:///C:/Users/ADMIN/Desktop/PhishSense/backend/utils/ssrfValidator.js):

* **SSRF Protection**: Resolves all DNS `A` and `AAAA` records and rejects any private IPv4 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.169.254`, `100.64.0.0/10`), private IPv6 (`::1`, `fc00::/7`, `fe80::/10`), multicast, or cloud metadata hostnames (`metadata.google.internal`, `instance-data`).
* **Manual Redirect Handling**: Enforces manual redirect following with SSRF validation re-executed at every hop (capped at 3 hops).
* **Headless Screenshot Sandbox**: Renders an isolated PNG snapshot using local Chrome/Edge with hardened flags (`--headless`, `--no-sandbox`, `--disable-gpu`, `--deny-permission-prompts`, `--virtual-time-budget=4000`, `--host-resolver-rules=MAP 127.0.0.1 ~NOTFOUND, MAP localhost ~NOTFOUND, MAP 169.254.169.254 ~NOTFOUND`).
* **Process Isolation**: Guarantees termination of child processes and browser trees (`taskkill` / `SIGKILL`) with a strict 15-second timeout.

---

### Layer 5: Composite Risk Scoring Formula & Ranges

The final platform risk score aggregates all three detection layers into a strictly bounded 0–100 integer:

$$\text{Final Risk Score} = \min\left(100, \max\left(0, \text{round}\left(\text{Heuristics}_{\text{pts}} + \text{ThreatIntel}_{\text{pts}} + \text{AI}_{\text{pts}}\right)\right)\right)$$

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                            PHISHSENSE RISK TIERS                             │
├──────────────┬──────────────────┬────────────────────────────────────────────┤
│ Score Range  │ Classification   │ Recommended User Action                    │
├──────────────┼──────────────────┼────────────────────────────────────────────┤
│ 81 – 100     │ MALICIOUS        │ DANGEROUS: Do not visit, do not enter info │
│ 51 – 80      │ HIGH RISK        │ HIGH RISK: Multiple phishing signs detected│
│ 21 – 50      │ SUSPICIOUS / MED │ WARNING: Unverified link or anomalies      │
│ 0 – 20       │ LOW RISK (SAFE)  │ SAFE: No significant warning signs found   │
└──────────────┴──────────────────┴────────────────────────────────────────────┘
```

---

### Layer 6: Explainability Architecture

PhishSense rejects opaque "black-box" outputs:
1. **Executive Summary**: Displays a clear verdict badge, animated risk gauge, plain-English finding ("*This website appears to be pretending to be PayPal*"), actionable guidance, and an isolated screenshot preview.
2. **Advanced Technical Details**: Includes tabbed forensic views:
   - **AI Pattern Check**: Model prediction, sequence confidence percentage, token analysis finding.
   - **Domain & Structure**: Interactive 13-rule checklist with pass/fail/detected status.
   - **Threat Feeds**: VirusTotal vendor detection ratios, OpenPhish match status.
   - **Network Protocols**: TLS encryption status, SSRF defense status, public destination verification.
   - **Risk Calculation**: Step-by-step mathematical breakdown showing exact point contributions ($\text{Heuristics} + \text{Intel} + \text{AI} = \text{Score}$).
   - **Reachability**: HTTP status code, latency (ms), content type, and server response.

---

## Machine Learning Subsystem

### Production Runtime Model (URLBERT v4 ONNX)

* **Deployment Target**: `backend/services/aiService.js` loads `ml/urlbert/model.onnx` and `ml/urlbert/tokenizer.json`.
* **Execution Engine**: `onnxruntime-node` on CPU.
* **Architecture**: BERT sequence classifier (`BertForSequenceClassification`):
  - Hidden Layers: 8
  - Attention Heads: 8
  - Hidden Embedding Size: 192
  - Intermediate Feedforward Size: 768
  - Max Sequence Length: 64 tokens
  - Vocabulary Size: 400 WordPiece subwords
* **Inference Latency**: Typically $10 – 20\text{ ms}$ on commodity hardware.

### Research & Feature Engineering Baseline (Random Forest)

Implemented in `ml/` for tabular benchmarking and comparative research:

* **Feature Extractor** ([`ml/feature_extractor.py`](file:///C:/Users/ADMIN/Desktop/PhishSense/ml/feature_extractor.py)): Extracts 29 handcrafted features from raw URL strings:
  1. *Lexical (13)*: `url_length`, `hostname_length`, `path_length`, `dots_count`, `hyphens_count`, `underscores_count`, `slashes_count`, `special_chars_count`, `digits_count`, `digit_ratio`, `query_params_count`, `fragments_count`, `subdomains_count`.
  2. *Security & Protocol (14)*: `has_https`, `has_http`, `has_ip_host`, `suspicious_tld`, `url_shortener`, `excessive_subdomains`, `keyword_login`, `keyword_secure`, `keyword_verify`, `keyword_account`, `keyword_update`, `keyword_password`, `keyword_payment`, `suspicious_keywords_count`.
  3. *Domain Impersonation (2)*: `brand_similarity_detected` (Levenshtein typosquatting), `homoglyph_idn_indicator` (Punycode/non-ASCII).
* **Model** ([`ml/train_model.py`](file:///C:/Users/ADMIN/Desktop/PhishSense/ml/train_model.py)): 25-tree Random Forest Classifier (max depth 8) trained with zero native C-extension dependencies for 100% portability.
* **Serialized Outputs**: `ml/model/phish_model.json` (tree nodes) and `ml/model/feature_names.json` (feature metadata).

### Benchmark Dataset Specifications

* **Dataset Name**: PhishSense Cybersecurity URL Benchmark Dataset (v1.0) ([`ml/dataset/DATASET_INFO.md`](file:///C:/Users/ADMIN/Desktop/PhishSense/ml/dataset/DATASET_INFO.md))
* **Total Samples**: 1,200 labeled URLs
  - **Benign Class (`0`)**: 600 URLs (Tranco Top 1M, Wikipedia, Google, GitHub, Microsoft, Apple, AWS)
  - **Phishing Class (`1`)**: 600 URLs (PhishTank, OpenPhish, URLhaus verified threat feeds)
* **Train/Test Split**: Stratified 80/20 split (960 Training / 240 Testing; seed 42)
* **Evaluation Metrics on Test Set (240 unseen samples: 120 Benign, 120 Phishing)**:
  - **Accuracy**: $100.00\%$
  - **Precision**: $100.00\%$
  - **Recall**: $100.00\%$
  - **F1-Score**: $1.000$
  - **ROC-AUC**: $0.9958$
  - **Confusion Matrix**: $\text{TN} = 120, \text{FP} = 0, \text{FN} = 0, \text{TP} = 120$

### Fail-Safe AI Execution

If the ONNX model files are missing, corrupted, or the runtime encounters an exception, `aiService.js` catches the error, logs a warning, and returns `{ available: false, status: 'TEMPORARILY UNAVAILABLE', probability: 0.0 }`. The core detection pipeline **never crashes** and continues operating using static heuristics and threat intelligence.

---

## Threat Intelligence Integrations

| Provider | Integration Type | Endpoint / Protocol | Point Range | Status |
| :--- | :--- | :--- | :---: | :---: |
| **VirusTotal** | REST API v3 (JSON) | `https://www.virustotal.com/api/v3/urls/{id}` | -10 to +60 | Active (Key Configured) |
| **URLhaus** | REST API (POST) | `https://urlhaus-api.abuse.ch/v1/url/` | 0 or +30 | Active (Key Configured) |
| **OpenPhish** | HTTP Text Feed | `https://openphish.com/feed.txt` | 0 or +30 | Active (5-min In-Memory Cache) |
| **Google Safe Browsing** | REST API | Interface Placeholder | 0 or +40 | Future Integration |

---

## Project Structure

```text
PhishSense/
├── AI_IMPLEMENTATION_REPORT.md   # Comprehensive technical report on AI/ML subsystem
├── AI_TEST_RESULTS.md            # Empirical test suite results with score breakdowns
├── README.md                     # Primary system architecture & operational documentation
├── STUDENT_DETAILS.txt           # Academic submission metadata
├── backend/                      # Node.js / Express backend service
│   ├── config/
│   │   └── config.js             # Central configuration loader
│   ├── controllers/
│   │   ├── authController.js     # User registration, login, OTP verification, password reset
│   │   ├── historyController.js  # Scan history retrieval and management
│   │   ├── phishController.js    # URL analysis orchestrator controller
│   │   └── previewController.js  # Safe URL reachability and screenshot controller
│   ├── data/
│   │   ├── history.json          # Persistent scan history JSON database
│   │   └── users.json            # Persistent user accounts JSON database
│   ├── middleware/
│   │   └── authMiddleware.js     # JWT extraction and optional/required auth guards
│   ├── routes/
│   │   ├── authRoutes.js         # Authentication routes (/api/v1/auth)
│   │   ├── historyRoutes.js      # Scan history routes (/api/v1/history)
│   │   ├── phishRoutes.js        # Detection routes (/api/v1/phish)
│   │   └── previewRoutes.js      # Isolated preview routes (/api/v1/preview)
│   ├── ruleEngine/
│   │   └── engine.js             # 13-rule heuristic phishing detection engine
│   ├── scripts/
│   │   ├── auditSuite.js         # End-to-end security audit test script
│   │   ├── devResetAccounts.js   # Development account reset script
│   │   ├── scanSecrets.js        # Secret leak scanner utility
│   │   ├── testEmailDelivery.js  # SMTP email delivery tester
│   │   └── verifyPreview.js      # Isolated preview verification script
│   ├── services/
│   │   ├── aiService.js          # In-process URLBERT v4 ONNX model inference service
│   │   ├── detectionService.js   # Multi-layer score orchestrator & breakdown calculator
│   │   ├── emailService.js       # Nodemailer SMTP transporter & email templates
│   │   ├── historyService.js     # User scan persistence service
│   │   ├── previewService.js     # Headless browser preview and screenshot capture
│   │   └── userService.js        # User authentication, OTP hashing, and credential logic
│   ├── threatIntel/
│   │   └── intelProvider.js      # Connectors for VirusTotal, URLhaus, and OpenPhish
│   ├── utils/
│   │   ├── authUtils.js          # Password hashing (PBKDF2/SHA256), tokens, OTP generator
│   │   ├── logger.js             # Structured Winston logging utility
│   │   └── ssrfValidator.js      # RFC-compliant SSRF defense validator and IP resolver
│   ├── .env.example              # Environment variables template (no secrets)
│   ├── package.json              # Backend dependencies and run scripts
│   └── server.js                 # Express application entry point & HTTP server
├── docs/
│   └── architecture.md           # Mermaid sequence diagrams and design notes
├── frontend/                     # React 18 / Vite frontend application
│   ├── public/
│   │   ├── phishsense_icon.png   # PhishSense application icon
│   │   ├── phishsense_logo.png   # PhishSense full logo
│   │   └── secure-login.svg      # Authentication illustration asset
│   ├── src/
│   │   ├── assets/               # Bundled images and logos
│   │   ├── components/
│   │   │   ├── AuthModal.jsx     # Modal for Sign In, Sign Up, OTP, and Password Reset
│   │   │   ├── Button.jsx        # Reusable button component
│   │   │   ├── DetailedAnalysis.jsx # Tabbed technical forensics and layer inspector
│   │   │   ├── ExecutiveSummary.jsx # Verdict card, recommendations, and preview frame
│   │   │   ├── RiskGauge.jsx     # Visual SVG risk gauge component
│   │   │   └── ScanHistory.jsx   # Interactive scan history table with inspect modal
│   │   ├── services/
│   │   │   └── api.js            # API client wrapper with safe JSON error parsing
│   │   ├── utils/
│   │   │   ├── helpers.js        # Formatters, motion detection, and data URI validators
│   │   │   └── historyStorage.js # LocalStorage fallback & backend synchronization
│   │   ├── App.css               # Component-level styles
│   │   ├── App.jsx               # Main application container & view router
│   │   ├── index.css             # Tailwind CSS imports and typography rules
│   │   └── main.jsx              # React DOM mounting entry point
│   ├── index.html                # Single Page Application HTML template
│   ├── package.json              # Frontend dependencies and Vite scripts
│   ├── postcss.config.js         # PostCSS configuration for Tailwind
│   ├── tailwind.config.js        # Tailwind CSS theme configuration
│   └── vite.config.js            # Vite build configuration
└── ml/                           # Machine Learning module & Python assets
    ├── dataset/
    │   ├── build_dataset.py      # Benchmark dataset generator script
    │   ├── DATASET_INFO.md       # Dataset metadata and distribution documentation
    │   └── phishing_urls.csv     # 1,200 labeled URL benchmark dataset
    ├── model/
    │   ├── feature_names.json    # Saved 29 feature list and Random Forest metrics
    │   └── phish_model.json      # Serialized Random Forest decision tree weights
    ├── urlbert/
    │   ├── config.json           # URLBERT v4 model architecture configuration
    │   ├── model.onnx            # Serialized ONNX Transformer model weights
    │   ├── model.onnx.data       # ONNX tensor binary weights
    │   ├── tokenizer.json        # WordPiece vocabulary (400 subword tokens)
    │   └── tokenizer_config.json # Tokenizer parameters
    ├── evaluate_model.py         # Independent evaluation script for Random Forest
    ├── feature_extractor.py      # 29-feature extractor & explainability indicator builder
    ├── predict.py                # Standalone CLI prediction interface
    ├── README.md                 # ML subsystem documentation
    ├── run_test_suite.py         # Test suite runner executing backend detection tests
    ├── test_auth_flow.js         # Auth layer unit test script
    └── train_model.py            # Reproducible 80/20 train/test training pipeline
```

---

## Installation & Local Setup

### Prerequisites

* **Node.js**: v18.0.0 or higher
* **npm**: v9.0.0 or higher
* **Python**: v3.8 or higher (optional, only required if retraining the Random Forest model)
* **Google Chrome or Microsoft Edge**: (optional, detected automatically for isolated website screenshots)

---

### 1. Backend Setup

```bash
# Navigate to the backend directory
cd backend

# Install dependencies (Express, onnxruntime-node, nodemailer, winston, cors, dotenv)
npm install

# Create local environment configuration
cp .env.example .env

# Start backend server in development mode
npm run dev

# Or start in standard production mode
npm start
```

The backend service will start on `http://localhost:5000`.

---

### 2. Frontend Setup

```bash
# In a new terminal window, navigate to the frontend directory
cd frontend

# Install frontend dependencies (React 18, Vite, Tailwind CSS, GSAP)
npm install

# Start Vite development server
npm run dev
```

Open your browser at `http://localhost:5173`.

---

### 3. Machine Learning Setup (Optional Training/Evaluation)

To retrain the Random Forest baseline model or evaluate metrics:

```bash
# Navigate to the ml directory
cd ml

# (Optional) Rebuild the 1,200-sample benchmark dataset
python dataset/build_dataset.py

# Train the Random Forest classifier
python train_model.py

# Evaluate model metrics and display confusion matrix
python evaluate_model.py

# Test CLI prediction on a URL
python predict.py "https://accounts-google-verify.com/login"
```

---

### Environment Variables Configuration

Create a `.env` file in the `backend/` directory based on `.env.example`:

```ini
# Server Configuration
PORT=5000
NODE_ENV=development
LOG_LEVEL=info

# Threat Intelligence API Keys (Optional)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
URLHAUS_API_KEY=your_urlhaus_api_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_safe_browsing_key_here

# SMTP Email Delivery Configuration (Optional - for real email verification codes)
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=your_email@gmail.com
# SMTP_PASS=your_16_char_google_app_password
# SMTP_FROM="PhishSense Security" <your_email@gmail.com>
```

> [!NOTE]
> If external SMTP credentials are not configured, the backend automatically provisions an ephemeral Ethereal test mailbox during development and logs the preview link to the terminal.

---

## API Endpoints Reference

### Phishing Detection & Preview

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `POST` | `/api/v1/phish/analyze` | Analyzes target URL across heuristics, threat intel, and AI | No |
| `POST` | `/api/v1/preview` | Generates safe website preview and reachability telemetry | No |
| `GET` | `/health` | Server health check endpoint | No |

#### Example Request (`POST /api/v1/phish/analyze`)

```json
{
  "url": "https://accounts-google-verify.com/login"
}
```

#### Example Response (Truncated)

```json
{
  "url": "https://accounts-google-verify.com/login",
  "timestamp": "2026-08-31T19:00:00.000Z",
  "score": 65,
  "classification": "HIGH RISK",
  "reasons": [
    "Possible Google impersonation detected. Domain differs from legitimate brand domain (google.com).",
    "Suspicious keyword detected: login, verify",
    "AI detected strong phishing patterns (100% pattern match)."
  ],
  "scoreBreakdown": [
    { "name": "Domain Impersonation Risk", "points": 25, "category": "heuristic" },
    { "name": "Suspicious Keywords Risk", "points": 10, "category": "heuristic" },
    { "name": "AI Model Phishing Contributor", "points": 30, "category": "ai", "detail": "Probability: 100% (PHISHING)" }
  ],
  "details": {
    "heuristics": { "lookalikeDomain": true, "suspiciousKeywords": true },
    "threatIntel": { "virusTotal": { "status": "CONNECTED", "detections": 0 } },
    "aiAnalysis": {
      "available": true,
      "prediction": "PHISHING",
      "probability": 1.0,
      "confidence": 100,
      "model_type": "URLBERT Tiny v4 Classifier"
    },
    "scoringModel": {
      "heuristicComponent": 35,
      "intelComponent": 0,
      "aiComponent": 30
    }
  }
}
```

---

### Authentication & Scan History

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `POST` | `/api/v1/auth/register` | Registers new user account (dispatches 6-digit email OTP) | No |
| `POST` | `/api/v1/auth/login` | Authenticates user (requires verified email) | No |
| `POST` | `/api/v1/auth/verify-email` | Verifies account using 6-digit OTP | No |
| `POST` | `/api/v1/auth/resend-verification` | Resends OTP code (30s cooldown) | No |
| `POST` | `/api/v1/auth/forgot-password` | Requests password reset token via email | No |
| `POST` | `/api/v1/auth/reset-password` | Resets password using single-use token | No |
| `GET` | `/api/v1/auth/me` | Retrieves authenticated user profile | Yes (JWT) |
| `POST` | `/api/v1/auth/logout` | Clears user session | No |
| `GET` | `/api/v1/history` | Fetches scan history for authenticated user or guest | Optional |
| `POST` | `/api/v1/history` | Saves a scan record to history | Optional |
| `DELETE` | `/api/v1/history/:id` | Deletes a specific scan record by ID | Optional |
| `DELETE` | `/api/v1/history` | Clears all scan history for the user | Optional |

---

## Authentication & History Management

* **Guest Mode**: Allows up to 3 scans without registration, with history persisted in browser `localStorage`.
* **Registered Mode**: Unlocks unlimited scans. When registered, scans are stored persistently in `backend/data/history.json` and associated with the user's verified account.
* **Email Verification**: Enforces a 6-digit cryptographic OTP code expiring in 10 minutes with a 5-attempt limit to prevent brute-force attacks.
* **Password Security**: Passwords are validated against length ($\ge 8$ characters) and complexity requirements, salted with a 16-byte random salt, and hashed via PBKDF2/SHA-256 (100,000 iterations).

---

## System Limitations

1. **URL-Lexical & Sequence Scope**: PhishSense evaluates URLs statically and via headless visual rendering; it does not execute deep dynamic JavaScript payloads, multi-step CAPTCHAs, or download file attachments.
2. **Cloaked Phishing Kits**: Phishing kits that selectively serve benign content to security scanners (IP cloaking or geofencing) may evade initial heuristic detection until reported to threat intelligence feeds.
3. **External API Rate Limits**: Threat intelligence lookup depth depends on available quota for third-party API keys (e.g. VirusTotal free tier limits). If keys are absent or rate-limited, the system falls back seamlessly to heuristics and local AI.
4. **Zero-Day Obfuscations**: While URLBERT v4 generalizes across subword tokens, entirely novel evasion structures with authentic-looking domains and no security keywords may achieve lower initial risk scores until contextual threat signals appear.

---

## License & Academic Attribution

Developed for academic submission and cybersecurity research at the **Department of Computer Science, Kwame Nkrumah University of Science and Technology (KNUST)**.

* **Student Name**: Adiza Malik
* **Index Number**: 9026923
* **Supervisor**: Dr. Kate Takyi
* **Academic Year**: 2025/2026
