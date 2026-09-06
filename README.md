# PhishSense – Explainable Intelligent Phishing Detection System

PhishSense is a multi-layered, explainable cybersecurity web application designed to analyze web addresses (URLs) and assess phishing threats in real time. Rather than relying on single-point heuristics or opaque binary verdicts, PhishSense integrates deterministic lexical and domain inspection, live threat intelligence feeds, deep learning sequence classification via **URLBERT**, and safe website preview rendering with strict Server-Side Request Forgery (SSRF) defenses.

---

## Academic Information

* **Institution**: Kwame Nkrumah University of Science and Technology (KNUST)
* **Department**: Department of Computer Science
* **Degree**: B.Sc. Computer Science
* **Student Name**: Adiza Malik
* **Index Number**: 9026923
* **Project Supervisor**: Dr. Kate Takyi
* **Academic Year**: 2025 / 2026

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Problem Statement & Threat Vectors](#2-problem-statement--threat-vectors)
3. [Main Detection Approach](#3-main-detection-approach)
4. [System Architecture](#4-system-architecture)
5. [Current Detection Layers & Components](#5-current-detection-layers--components)
   - [Layer 1: Heuristic Rule Engine (0–40 Points)](#layer-1-heuristic-rule-engine-040-points)
   - [Layer 2: Threat Intelligence Feeds (-10 to 60 Points)](#layer-2-threat-intelligence-feeds--10-to-60-points)
   - [Layer 3: AI & Machine Learning Classification (0–30 Points)](#layer-3-ai--machine-learning-classification-030-points)
   - [Layer 4: Isolated Website Preview & Reachability Probing](#layer-4-isolated-website-preview--reachability-probing)
   - [Layer 5: Server-Side Request Forgery (SSRF) Defense Boundary](#layer-5-server-side-request-forgery-ssrf-defense-boundary)
   - [Layer 6: Composite Risk Scoring & Classification Ranges](#layer-6-composite-risk-scoring--classification-ranges)
6. [Explainability & Human-Centered Interface](#6-explainability--human-centered-interface)
7. [Threat Intelligence Providers Implemented](#7-threat-intelligence-providers-implemented)
8. [AI / Machine Learning Subsystem (URLBERT)](#8-ai--machine-learning-subsystem-urlbert)
   - [Model Architecture & Specifications](#model-architecture--specifications)
   - [In-Process ONNX Runtime Integration](#in-process-onnx-runtime-integration)
   - [Custom WordPiece Tokenizer](#custom-wordpiece-tokenizer)
   - [Domain-Context Calibration](#domain-context-calibration)
   - [Softmax & Scoring Formulation](#softmax--scoring-formulation)
   - [Fail-Safe Error Boundary](#fail-safe-error-boundary)
9. [Website Preview & Network Security Probing](#9-website-preview--network-security-probing)
10. [SSRF Protection Architecture](#10-ssrf-protection-architecture)
11. [Technology Stack](#11-technology-stack)
    - [Frontend Technology](#frontend-technology)
    - [Backend Technology](#backend-technology)
    - [Machine Learning Technology](#machine-learning-technology)
12. [Project Folder Structure](#12-project-folder-structure)
13. [Installation & Setup Instructions](#13-installation--setup-instructions)
    - [Prerequisites](#prerequisites)
    - [Backend Setup](#backend-setup)
    - [Frontend Setup](#frontend-setup)
14. [Environment Variables Configuration](#14-environment-variables-configuration)
15. [Running the Application](#15-running-the-application)
16. [Testing & Verification Instructions](#16-testing--verification-instructions)
17. [API Endpoints Reference](#17-api-endpoints-reference)
18. [Authentication & Account Management](#18-authentication--account-management)
19. [Important System Limitations](#19-important-system-limitations)


---

## 1. Project Overview

Phishing remains one of the primary delivery vectors for credential theft, unauthorized access, and financial fraud. Modern phishing campaigns deploy sophisticated techniques—such as brand typosquatting, Unicode homoglyphs, sub-domain chaining, and evasion through link shorteners—that defeat simple static blocklists.

**PhishSense** implements a defense-in-depth security architecture that evaluates incoming URLs concurrently across three distinct analytical paradigms:
1. **Deterministic Heuristics**: Structural, lexical, protocol, and brand similarity checks that capture known structural anomalies instantly.
2. **Global Threat Intelligence**: Live threat reputation lookups from VirusTotal and OpenPhish to identify globally flagged campaigns and verified clean domains.
3. **Deep Learning Sequence Classification**: In-process neural transformer classification via **URLBERT Tiny v4**, which evaluates character-level token sequences for semantic phishing indicators.

The platform synthesizes these signals into an explainable **Risk Score (0–100%)**, assigns one of four clear risk classifications, and presents transparent evidence so users understand *why* a web address was flagged.

---

## 2. Problem Statement & Threat Vectors

### The Core Problem

1. **Evasion of Static Blacklists**: Zero-day phishing campaigns often operate on newly registered domains or disposable infrastructure that have not yet been indexed by threat blacklists.
2. **The "Black-Box" Usability Gap**: Conventional security tools often present users with a binary "Safe" or "Dangerous" label without explaining the underlying rationale, leaving users unable to assess borderline links or learn safe browsing habits.
3. **Visual Deception**: Attackers register lookalike domains using character substitutions (e.g., `paypa1.com` instead of `paypal.com`) or internationalized domain names (IDN homoglyphs) that visually mimic legitimate brands.

### Attack Patterns Addressed by PhishSense

* **Direct IP Hostnames**: Circumventing domain name systems by linking directly to raw IPv4/IPv6 addresses (e.g., `http://192.168.1.100/login`).
* **Brand Typosquatting & Impersonation**: Inserting brand names into subdomains or registering edit-distance variations of protected brands.
* **Homoglyph & IDN Spoofing**: Replacing Latin characters with visually identical Cyrillic, Greek, or Punycode (`xn--`) representations.
* **High-Abuse TLDs**: Utilizing low-cost or high-abuse top-level domains frequently associated with spam campaigns (`.xyz`, `.top`, `.tk`, etc.).
* **Protocol Downgrade**: Delivering credential forms over unencrypted plaintext HTTP.
* **URL Shorteners**: Concealing actual landing page destinations through redirection services (`bit.ly`, `tinyurl.com`, etc.).
* **Subdomain Complexity**: Stacking multiple subdomain levels to deceive users reading the URL from left to right.
* **Credential & Urgency Keywords**: Embedding targeted keywords (`login`, `verify`, `banking`, `secure`, `wallet`) into unauthorized hostnames and paths.

---

## 3. Main Detection Approach

PhishSense employs a **defense-in-depth, concurrent multi-layered approach**:

```text
Incoming Raw URL
       │
       ▼
[ Sanitization & Validation ]  ──▶ Strips tags, verifies protocol (HTTP/HTTPS), bounds length
       │
       ├───────────────────────────────────────────────┐
       │                                               │
       ▼                                               ▼
[ Concurrent Analytical Pipeline ]             [ Safe Preview Probe ]
 ├── Layer 1: Heuristic Rule Engine (0–40 pts)  ├── SSRF Validation (Private IP & DNS check)
 ├── Layer 2: Threat Intelligence (-10–60 pts)  ├── Manual Redirect Follow (Max 3 hops)
 └── Layer 3: URLBERT AI Inference (0–30 pts)   └── Headless Screenshot Sandbox
       │                                               │
       └───────────────────────┬───────────────────────┘
                               │
                               ▼
               [ Risk Scoring & Attribution Engine ]
                   Final Score = clamp[0, 100](Sum)
                               │
                               ▼
                     [ Explainable Output ]
                   Executive Summary + Forensics
```

* Each layer contributes independently to a unified, bounded risk score between 0 and 100 points.
* If any layer is unavailable or encounters a network error (e.g., threat feed timeout), the application handles the failure gracefully and continues evaluating the URL using the remaining active layers.

---

## 4. System Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CLIENT TIER (Frontend)                            │
│                  React 18 + Vite SPA + Tailwind CSS + GSAP                  │
│   [ URL Input ] ── [ Executive Summary ] ── [ Advanced Forensic Details ]  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTP POST (JSON)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SERVER TIER (Backend)                             │
│                  Node.js / Express.js REST API (Port 5000)                  │
│   ├── Security Headers (CSP, HSTS, X-Frame-Options: DENY)                   │
│   ├── In-Memory Rate Limiting (60 requests/min per IP)                      │
│   ├── Input Sanitization & Normalization                                    │
│   └── Session Authentication & Scan History Persistence                     │
└───────────────────┬─────────────────────────────────────┬───────────────────┘
                    │                                     │
                    ▼                                     ▼
┌─────────────────────────────────────┐ ┌─────────────────────────────────────┐
│         DETECTION SUBSYSTEM         │ │           PREVIEW SUBSYSTEM         │
│                                     │ │                                     │
│  Layer 1: Heuristic Rule Engine     │ │  SSRF Validator                     │
│  - 13 Deterministic Rules (0–40 pts)│ │  - DNS A/AAAA inspection            │
│                                     │ │  - Private/Loopback/Metadata block  │
│  Layer 2: Threat Intelligence Hub   │ │                                     │
│  - VirusTotal API v3                │ │  Safe Headless Browser Sandbox      │
│  - OpenPhish Community Feed         │ │  - Chromium/Edge automation         │
│                                     │ │  - Hardened DNS mapping flags       │
│  Layer 3: AI / ML Inference         │ │  - Process tree termination         │
│  - URLBERT Tiny v4 Transformer      │ │                                     │
│  - onnxruntime-node (CPU execution) │ │                                     │
└───────────────────┬─────────────────┘ └──────────────────┬──────────────────┘
                    │                                      │
                    └──────────────────┬───────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        COMPOSITE RISK SCORING ENGINE                        │
│             Final Score = min(100, max(0, round(H + TI + AI)))              │
│       Classification: LOW RISK (0-20) | SUSPICIOUS (21-50)                  │
│                       HIGH RISK (51-80) | MALICIOUS (81-100)                │
└─────────────────────────────────────────────────────────────────────────────┘
```

### End-to-End Data Flow

1. **User Submission**: The client enters a URL via the React web interface.
2. **Sanitization & Normalization**: The backend validates length ($\le 2048$ characters), strips HTML/script tags to prevent XSS, ensures the presence of an `http://` or `https://` protocol scheme, and parses the URL using the standard WHATWG URL parser.
3. **Concurrent Detection**:
   - `backend/ruleEngine/engine.js` runs 13 lexical and domain structural checks synchronously.
   - `backend/threatIntel/intelProvider.js` queries VirusTotal (if configured) and OpenPhish concurrently via `Promise.all`.
   - `backend/services/aiService.js` tokenizes the URL with an in-process WordPiece tokenizer and performs neural sequence inference using the URLBERT ONNX model.
4. **Isolated Preview Dispatch**: In parallel, `backend/services/previewService.js` performs SSRF validation on the destination host, probes reachability via manual redirect following, and captures a sandboxed screenshot using headless Chromium or Edge.
5. **Score Aggregation**: `backend/services/detectionService.js` aggregates the points, bounds the score strictly between 0 and 100, assigns the risk category, and compiles plain-English explanations.
6. **Presentation**: The frontend renders the Executive Summary (verdict banner, animated gauge, reasons, recommendations, screenshot) and allows expanding into the Advanced Security Details.

---

## 5. Current Detection Layers & Components

### Layer 1: Heuristic Rule Engine (0–40 Points)

Implemented in [`backend/ruleEngine/engine.js`](file:///C:/Users/ADMIN/Desktop/PhishSense/backend/ruleEngine/engine.js), the rule engine evaluates 13 deterministic security checks.

| Rule Key | Rule Name | Detection Condition | Raw Points |
| :--- | :--- | :--- | :---: |
| `hasIpHost` | Direct IP Host Address | Hostname is an IPv4 or IPv6 address literal | +30 |
| `lookalikeDomain` | Brand Typosquatting | Levenshtein distance ($1-2$) or character substitution against 17 protected brands (`Google`, `PayPal`, `Microsoft`, `Amazon`, `Apple`, `Facebook`, `Instagram`, `Netflix`, `LinkedIn`, `Pinterest`, `GitHub`, `Twitter`, `Binance`, `Coinbase`, `Steam`, `Chase`, `WellsFargo`) on non-official domains | +25 |
| `unicodeLookalikeDomain` | Lookalike Character Deception | Hostname contains Punycode prefix (`xn--`), non-ASCII characters, or Cyrillic/Greek homoglyphs | +25 |
| `suspiciousTld` | High-Risk Domain Extension | Domain uses a known high-abuse TLD (`.xyz`, `.top`, `.club`, `.info`, `.work`, `.gq`, `.cf`, `.ml`, `.ga`, `.online`, `.site`, `.buzz`, `.icu`, `.tk`, `.monster`, `.fit`, `.kim`, `.racing`, `.surf`, `.cc`, `.space`, `.best`) | +20 |
| `noHttps` | Transport Encryption (HTTP) | Protocol is insecure plaintext HTTP | +15 |
| `urlShortener` | URL Shortener Obfuscation | Domain belongs to a known URL shortener service (`bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `is.gd`, `buff.ly`, `ow.ly`, `rb.gy`, `cutt.ly`, `shorturl.at`, etc.) | +15 |
| `excessiveSubdomains` | Subdomain Nesting & Complexity | Subdomain hierarchy exceeds 3 levels | +15 |
| `suspiciousKeywords` | Suspicious Security Keywords | Hostname or path contains sensitive authentication keywords (`login`, `signin`, `verify`, `verification`, `update`, `account`, `banking`, `secure`, `security`, `password`, `credential`, `wallet`, etc.) | +10 |
| `excessiveHyphens` | Excessive Domain Hyphenation | Hostname contains more than 2 hyphens | +10 |
| `excessiveUrlLength` | Abnormal URL Length | Total URL length exceeds 75 characters | +10 |
| `suspiciousSymbols` | Suspicious URL Symbols | URL contains embedded `@` signs, double slashes `//` in path, `~`, `$`, or `*` | +10 |
| `excessiveNumbers` | Suspicious Numeric Patterns | Non-IP hostname contains more than 3 numeric digits | +10 |
| `deepUrlPath` | Deep Directory Path Structure | Directory path exceeds 3 nested segments | +10 |

**Heuristic Component Formula**:
$$\text{Heuristics}_{\text{pts}} = \min\left(40, \sum \text{Triggered Rule Points}\right)$$

---

### Layer 2: Threat Intelligence Feeds (-10 to 60 Points)

Implemented in [`backend/threatIntel/intelProvider.js`](file:///C:/Users/ADMIN/Desktop/PhishSense/backend/threatIntel/intelProvider.js), PhishSense aggregates signals across two live external intelligence feeds:

1. **VirusTotal API v3**:
   - URL is encoded into RFC 4648 Base64url format without padding.
   - Evaluates multi-vendor consensus across up to 90+ security engines:
     - $\ge 5$ malicious engines: **+60 points** (Maximum Threat Signal)
     - $3 – 4$ malicious engines: **+45 points**
     - $2$ malicious engines: **+30 points** (or **+15 points** if established domain with $\ge 20$ harmless engines)
     - $1$ malicious engine: **+25 points** (or **+3 points** outlier flag if $\ge 20$ harmless engines)
     - Suspicious-only engines: **+10 to +15 points** (or **+2 to +5 points** if established domain with $\ge 20$ harmless engines)
     - Verified clean consensus ($\ge 20$ harmless, $0$ malicious, $0$ suspicious): **-10 points** (Clean Reputation Discount)
2. **OpenPhish Community Feed**:
   - Downloads the active phishing community feed (`https://openphish.com/feed.txt`).
   - Caches entries in memory for 5 minutes (300,000 ms) to conserve bandwidth.
   - Matching active phishing URL: **+30 points**.

**Threat Intelligence Component Formula**:
$$\text{ThreatIntel}_{\text{pts}} = \min\left(60, \max\left(-10, \text{Raw Intel Points}\right)\right)$$

---

### Layer 3: AI & Machine Learning Classification (0–30 Points)

Implemented in [`backend/services/aiService.js`](file:///C:/Users/ADMIN/Desktop/PhishSense/backend/services/aiService.js), PhishSense executes in-process neural sequence inference using **URLBERT Tiny v4** via `onnxruntime-node`.

* **Model Family**: BERT Sequence Classifier (`BertForSequenceClassification`).
* **Input**: Raw URL character sequence encoded via WordPiece tokenizer (max sequence length 64).
* **Domain Calibration**: Authentic brand apex domains (e.g., `google.com`, `paypal.com`, `github.com`) are calibrated down ($P \le 0.05$) to eliminate token-bias false positives on legitimate high-traffic brands.
* **AI Scoring Points**:
  - If $P(\text{phishing}) \ge 0.50$: $\text{AI}_{\text{pts}} = \min(30, \max(0, \text{round}(P(\text{phishing}) \times 30)))$
  - If $P(\text{phishing}) < 0.50$: $\text{AI}_{\text{pts}} = 0$
* **Prediction Categories**:
  - $P \ge 0.70$: `PHISHING`
  - $0.40 \le P < 0.70$: `SUSPICIOUS`
  - $P < 0.40$: `BENIGN`

$$\text{AI}_{\text{pts}} \in [0, 30]$$

---

### Layer 4: Isolated Website Preview & Reachability Probing

Implemented in [`backend/services/previewService.js`](file:///C:/Users/ADMIN/Desktop/PhishSense/backend/services/previewService.js), PhishSense safely probes destination reachability and captures a visual screenshot:

* **Manual Redirect Navigation**: Follows HTTP redirects manually up to 3 hops, re-running SSRF checks at every hop.
* **Timeout Protection**: 5-second probe timeout.
* **Bot-Protection Detection**: Identifies automated-challenge interstitial pages (Cloudflare, DDoS-Guard, etc.).
* **Headless Browser Sandbox**: Automates local Chromium or Edge using restricted flags (`--headless`, `--no-sandbox`, `--disable-dev-shm-usage`, `--deny-permission-prompts`, `--virtual-time-budget=4000`, `--hide-scrollbars`, `--window-size=1280,720`).
* **Process Cleanup**: Enforces termination of child processes (`taskkill /F /T /PID` on Windows or `SIGKILL` on POSIX) with a strict 15-second timeout.

---

### Layer 5: Server-Side Request Forgery (SSRF) Defense Boundary

Implemented in [`backend/utils/ssrfValidator.js`](file:///C:/Users/ADMIN/Desktop/PhishSense/backend/utils/ssrfValidator.js):

* Enforces protocol restriction: only `http:` and `https:` schemes are permitted.
* Rejects embedded credentials in URLs (`user:pass@host`).
* Rejects explicit forbidden hostnames (`localhost`, `metadata.google.internal`, `instance-data`, etc.).
* Resolves all DNS `A` and `AAAA` records and validates each IP address against private, loopback, link-local, carrier-grade NAT, and cloud metadata ranges.
* Enforces browser-level DNS blacklisting via Chrome flag:
  `--host-resolver-rules=MAP 127.0.0.1 ~NOTFOUND, MAP localhost ~NOTFOUND, MAP 169.254.169.254 ~NOTFOUND, MAP 0.0.0.0 ~NOTFOUND, MAP [::1] ~NOTFOUND`.

---

### Layer 6: Composite Risk Scoring & Classification Ranges

Implemented in [`backend/services/detectionService.js`](file:///C:/Users/ADMIN/Desktop/PhishSense/backend/services/detectionService.js), the platform risk score combines all three detection components into a strictly bounded integer between 0 and 100:

$$\text{Final Risk Score} = \min\left(100, \max\left(0, \text{round}\left(\text{Heuristics}_{\text{pts}} + \text{ThreatIntel}_{\text{pts}} + \text{AI}_{\text{pts}}\right)\right)\right)$$

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                            PHISHSENSE RISK TIERS                             │
├──────────────┬──────────────────┬────────────────────────────────────────────┤
│ Score Range  │ Classification   │ Recommended User Action                    │
├──────────────┼──────────────────┼────────────────────────────────────────────┤
│ 81 – 100     │ MALICIOUS        │ DANGEROUS: Do not visit, do not enter info │
│ 51 – 80      │ HIGH RISK        │ HIGH RISK: Multiple phishing signs detected│
│ 21 – 50      │ SUSPICIOUS       │ WARNING: Unverified link or anomalies      │
│ 0 – 20       │ LOW RISK (SAFE)  │ SAFE: No significant warning signs found   │
└──────────────┴──────────────────┴────────────────────────────────────────────┘
```

---

## 6. Explainability & Human-Centered Interface

PhishSense adheres to the principles of **Explainable Artificial Intelligence (XAI)** by structuring analysis results into two complementary views:

### 1. Executive Summary (Everyday Browsing Guidance)
* **Verdict Banner**: Color-coded risk status (`LOW RISK`, `SUSPICIOUS`, `HIGH RISK`, `MALICIOUS`).
* **Animated Risk Gauge**: Smooth SVG gauge visualizing the 0–100 score.
* **Why We Flagged It**: Plain-English explanations describing exactly which patterns triggered risk (e.g., "*Possible PayPal impersonation detected. Domain differs from legitimate brand domain (paypal.com)*", "*AI detected strong phishing patterns (100% pattern match)*").
* **What Should You Do?**: Actionable security recommendations tailored to the risk tier.
* **Isolated Preview Status**: Indicators showing whether the website is reachable, rendered, bot-protected, or blocked by SSRF defense.

### 2. Advanced Security Details (Technical Forensics)
Accessible via the "View Security Details" button, this section provides 6 tabbed inspection views:
1. **AI Pattern Check**: URLBERT prediction category, sequence confidence percentage, token analysis finding, and exact AI point contribution (+0 to +30 pts).
2. **Domain & Structure**: Interactive checklist of all 13 heuristic rules with status badges (`Passed`, `Detected`, `Warning`), points, and expandable forensic descriptions.
3. **Threat Feeds**: Live status cards for VirusTotal (vendor detection ratio, individual flagged vendor names, outlier analysis) and OpenPhish (feed match indicator).
4. **Network Protocols**: Transport TLS encryption status, SSRF defense boundary verification, and public destination confirmation.
5. **Risk Calculation**: Complete mathematical equation displaying exact component contributions ($\text{Heuristics} + \text{Threat Intel} + \text{AI} = \text{Composite Score}$).
6. **Website Reachability**: HTTP status code, server response latency (ms), content type, and extracted page title.

---

## 7. Threat Intelligence Providers Implemented

| Provider | Type | Endpoint / Feed | Scoring Range | Requirement |
| :--- | :--- | :--- | :---: | :--- |
| **VirusTotal** | REST API v3 | `https://www.virustotal.com/api/v3/urls/{id}` | -10 to +60 pts | Optional API key (`VIRUSTOTAL_API_KEY`) |
| **OpenPhish** | HTTP Text Feed | `https://openphish.com/feed.txt` | 0 or +30 pts | Free community feed (No key required; 5-minute memory cache) |

> [!NOTE]
> * **URLhaus** and **Google Safe Browsing** are not active components in the current implementation.
> * If the `VIRUSTOTAL_API_KEY` is not provided in `.env`, the backend logs an informational note and continues operating in heuristic and AI detection mode without failure.

---

## 8. AI / Machine Learning Subsystem (URLBERT)

### Model Architecture & Specifications

PhishSense utilizes **URLBERT Tiny v4**, a deep bidirectional transformer model trained to evaluate lexical and structural subwords within URLs.

* **Architecture**: `BertForSequenceClassification` (BERT)
* **Transformer Layers (`num_hidden_layers`)**: 8
* **Attention Heads (`num_attention_heads`)**: 8
* **Hidden Dimension (`hidden_size`)**: 192
* **Intermediate Feedforward Dimension (`intermediate_size`)**: 768
* **Max Position Embeddings (`max_position_embeddings`)**: 64 tokens
* **Vocabulary Size (`vocab_size`)**: 400 WordPiece subwords
* **Hidden Activation**: GELU
* **Artifact Files** (located in `ml/urlbert/`):
  - `model.onnx`: Computation graph and model topology
  - `model.onnx.data`: Model tensor weight buffers
  - `tokenizer.json`: WordPiece vocabulary and token ID mappings
  - `config.json`: Model hyperparameters and layer definitions
  - `tokenizer_config.json`: Pre-tokenization and truncation settings

### In-Process ONNX Runtime Integration

Inference is executed directly inside the Node.js backend process via `onnxruntime-node` (v1.27.0). This design eliminates the latency, process overhead, and operational complexity of running a separate external Python daemon for real-time web requests.

* **Execution Provider**: CPU
* **Session Management**: Singleton session initialized and warmed up during server startup.
* **Inference Latency**: Typically sub-25 ms on commodity CPUs.

### Custom WordPiece Tokenizer

The backend implements an in-process JavaScript tokenizer (`UrlBertTokenizer` in [`backend/services/aiService.js`](file:///C:/Users/ADMIN/Desktop/PhishSense/backend/services/aiService.js)):
1. **Pre-tokenization**: Lowercases the URL string and isolates ASCII punctuation as individual tokens while preserving alphanumeric sequences.
2. **WordPiece Subword Encoding**: Applies greedy longest-match subword lookup using `##` continuation prefixes against the 400-token vocabulary.
3. **Tensor Formatting**: Generates 64-element `input_ids`, `attention_mask`, and `token_type_ids` vectors as `BigInt64Array` tensors, bounded with `[CLS]` and `[SEP]` markers.

### Domain-Context Calibration

Pure sequence transformers can exhibit token-bias false positives on legitimate brand names (such as `google`, `paypal`, or `microsoft`) because these tokens appear frequently in phishing training datasets. To prevent false alarms on authentic brand homepages:

* The service verifies whether the URL belongs to an authentic, recognized apex domain (`isAuthenticBrandApexDomain`).
* If verified as the genuine apex domain (and not a typosquat or subdomain masquerade), the phishing probability is calibrated to a safe baseline ($P \le 0.05$).

### Softmax & Scoring Formulation

The model outputs raw 2-class logits $[z_0, z_1]$. The phishing probability $P(\text{phishing})$ is derived using numerically stable Softmax:

$$m = \max(z_0, z_1), \quad P(\text{phishing}) = \frac{e^{z_1 - m}}{e^{z_0 - m} + e^{z_1 - m}}$$

The probability maps to the risk scoring engine as follows:
* If $P(\text{phishing}) \ge 0.50$:
  $$\text{AI}_{\text{pts}} = \min(30, \max(0, \text{round}(P(\text{phishing}) \times 30)))$$
* If $P(\text{phishing}) < 0.50$:
  $$\text{AI}_{\text{pts}} = 0$$

### Fail-Safe Error Boundary

If the ONNX model files are unreadable or an execution error occurs, `aiService.js` catches the exception and returns:
```json
{
  "available": false,
  "status": "TEMPORARILY UNAVAILABLE",
  "prediction": "UNAVAILABLE",
  "probability": 0.0,
  "confidence": 0
}
```
The core detection pipeline **never throws an unhandled error** and continues scoring the URL using heuristics and threat intelligence.

---

## 9. Website Preview & Network Security Probing

Implemented in [`backend/services/previewService.js`](file:///C:/Users/ADMIN/Desktop/PhishSense/backend/services/previewService.js), PhishSense includes a sandboxed website preview capability:

```text
Target URL
    │
    ▼
[ SSRF Validator ] ──(Fails)──▶ Returns BLOCKED / UNSAFE_DESTINATION (No connection made)
    │ (Passes)
    ▼
[ Manual Redirect Follower ] ──▶ Re-checks SSRF on every hop (Max 3 hops)
    │
    ▼
[ Bot Protection Check ] ────▶ Detects Cloudflare / DDoS-Guard challenge pages
    │ (Clean)
    ▼
[ Headless Browser Sandbox ] ──▶ Isolated Chromium/Edge process with DNS restriction flags
    │
    ▼
Base64 PNG Screenshot returned to client
```

### Preview Status Categories

1. **Live preview available** (`Emerald`): The target website is reachable, passed SSRF checks, and an isolated screenshot was captured.
2. **Website is reachable** (`Slate`): The target web server responded with valid HTTP headers, but visual rendering was unavailable or blocked by bot verification challenges.
3. **Preview blocked** (`Amber`): The target URL resolved to a private, loopback, or cloud metadata address and was blocked by SSRF defense before any outbound connection was initiated.
4. **Website unreachable** (`Slate`): The target server refused connection, timed out, or the domain could not be resolved in DNS.

---

## 10. SSRF Protection Architecture

Implemented in [`backend/utils/ssrfValidator.js`](file:///C:/Users/ADMIN/Desktop/PhishSense/backend/utils/ssrfValidator.js), the SSRF defense module protects internal infrastructure from server-side request forgery:

1. **Scheme Validation**: Strictly restricts URLs to `http:` and `https:`.
2. **Embedded Credential Check**: Blocks URLs containing `username` or `password` fields (`http://user:pass@host`).
3. **Explicit Hostname Blacklist**: Rejects `localhost`, `localhost.localdomain`, `local`, `broadcasthost`, `metadata.google.internal`, `metadata.google`, and `instance-data`.
4. **Comprehensive DNS Resolution**: Resolves target hostnames to all IPv4 (`A`) and IPv6 (`AAAA`) records using `dns.lookup(hostname, { all: true })`.
5. **Private IP Range Enforcement**:
   - **IPv4 Ranges Rejected**:
     - `0.0.0.0/8` (Current network)
     - `10.0.0.0/8` (Private Class A)
     - `100.64.0.0/10` (Carrier-grade NAT)
     - `127.0.0.0/8` (Loopback addresses)
     - `169.254.0.0/16` (Link-Local & Cloud Metadata `169.254.169.254`)
     - `172.16.0.0/12` (Private Class B)
     - `192.0.0.0/24`, `192.0.2.0/24` (TEST-NET-1)
     - `192.168.0.0/16` (Private Class C)
     - `198.18.0.0/15` (Benchmark testing)
     - `198.51.100.0/24` (TEST-NET-2), `203.0.113.0/24` (TEST-NET-3)
     - `224.0.0.0/4` (Multicast), `240.0.0.0/4` (Reserved)
     - `255.255.255.255` (Limited broadcast)
   - **IPv6 Ranges Rejected**:
     - `::1` (Loopback)
     - `::` (Unspecified)
     - `::ffff:0:0/96` (IPv4-mapped private addresses)
     - `fc00::/7` (Unique Local Addresses)
     - `fe80::/10` (Link-Local Unicast)
     - `ff00::/8` (Multicast)
     - `100::/64` (Discard prefix), `2001:db8::/32` (Documentation prefix)
6. **Sub-Resource DNS Isolation**: Headless Chromium is started with `--host-resolver-rules="MAP 127.0.0.1 ~NOTFOUND, MAP localhost ~NOTFOUND, MAP 169.254.169.254 ~NOTFOUND, MAP 0.0.0.0 ~NOTFOUND, MAP [::1] ~NOTFOUND"` to prevent web page sub-resources or scripts from accessing internal endpoints.

---

## 11. Technology Stack

### Frontend Technology

* **Core Framework**: React 18 (`react` 18.3.1, `react-dom` 18.3.1)
* **Build System & Dev Server**: Vite 5 (`vite` 5.3.1)
* **Styling**: Tailwind CSS (`tailwindcss` 3.4.19, `postcss` 8.5.15, `autoprefixer` 10.5.2)
* **Animation & Transitions**: GSAP (`gsap` 3.15.0) for score counters, gauge animations, and accordion reveals
* **Typography & Icons**: Inter / Outfit fonts, Google Material Symbols Outlined
* **State & Features**:
  - Light and Dark UI theme modes with persistent user preference
  - Guest scan limit (3 free scans) with `localStorage` fallback
  - Registered user session with persistent scan history synchronization
  - Responsive layout optimized for desktop, tablet, and mobile browsers

### Backend Technology

* **Runtime**: Node.js (v18.0.0 or higher recommended)
* **Web Framework**: Express.js (`express` 4.19.2)
* **Security & Middleware**:
  - Security HTTP headers (CSP, HSTS, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, X-XSS-Protection)
  - Custom in-memory rate limiting (60 requests per minute per IP with periodic memory cleanup)
  - Strict CORS origin validation (`cors` 2.8.5)
* **Logging**: Structured logging using Winston (`winston` 3.13.0)
* **Configuration**: `dotenv` (16.4.5)
* **Email Delivery**: Nodemailer (`nodemailer` 9.0.5) supporting SMTP (Gmail App Passwords or custom mail servers) with fallback to ephemeral Ethereal test accounts during development
* **Persistence**: Local JSON flat-file storage (`backend/data/users.json` and `backend/data/history.json`)
* **Cryptography & Authentication**:
  - Passwords hashed using PBKDF2 with SHA-512 (100,000 iterations, 16-byte cryptographically secure random salt)
  - Minimum 12-character password policy with common password blacklist validation
  - 6-digit numeric OTP generation with SHA-256 hash storage and constant-time verification (`crypto.timingSafeEqual`)
  - HMAC-SHA256 session token generation and authentication middleware

### Machine Learning Technology

* **Active Runtime Model**: **URLBERT Tiny v4**
* **Inference Framework**: ONNX Runtime Node.js binding (`onnxruntime-node` 1.27.0)
* **Target Hardware**: CPU inference
* **Tokenizer**: Custom JavaScript WordPiece implementation parsing vocabulary from `ml/urlbert/tokenizer.json`

---

## 12. Project Folder Structure

```text
PhishSense/
├── AI_TEST_RESULTS.md            # Empirical test suite results with score breakdowns
├── PHISHSENSE_Doc.pdf            # Academic project documentation PDF
├── README.md                     # Primary system architecture & operational documentation
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
│   │   └── authMiddleware.js     # Session token extraction and route guards
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
│   │   └── intelProvider.js      # Connectors for VirusTotal and OpenPhish
│   ├── utils/
│   │   ├── authUtils.js          # Password hashing (PBKDF2/SHA-512), tokens, OTP generator
│   │   ├── logger.js             # Structured Winston logging utility
│   │   └── ssrfValidator.js      # RFC-compliant SSRF defense validator and IP resolver
│   ├── .env.example              # Environment variables template (no secrets)
│   ├── package.json              # Backend dependencies and run scripts
│   └── server.js                 # Express application entry point & HTTP server
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
└── ml/                           # Machine Learning assets & evaluation utilities
    ├── dataset/
    │   ├── DATASET_INFO.md       # Dataset metadata and benchmark documentation
    │   ├── build_dataset.py      # Benchmark dataset generator script
    │   └── phishing_urls.csv     # Labeled URL benchmark dataset
    ├── urlbert/
    │   ├── config.json           # URLBERT v4 model architecture configuration
    │   ├── model.onnx            # Serialized ONNX Transformer model weights
    │   ├── model.onnx.data       # ONNX tensor binary weights
    │   ├── tokenizer.json        # WordPiece vocabulary (400 subword tokens)
    │   └── tokenizer_config.json # Tokenizer parameters
    ├── README.md                 # ML subsystem documentation
    ├── run_test_suite.py         # Test suite runner executing backend detection tests
    └── test_auth_flow.js         # Auth layer unit test script
```

---

## 13. Installation & Setup Instructions

### Prerequisites

* **Node.js**: v18.0.0 or higher
* **npm**: v9.0.0 or higher
* **Google Chrome or Microsoft Edge**: (Optional; automatically detected for headless website screenshot rendering)
* **Python**: v3.8 or higher (Optional; only needed if running benchmark test scripts in `ml/`)

---

### Backend Setup

```bash
# 1. Navigate to the backend directory
cd backend

# 2. Install dependencies (Express, onnxruntime-node, nodemailer, winston, cors, dotenv)
npm install

# 3. Create local environment configuration from template
cp .env.example .env

# 4. Start the backend in development mode (using nodemon)
npm run dev

# Or start in standard production mode
npm start
```

The backend service will listen on `http://localhost:5000`. On boot, it automatically initializes and warms up the URLBERT ONNX inference session.

---

### Frontend Setup

```bash
# 1. Open a new terminal and navigate to the frontend directory
cd frontend

# 2. Install dependencies (React 18, Vite, Tailwind CSS, GSAP)
npm install

# 3. Start the Vite development server
npm run dev
```

Open your browser and navigate to `http://localhost:5173`.

---

## 14. Environment Variables Configuration

Environment configuration is managed via `.env` in the `backend/` directory, structured using `backend/.env.example`:

```ini
# Server Configuration
PORT=5000
NODE_ENV=development
LOG_LEVEL=info

# Threat Intelligence API Keys (Optional)
# Enter your free VirusTotal API key to enable multi-vendor reputation lookups.
# If omitted or left blank, PhishSense continues running in heuristic & AI mode.
VIRUSTOTAL_API_KEY=your_virustotal_key_here

# Real Email Delivery Configuration (SMTP) - Optional
# By default in development, PhishSense automatically provisions an ephemeral
# Ethereal test inbox and prints email preview links to the console.
# To deliver real verification codes to user inboxes, configure SMTP credentials:

# Option A: Gmail SMTP (Requires a 16-character Google App Password)
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=your_address@gmail.com
# SMTP_PASS=your_16_char_app_password
# SMTP_FROM="PhishSense Security" <your_address@gmail.com>

# Option B: Custom / Transactional SMTP (SendGrid, Mailgun, Brevo, Resend, etc.)
# SMTP_HOST=smtp.resend.com
# SMTP_PORT=587
# SMTP_USER=resend
# SMTP_PASS=re_your_api_key
# SMTP_FROM="PhishSense" <security@yourverifieddomain.com>
```

---

## 15. Running the Application

1. **Start the Backend**:
   ```bash
   cd backend
   npm run dev
   ```
   *Terminal will log: `PhishSense backend service running on port 5000` and `URLBERT v4 ONNX Model loaded and warmed up successfully.`*

2. **Start the Frontend**:
   ```bash
   cd frontend
   npm run dev
   ```
   *Terminal will display the local Vite URL (e.g. `http://localhost:5173`).*

3. **In-Process ML Execution**:
   * No separate Python server or daemon is required to run the ML model.
   * When requests are submitted to `/api/v1/phish/analyze`, `backend/services/aiService.js` performs tokenization and ONNX inference directly inside the Node.js event loop.

---

## 16. Testing & Verification Instructions

The codebase includes verification and audit scripts:

### 1. Comprehensive Backend Audit Suite
Evaluates detection pipeline benchmarks, threat intelligence consensus math, and all 5 preview reachability/SSRF states:
```bash
cd backend
node scripts/auditSuite.js
```

### 2. Website Preview & SSRF Verification
Validates that private addresses (such as `127.0.0.1` and `169.254.169.254`) are blocked and verifies headless screenshot capture on public websites:
```bash
cd backend
node scripts/verifyPreview.js
```

### 3. Secret Leak Scanner
Scans the project directory for accidentally hardcoded credentials or API tokens before committing:
```bash
cd backend
node scripts/scanSecrets.js
```

### 4. SMTP Email Delivery Diagnostic
Validates SMTP configuration and dispatches a test verification code email:
```bash
cd backend
node scripts/testEmailDelivery.js your_email@example.com
```

### 5. Multi-URL Benchmark Test Runner
Runs the detection engine against benchmark URLs across legitimate, typosquatting, suspicious structure, and obfuscation categories:
```bash
python ml/run_test_suite.py
```

### 6. Authentication Flow Simulation
Tests guest scan limit decrementing, 3-scan threshold, and registration unlock:
```bash
node ml/test_auth_flow.js
```

---

## 17. API Endpoints Reference

### Phishing Detection & Preview Endpoints

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `POST` | `/api/v1/phish/analyze` | Analyzes target URL across heuristics, threat intel, and URLBERT | No |
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
  "timestamp": "2026-09-06T01:12:10.000Z",
  "score": 65,
  "classification": "HIGH RISK",
  "reasons": [
    "Possible Google impersonation detected. Domain differs from legitimate brand domain (google.com).",
    "Suspicious keyword detected: accounts, verify, login",
    "AI detected strong phishing patterns (100% pattern match)."
  ],
  "securityEvidence": [
    "Possible Google impersonation detected. Domain differs from legitimate brand domain (google.com).",
    "Suspicious keyword detected: accounts, verify, login"
  ],
  "scoreBreakdown": [
    { "name": "Domain Impersonation Risk", "points": 25, "category": "heuristic" },
    { "name": "Suspicious Keywords Risk", "points": 10, "category": "heuristic" },
    { "name": "AI Model Phishing Contributor", "points": 30, "category": "ai", "detail": "Probability: 100% (PHISHING)" }
  ],
  "details": {
    "heuristics": {
      "lookalikeDomain": true,
      "suspiciousKeywords": true
    },
    "threatIntel": {
      "virusTotal": { "status": "NOT CONFIGURED", "configured": false, "detections": 0 },
      "openPhish": { "status": "CONNECTED", "threatFound": false }
    },
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
      "aiComponent": 30,
      "weightAllocation": "Multi-Layer Hybrid Scoring (Heuristics 0–40, Threat Intel 0–60, AI 0–30)"
    }
  }
}
```

---

### Authentication & History Endpoints

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `POST` | `/api/v1/auth/register` | Registers new user account and dispatches 6-digit email OTP | No |
| `POST` | `/api/v1/auth/login` | Authenticates user (requires verified email) | No |
| `POST` | `/api/v1/auth/verify-email` | Validates 6-digit email OTP to verify account | No |
| `POST` | `/api/v1/auth/resend-verification` | Resends OTP verification email (30-second cooldown) | No |
| `POST` | `/api/v1/auth/forgot-password` | Initiates password reset via email token | No |
| `POST` | `/api/v1/auth/reset-password` | Resets password using single-use reset token | No |
| `GET` | `/api/v1/auth/me` | Retrieves profile of currently authenticated user | Yes (Bearer Token) |
| `POST` | `/api/v1/auth/logout` | Clears user session | No |
| `GET` | `/api/v1/history` | Fetches scan history for authenticated user or guest | Optional |
| `POST` | `/api/v1/history` | Persists a new scan record | Optional |
| `DELETE` | `/api/v1/history/:id` | Deletes a single scan record by ID | Optional |
| `DELETE` | `/api/v1/history` | Clears all scan history for the user | Optional |

---

## 18. Authentication & Account Management

* **Guest Mode**: Allows up to 3 scans without registration. Scans are saved in browser `localStorage`.
* **Registered Mode**: Unlocks unlimited scans. Scan records are synchronized to `backend/data/history.json`.
* **Email Verification**: Enforces a 6-digit cryptographic OTP expiring in 10 minutes with a 5-attempt limit to prevent brute force.
* **Password Policy & Hashing**:
  - Requires a minimum of 12 characters.
  - Salted with a 16-byte random salt and hashed using PBKDF2 with SHA-512 (100,000 iterations).
  - Validated against common password blacklists.
* **Session Security**: Authenticated requests use cryptographically signed session tokens sent via standard `Authorization: Bearer <token>` headers.

---

## 19. Important System Limitations

To maintain academic and scientific integrity, the system's operational boundaries should be understood:

1. **URL-Lexical & Preview Scope**: PhishSense evaluates URLs statically and renders a visual screenshot of landing pages. It does not execute dynamic multistage JavaScript malware payloads, execute file downloads, or bypass CAPTCHAs.
2. **Cloaking & Geofencing**: Attackers employing IP cloaking (serving benign pages to security bots and phishing content only to targeted victim IPs) may present clean content to the headless preview scanner until community feeds flag the domain.
3. **Third-Party API Rate Limits**: VirusTotal lookup depends on external API availability and key limits (e.g., standard free-tier limits). If API keys are absent or rate limits are reached, the system gracefully falls back to heuristics and local AI without crashing.
4. **Novel Unseen Structures**: While URLBERT generalizes effectively across subword tokens, novel evasion techniques that use aged domains with legitimate-looking lexical structures and no credential keywords may require threat intelligence feeds for definitive flagging.
5. **Flat-File Storage Scope**: User accounts and scan records are stored in local JSON files (`data/users.json` and `data/history.json`), which is suitable for academic demonstration and single-server evaluation, but not intended for distributed multi-node production clusters.

---

## Academic Attribution & Submission

* **Institution**: Kwame Nkrumah University of Science and Technology (KNUST)
* **Department**: Department of Computer Science
* **Student Name**: Adiza Malik (Index Number: 9026923)
* **Supervisor**: Dr. Kate Takyi
* **Academic Year**: 2025/2026
