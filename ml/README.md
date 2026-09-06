# PhishSense Intelligent AI/ML Phishing Detection Module

This directory contains the machine learning subsystem of PhishSense, featuring both the **URLBERT v4 Transformer ONNX model** (used for in-process real-time inference by the Node.js backend) and a reproducible **Random Forest URL classifier baseline** with 29 handcrafted features.

## Directory Structure

```text
ml/
├── dataset/
│   ├── DATASET_INFO.md         # Detailed dataset source & preprocessing metadata
│   ├── build_dataset.py        # Reproducible dataset generator script
│   └── phishing_urls.csv       # 1,200 labeled URL benchmark dataset (600 benign, 600 phishing)
├── model/
│   ├── feature_names.json      # Saved feature names list & evaluation metrics
│   └── phish_model.json        # Serialized Random Forest classifier trees & parameters
├── urlbert/
│   ├── config.json             # URLBERT v4 Transformer architecture configuration
│   ├── model.onnx              # Serialized ONNX model weights (8 layers, 8 heads, 192 hidden)
│   ├── model.onnx.data         # Serialized ONNX tensor weights
│   ├── tokenizer.json          # 400-token WordPiece vocabulary
│   └── tokenizer_config.json   # Tokenizer configuration
├── evaluate_model.py           # Independent model performance evaluation script
├── feature_extractor.py        # 29 lexical, security, and brand impersonation feature extractor
├── predict.py                  # CLI Python prediction interface
├── README.md                   # Machine learning subsystem documentation
├── run_test_suite.py           # Test suite runner
├── test_auth_flow.js           # Auth layer verification script
└── train_model.py              # Reproducible 80/20 train/test training pipeline
```

## Features Extracted (29 Total)

1. **Lexical & Structural Features (13)**: URL length, hostname length, path length, dot count, hyphen count, underscore count, slash count, special characters count, digit count, digit ratio, query parameters count, fragment count, subdomain count.
2. **Security & Protocol Features (14)**: HTTPS usage, HTTP usage, IP address hostname indicator, suspicious TLD match, URL shortener match, excessive subdomains indicator, individual security keywords (login, secure, verify, account, update, password, payment), total suspicious keywords count.
3. **Domain Impersonation Features (2)**: Protected brand typosquatting / Levenshtein similarity detection, IDN homoglyph / non-ASCII character spoofing indicator.

## Training & Evaluation Commands

```bash
# Generate/Refresh Benchmark Dataset
python ml/dataset/build_dataset.py

# Train Random Forest Classifier
python ml/train_model.py

# Evaluate Model & Output Confusion Matrix
python ml/evaluate_model.py

# Run CLI Prediction on Target URL
python ml/predict.py "https://accounts-google-verify.com/login"
```
