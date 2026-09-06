#!/usr/bin/env python3
"""
PhishSense Production Model Inference Service
Loads trained Random Forest model, extracts features for incoming URL,
runs inference, and outputs structured explainable prediction JSON.
"""

import sys
import json
import os
from feature_extractor import extract_features, generate_explainable_indicators
from train_model import RandomForestClassifier

def predict_url(url_str):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_json_path = os.path.join(base_dir, 'model', 'phish_model.json')
    meta_json_path = os.path.join(base_dir, 'model', 'feature_names.json')

    if not os.path.exists(model_json_path) or not os.path.exists(meta_json_path):
        return {
            "available": False,
            "error": "AI Model files not found. Please train model first.",
            "prediction": "UNAVAILABLE",
            "probability": 0.0,
            "confidence": 0,
            "importantFeatures": []
        }

    try:
        with open(model_json_path, 'r', encoding='utf-8') as f:
            model_data = json.load(f)

        with open(meta_json_path, 'r', encoding='utf-8') as f:
            meta_data = json.load(f)

        feature_names = meta_data.get("feature_names", [])
        clf = RandomForestClassifier.from_dict(model_data)

        raw_features = extract_features(url_str)
        sample_vec = [raw_features[name] for name in feature_names]

        prob = clf.predict_proba(sample_vec)
        prob = max(0.0, min(1.0, prob))

        if prob >= 0.70:
            prediction = "PHISHING"
        elif prob >= 0.40:
            prediction = "SUSPICIOUS"
        else:
            prediction = "BENIGN"

        confidence = round(prob * 100)
        important_indicators = generate_explainable_indicators(raw_features)

        return {
            "available": True,
            "prediction": prediction,
            "probability": round(prob, 4),
            "confidence": confidence,
            "importantFeatures": important_indicators,
            "model_type": meta_data.get("model_type", "Random Forest Classifier"),
            "model_version": "1.0.0",
            "features": raw_features
        }

    except Exception as e:
        return {
            "available": False,
            "error": f"Inference execution failed: {str(e)}",
            "prediction": "UNAVAILABLE",
            "probability": 0.0,
            "confidence": 0,
            "importantFeatures": []
        }

def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "available": False,
            "error": "No URL provided as argument."
        }))
        sys.exit(1)

    target_url = sys.argv[1]
    res = predict_url(target_url)
    print(json.dumps(res, indent=2))

if __name__ == '__main__':
    main()
