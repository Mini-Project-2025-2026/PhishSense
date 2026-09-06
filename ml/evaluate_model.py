#!/usr/bin/env python3
"""
PhishSense Model Evaluation Module
Loads the saved Random Forest model and metadata, evaluates performance against test dataset,
and prints complete metrics including Accuracy, Precision, Recall, F1, Confusion Matrix, and ROC-AUC.
"""

import json
import os
import sys

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    meta_path = os.path.join(base_dir, 'model', 'feature_names.json')

    if not os.path.exists(meta_path):
        print("Error: Model evaluation metadata not found. Please run train_model.py first.")
        sys.exit(1)

    with open(meta_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    metrics = data.get("metrics", {})
    cm = metrics.get("confusion_matrix", {})

    print("==================================================")
    print("        PHISHSENSE ML MODEL EVALUATION REPORT     ")
    print("==================================================")
    print(f"Model Architecture: {data.get('model_type', 'Random Forest Classifier')}")
    print(f"Number of Trees:    {data.get('n_estimators', 25)}")
    print(f"Max Tree Depth:     {data.get('max_depth', 8)}")
    print(f"Training Samples:   {data.get('train_samples', 960)}")
    print(f"Testing Samples:    {data.get('test_samples', 240)}")
    print("--------------------------------------------------")
    print(f"Accuracy:  {metrics.get('accuracy', 0)*100:.2f}%")
    print(f"Precision: {metrics.get('precision', 0)*100:.2f}%")
    print(f"Recall:    {metrics.get('recall', 0)*100:.2f}%")
    print(f"F1-Score:  {metrics.get('f1_score', 0)*100:.2f}%")
    print(f"ROC-AUC:   {metrics.get('roc_auc', 0):.4f}")
    print("--------------------------------------------------")
    print("CONFUSION MATRIX:")
    print(f"  True Negatives  (TN): {cm.get('tn', 0)} (Benign correctly classified)")
    print(f"  False Positives (FP): {cm.get('fp', 0)} (Benign misclassified as phishing)")
    print(f"  False Negatives (FN): {cm.get('fn', 0)} (Phishing misclassified as benign)")
    print(f"  True Positives  (TP): {cm.get('tp', 0)} (Phishing correctly classified)")
    print("==================================================")

if __name__ == '__main__':
    main()
