#!/usr/bin/env python3
"""
PhishSense ML Model Training Pipeline
Trains a Random Forest Classifier on URL lexical, security, and brand features.
Calculates Accuracy, Precision, Recall, F1-Score, Confusion Matrix, and ROC-AUC.
Saves model weights to ml/model/phish_model.json and feature_names.json.
"""

import csv
import json
import math
import os
import random
from feature_extractor import extract_features, get_feature_names

class DecisionTreeNode:
    def __init__(self, feature_idx=None, threshold=None, left=None, right=None, value=None):
        self.feature_idx = feature_idx
        self.threshold = threshold
        self.left = left
        self.right = right
        self.value = value # Probability of class 1

    def is_leaf(self):
        return self.value is not None

    def to_dict(self):
        if self.is_leaf():
            return {"value": self.value}
        return {
            "feature_idx": self.feature_idx,
            "threshold": self.threshold,
            "left": self.left.to_dict(),
            "right": self.right.to_dict()
        }

    @staticmethod
    def from_dict(d):
        if "value" in d:
            return DecisionTreeNode(value=d["value"])
        return DecisionTreeNode(
            feature_idx=d["feature_idx"],
            threshold=d["threshold"],
            left=DecisionTreeNode.from_dict(d["left"]),
            right=DecisionTreeNode.from_dict(d["right"])
        )

def gini_impurity(y):
    if not y:
        return 0.0
    p1 = sum(y) / len(y)
    p0 = 1.0 - p1
    return 1.0 - (p0**2 + p1**2)

def build_tree(X, y, depth=0, max_depth=10, min_samples_split=4, n_features=None):
    n_samples = len(y)
    if n_samples == 0:
        return DecisionTreeNode(value=0.0)

    p1 = sum(y) / n_samples
    if depth >= max_depth or n_samples < min_samples_split or p1 == 0.0 or p1 == 1.0:
        return DecisionTreeNode(value=p1)

    tot_features = len(X[0])
    if n_features is None:
        n_features = int(math.sqrt(tot_features)) + 1

    feature_indices = random.sample(range(tot_features), min(n_features, tot_features))

    best_gini = float('inf')
    best_feat = None
    best_thresh = None
    best_left_X, best_left_y = [], []
    best_right_X, best_right_y = [], []

    for feat_idx in feature_indices:
        vals = [row[feat_idx] for row in X]
        unique_vals = sorted(list(set(vals)))
        if len(unique_vals) <= 1:
            continue

        # Check candidate split thresholds
        thresholds = [(unique_vals[i] + unique_vals[i+1])/2.0 for i in range(len(unique_vals)-1)]
        if len(thresholds) > 10:
            step = len(thresholds) // 10
            thresholds = thresholds[::step]

        for thresh in thresholds:
            left_X, left_y = [], []
            right_X, right_y = [], []

            for row_x, label in zip(X, y):
                if row_x[feat_idx] <= thresh:
                    left_X.append(row_x)
                    left_y.append(label)
                else:
                    right_X.append(row_x)
                    right_y.append(label)

            if not left_y or not right_y:
                continue

            g_left = gini_impurity(left_y)
            g_right = gini_impurity(right_y)
            weighted_gini = (len(left_y)/n_samples)*g_left + (len(right_y)/n_samples)*g_right

            if weighted_gini < best_gini:
                best_gini = weighted_gini
                best_feat = feat_idx
                best_thresh = thresh
                best_left_X, best_left_y = left_X, left_y
                best_right_X, best_right_y = right_X, right_y

    if best_feat is None:
        return DecisionTreeNode(value=p1)

    left_child = build_tree(best_left_X, best_left_y, depth+1, max_depth, min_samples_split, n_features)
    right_child = build_tree(best_right_X, best_right_y, depth+1, max_depth, min_samples_split, n_features)

    return DecisionTreeNode(feature_idx=best_feat, threshold=best_thresh, left=left_child, right=right_child)

def predict_tree(node, sample):
    if node.is_leaf():
        return node.value
    if sample[node.feature_idx] <= node.threshold:
        return predict_tree(node.left, sample)
    else:
        return predict_tree(node.right, sample)

class RandomForestClassifier:
    def __init__(self, n_estimators=25, max_depth=8, min_samples_split=4):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.trees = []

    def fit(self, X, y):
        self.trees = []
        n_samples = len(X)
        random.seed(42)

        for _ in range(self.n_estimators):
            # Bootstrap sample
            indices = [random.randint(0, n_samples - 1) for _ in range(n_samples)]
            X_boot = [X[i] for i in indices]
            y_boot = [y[i] for i in indices]
            tree = build_tree(X_boot, y_boot, max_depth=self.max_depth, min_samples_split=self.min_samples_split)
            self.trees.append(tree)

    def predict_proba(self, sample):
        if not self.trees:
            return 0.5
        preds = [predict_tree(t, sample) for t in self.trees]
        return sum(preds) / len(preds)

    def predict(self, sample, threshold=0.5):
        return 1 if self.predict_proba(sample) >= threshold else 0

    def to_dict(self):
        return {
            "n_estimators": self.n_estimators,
            "max_depth": self.max_depth,
            "min_samples_split": self.min_samples_split,
            "trees": [t.to_dict() for t in self.trees]
        }

    @staticmethod
    def from_dict(d):
        rf = RandomForestClassifier(
            n_estimators=d["n_estimators"],
            max_depth=d["max_depth"],
            min_samples_split=d["min_samples_split"]
        )
        rf.trees = [DecisionTreeNode.from_dict(t) for t in d["trees"]]
        return rf

def calculate_metrics(y_true, y_pred, y_probs):
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    acc = (tp + tn) / max(1, len(y_true))
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    f1 = 2 * (prec * rec) / max(1e-6, (prec + rec))

    # ROC-AUC estimation via trapezoidal integration of sorted probabilities
    sorted_pairs = sorted(zip(y_probs, y_true), key=lambda x: x[0], reverse=True)
    n_pos = sum(y_true)
    n_neg = len(y_true) - n_pos

    auc = 0.5
    if n_pos > 0 and n_neg > 0:
        fp_count = 0
        tp_count = 0
        auc_sum = 0
        prev_fp = 0
        prev_tp = 0
        for prob, label in sorted_pairs:
            if label == 1:
                tp_count += 1
            else:
                fp_count += 1
                auc_sum += (tp_count + prev_tp) / 2.0
                prev_tp = tp_count
        auc = round(auc_sum / (n_pos * n_neg), 4)

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": auc,
        "confusion_matrix": {
            "tp": tp, "tn": tn, "fp": fp, "fn": fn
        }
    }

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(base_dir, 'dataset', 'phishing_urls.csv')
    model_dir = os.path.join(base_dir, 'model')
    os.makedirs(model_dir, exist_ok=True)

    print("=== PhishSense ML Model Training ===")
    print(f"Loading dataset from: {csv_path}")

    urls = []
    labels = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row['url'])
            labels.append(int(row['label']))

    print(f"Total samples loaded: {len(urls)} ({labels.count(0)} benign, {labels.count(1)} phishing)")

    feature_names = get_feature_names()
    print(f"Extracting {len(feature_names)} features for all URLs...")

    X = []
    for url in urls:
        f_dict = extract_features(url)
        X.append([f_dict[name] for name in feature_names])

    # Stratified 80/20 train/test split with seed 42
    random.seed(42)
    benign_indices = [i for i, l in enumerate(labels) if l == 0]
    phish_indices = [i for i, l in enumerate(labels) if l == 1]

    random.shuffle(benign_indices)
    random.shuffle(phish_indices)

    n_train_b = int(0.8 * len(benign_indices))
    n_train_p = int(0.8 * len(phish_indices))

    train_indices = benign_indices[:n_train_b] + phish_indices[:n_train_p]
    test_indices = benign_indices[n_train_b:] + phish_indices[n_train_p:]

    random.shuffle(train_indices)
    random.shuffle(test_indices)

    X_train = [X[i] for i in train_indices]
    y_train = [labels[i] for i in train_indices]
    X_test = [X[i] for i in test_indices]
    y_test = [labels[i] for i in test_indices]

    print(f"Training samples: {len(X_train)} | Testing samples: {len(X_test)}")

    print("Training Random Forest Classifier (25 estimators)...")
    clf = RandomForestClassifier(n_estimators=25, max_depth=8)
    clf.fit(X_train, y_train)

    print("Evaluating model on test dataset...")
    y_probs = [clf.predict_proba(sample) for sample in X_test]
    y_preds = [1 if p >= 0.5 else 0 for p in y_probs]

    metrics = calculate_metrics(y_test, y_preds, y_probs)

    print("\n--- MODEL EVALUATION REPORT ---")
    print(f"Model: Random Forest URL Classifier")
    print(f"Accuracy:  {metrics['accuracy']*100:.2f}%")
    print(f"Precision: {metrics['precision']*100:.2f}%")
    print(f"Recall:    {metrics['recall']*100:.2f}%")
    print(f"F1-Score:  {metrics['f1_score']*100:.2f}%")
    print(f"ROC-AUC:   {metrics['roc_auc']:.4f}")
    print("\nConfusion Matrix:")
    print(f"  True Negatives (TN):  {metrics['confusion_matrix']['tn']}")
    print(f"  False Positives (FP): {metrics['confusion_matrix']['fp']}")
    print(f"  False Negatives (FN): {metrics['confusion_matrix']['fn']}")
    print(f"  True Positives (TP):  {metrics['confusion_matrix']['tp']}")

    # Save model and metadata
    model_json_path = os.path.join(model_dir, 'phish_model.json')
    feature_json_path = os.path.join(model_dir, 'feature_names.json')

    with open(model_json_path, 'w', encoding='utf-8') as f:
        json.dump(clf.to_dict(), f)

    with open(feature_json_path, 'w', encoding='utf-8') as f:
        json.dump({
            "feature_names": feature_names,
            "metrics": metrics,
            "model_type": "Random Forest Classifier",
            "n_estimators": clf.n_estimators,
            "max_depth": clf.max_depth,
            "train_samples": len(X_train),
            "test_samples": len(X_test)
        }, f, indent=2)

    print(f"\nTrained model successfully saved to: {model_json_path}")
    print(f"Feature metadata saved to: {feature_json_path}")

if __name__ == '__main__':
    main()
