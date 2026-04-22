"""
Training script for real-world datasets (NSL-KDD, CICIDS2018).
Evaluates Isolation Forest model on real attack data.
"""

import pandas as pd
import json
import sys
from pathlib import Path

from feature_extraction import extract_features
from anomaly_detector import NGFWAnomalyDetector
from data_loader import NSLKDDLoader, CICIDS2018Loader

from sklearn.metrics import precision_recall_fscore_support, confusion_matrix, roc_auc_score, roc_curve
import numpy as np

def evaluate_model(detector, test_features, test_labels):
    """
    Evaluate model and return comprehensive metrics.
    
    Args:
        detector: Trained NGFWAnomalyDetector
        test_features: Feature DataFrame
        test_labels: True labels (0=normal, 1=anomaly)
    
    Returns:
        Dictionary of evaluation metrics
    """
    predictions = detector.predict(test_features)
    scores = detector.score(test_features)
    
    # Classification metrics
    precision, recall, f1, _ = precision_recall_fscore_support(
        test_labels, predictions, average='binary', zero_division=0
    )
    
    # Confusion matrix
    tn, fp, fn, tp = confusion_matrix(test_labels, predictions).ravel()
    
    # False positive rate
    fpr_val = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0
    
    # False negative rate
    fnr = fn / (fn + tp) * 100 if (fn + tp) > 0 else 0
    
    # ROC-AUC
    try:
        roc_auc = roc_auc_score(test_labels, -scores)  # Lower scores = more anomalous
    except:
        roc_auc = 0.0
    
    results = {
        'precision': round(float(precision), 4),
        'recall': round(float(recall), 4),
        'f1_score': round(float(f1), 4),
        'fpr_percent': round(float(fpr_val), 2),
        'fnr_percent': round(float(fnr), 2),
        'roc_auc': round(float(roc_auc), 4),
        'true_positives': int(tp),
        'false_positives': int(fp),
        'true_negatives': int(tn),
        'false_negatives': int(fn),
        'total_anomalies': int(tp + fn),
        'total_normal': int(tn + fp),
    }
    
    return results


def train_and_evaluate_nsl_kdd():
    """Train and evaluate on NSL-KDD dataset."""
    
    print("[NSL-KDD] Checking for dataset...")
    nsl_kdd_train = Path('data/NSL-KDD/KDDTrain+.txt')
    nsl_kdd_test = Path('data/NSL-KDD/KDDTest+.txt')
    
    if not nsl_kdd_train.exists():
        print(f"❌ NSL-KDD training file not found at {nsl_kdd_train}")
        print("   Download from: http://www.unb.ca/cic/datasets/nsl-kdd.html")
        return None
    
    print("[NSL-KDD] Loading training data...")
    train_flows, train_labels = NSLKDDLoader.load_nsl_kdd(str(nsl_kdd_train))
    
    print(f"[NSL-KDD] Loading test data...")
    test_flows, test_labels = NSLKDDLoader.load_nsl_kdd(str(nsl_kdd_test))
    
    print(f"[NSL-KDD] Loaded {len(train_flows)} training flows, {len(test_flows)} test flows")
    print(f"[NSL-KDD] Train: {sum(1 for l in train_labels if l==0)} normal, {sum(1 for l in train_labels if l==1)} attacks")
    print(f"[NSL-KDD] Test:  {sum(1 for l in test_labels if l==0)} normal, {sum(1 for l in test_labels if l==1)} attacks")
    
    # Extract features
    print("[NSL-KDD] Extracting features (this may take a minute)...")
    train_features = extract_features(train_flows)
    test_features = extract_features(test_flows)
    
    # Train detector on normal traffic only
    print("[NSL-KDD] Training on normal traffic only...")
    normal_mask = pd.Series(train_labels) == 0
    baseline_features = train_features[normal_mask]
    
    detector = NGFWAnomalyDetector(n_estimators=200, contamination=0.05, random_state=42)
    detector.train(baseline_features, validation_split=0.15)
    
    # Evaluate on test set
    print("[NSL-KDD] Evaluating on test set...")
    results = evaluate_model(detector, test_features, test_labels)
    
    # Print results
    print("\n" + "="*60)
    print("EVALUATION RESULTS - NSL-KDD DATASET")
    print("="*60)
    print(f"Precision:           {results['precision']:.4f}")
    print(f"Recall:              {results['recall']:.4f}")
    print(f"F1-Score:            {results['f1_score']:.4f}")
    print(f"ROC-AUC:             {results['roc_auc']:.4f}")
    print(f"False Positive Rate: {results['fpr_percent']:.2f}%")
    print(f"False Negative Rate: {results['fnr_percent']:.2f}%")
    print("\nConfusion Matrix:")
    print(f"  TP: {results['true_positives']:5d}  FN: {results['false_negatives']:5d}")
    print(f"  FP: {results['false_positives']:5d}  TN: {results['true_negatives']:5d}")
    print("="*60)
    
    # Save model
    detector.save("models/ngfw_detector_nslkdd.pkl")
    print("\n✅ Model saved to models/ngfw_detector_nslkdd.pkl")
    
    # Save results as JSON
    results['dataset'] = 'NSL-KDD'
    results['model'] = 'Isolation Forest'
    with open("results/evaluation_nslkdd.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("✅ Results saved to results/evaluation_nslkdd.json")
    
    return results


if __name__ == "__main__":
    print("\n" + "="*60)
    print("NGFW ANOMALY DETECTION - REAL DATA EVALUATION")
    print("="*60 + "\n")
    
    results = train_and_evaluate_nsl_kdd()
    
    if results:
        print("\n✨ Evaluation complete!")
    else:
        print("\n⚠️  Download NSL-KDD dataset first:")
        print("    http://www.unb.ca/cic/datasets/nsl-kdd.html")
        print("    Extract to: data/NSL-KDD/")
