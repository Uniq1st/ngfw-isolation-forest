"""
Baseline Models for Comparison.
Tests Random Forest, One-Class SVM, Local Outlier Factor against Isolation Forest.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix, roc_auc_score
import warnings
warnings.filterwarnings('ignore')

class BaselineModels:
    """Train and evaluate baseline models."""
    
    @staticmethod
    def random_forest(X_train, y_train, X_test, y_test):
        """
        Random Forest: Supervised baseline.
        Trains on normal data, treats anomalies as separate class.
        """
        print("  [Random Forest] Training...", end=" ", flush=True)
        
        # Use normal traffic for training
        normal_mask = y_train == 0
        X_normal = X_train[normal_mask]
        
        # Train on normal + sample of anomalies for supervised learning
        X_train_mixed = pd.concat([X_normal, X_train[~normal_mask]])
        y_train_mixed = pd.concat([
            pd.Series([0] * len(X_normal)),
            pd.Series([1] * len(X_train[~normal_mask]))
        ])
        
        rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        rf.fit(X_train_mixed, y_train_mixed)
        predictions = rf.predict(X_test)
        
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, predictions, average='binary', zero_division=0
        )
        
        tn, fp, fn, tp = confusion_matrix(y_test, predictions).ravel()
        fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0
        
        print("✓")
        return {
            'model': 'Random Forest',
            'precision': round(float(precision), 4),
            'recall': round(float(recall), 4),
            'f1_score': round(float(f1), 4),
            'fpr_percent': round(float(fpr), 2),
            'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn)
        }
    
    @staticmethod
    def one_class_svm(X_train, y_train, X_test, y_test):
        """
        One-Class SVM: Unsupervised anomaly detector.
        Trains on normal data only.
        """
        print("  [One-Class SVM] Training...", end=" ", flush=True)
        
        # Train on normal traffic only
        normal_mask = y_train == 0
        X_normal = X_train[normal_mask]
        
        ocs = OneClassSVM(nu=0.05, kernel='rbf', random_state=42)
        ocs.fit(X_normal)
        
        # Predict: -1 = anomaly, 1 = normal
        predictions = (ocs.predict(X_test) == -1).astype(int)
        
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, predictions, average='binary', zero_division=0
        )
        
        tn, fp, fn, tp = confusion_matrix(y_test, predictions).ravel()
        fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0
        
        print("✓")
        return {
            'model': 'One-Class SVM',
            'precision': round(float(precision), 4),
            'recall': round(float(recall), 4),
            'f1_score': round(float(f1), 4),
            'fpr_percent': round(float(fpr), 2),
            'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn)
        }
    
    @staticmethod
    def local_outlier_factor(X_train, y_train, X_test, y_test):
        """
        Local Outlier Factor: Density-based anomaly detector.
        Trains on normal data with novelty detection enabled.
        """
        print("  [Local Outlier Factor] Training...", end=" ", flush=True)
        
        # Train on normal traffic only
        normal_mask = y_train == 0
        X_normal = X_train[normal_mask]
        
        lof = LocalOutlierFactor(n_neighbors=20, novelty=True, n_jobs=-1)
        lof.fit(X_normal)
        
        # Predict: -1 = anomaly, 1 = normal
        predictions = (lof.predict(X_test) == -1).astype(int)
        
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, predictions, average='binary', zero_division=0
        )
        
        tn, fp, fn, tp = confusion_matrix(y_test, predictions).ravel()
        fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0
        
        print("✓")
        return {
            'model': 'Local Outlier Factor',
            'precision': round(float(precision), 4),
            'recall': round(float(recall), 4),
            'f1_score': round(float(f1), 4),
            'fpr_percent': round(float(fpr), 2),
            'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn)
        }
    
    @staticmethod
    def isolation_forest(X_train, y_train, X_test, y_test):
        """
        Isolation Forest: Unsupervised anomaly detector.
        Trains on normal data only.
        """
        print("  [Isolation Forest] Training...", end=" ", flush=True)
        
        # Train on normal traffic only
        normal_mask = y_train == 0
        X_normal = X_train[normal_mask]
        
        # Use validation split for threshold calibration
        n = len(X_normal)
        n_val = int(n * 0.15)
        val_indices = np.random.choice(n, n_val, replace=False)
        train_indices = np.setdiff1d(np.arange(n), val_indices)
        
        X_train_if = X_normal.iloc[train_indices]
        X_val = X_normal.iloc[val_indices]
        
        ifr = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
        ifr.fit(X_train_if)
        
        # Calibrate threshold on validation set
        val_scores = ifr.decision_function(X_val)
        threshold = np.percentile(val_scores, 5)
        
        # Predict on test set
        test_scores = ifr.decision_function(X_test)
        predictions = (test_scores < threshold).astype(int)
        
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, predictions, average='binary', zero_division=0
        )
        
        tn, fp, fn, tp = confusion_matrix(y_test, predictions).ravel()
        fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0
        
        print("✓")
        return {
            'model': 'Isolation Forest',
            'precision': round(float(precision), 4),
            'recall': round(float(recall), 4),
            'f1_score': round(float(f1), 4),
            'fpr_percent': round(float(fpr), 2),
            'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn)
        }


if __name__ == "__main__":
    import json
    from pathlib import Path
    from data_loader import NSLKDDLoader
    from feature_extraction import extract_features
    
    print("\n" + "="*70)
    print("BASELINE MODEL COMPARISON")
    print("="*70 + "\n")
    
    # Check for data
    nsl_kdd_train = Path('data/NSL-KDD/KDDTrain+.txt')
    nsl_kdd_test = Path('data/NSL-KDD/KDDTest+.txt')
    
    if not nsl_kdd_train.exists():
        print("❌ NSL-KDD dataset not found!")
        print("   Download from: http://www.unb.ca/cic/datasets/nsl-kdd.html")
        exit(1)
    
    # Load data
    print("[Baseline] Loading NSL-KDD dataset...")
    train_flows, train_labels = NSLKDDLoader.load_nsl_kdd(str(nsl_kdd_train), sample_size=5000)
    test_flows, test_labels = NSLKDDLoader.load_nsl_kdd(str(nsl_kdd_test), sample_size=2000)
    
    # Extract features
    print("[Baseline] Extracting features...")
    X_train = extract_features(train_flows)
    X_test = extract_features(test_flows)
    y_train = pd.Series(train_labels)
    y_test = pd.Series(test_labels)
    
    print(f"[Baseline] Train: {len(X_train)} samples | Test: {len(X_test)} samples\n")
    
    # Train all models
    print("[Baseline] Training models...")
    results = [
        BaselineModels.random_forest(X_train, y_train, X_test, y_test),
        BaselineModels.one_class_svm(X_train, y_train, X_test, y_test),
        BaselineModels.local_outlier_factor(X_train, y_train, X_test, y_test),
        BaselineModels.isolation_forest(X_train, y_train, X_test, y_test),
    ]
    
    # Print comparison table
    print("\n" + "="*70)
    print("COMPARISON RESULTS")
    print("="*70)
    print(f"{'Model':<20} {'Precision':<12} {'Recall':<12} {'F1-Score':<12} {'FPR%':<10}")
    print("-"*70)
    
    for r in results:
        print(f"{r['model']:<20} {r['precision']:<12.4f} {r['recall']:<12.4f} {r['f1_score']:<12.4f} {r['fpr_percent']:<10.2f}")
    
    print("="*70)
    
    # Save results
    with open("results/baseline_comparison.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\n✅ Results saved to results/baseline_comparison.json")
