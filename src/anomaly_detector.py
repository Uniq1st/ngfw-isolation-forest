"""
Isolation Forest Anomaly Detector
Trains on baseline traffic and scores new flows.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os


class NGFWAnomalyDetector:
    def __init__(self, n_estimators: int = 200, contamination: float = 0.05,
                 random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state
        )
        self.threshold = None
        self.is_trained = False

    def train(self, baseline_features: pd.DataFrame, validation_split: float = 0.15):
        """Train on baseline (normal) traffic and calibrate threshold."""
        n = len(baseline_features)
        n_val = int(n * validation_split)
        train_data = baseline_features.iloc[n_val:]
        val_data   = baseline_features.iloc[:n_val]

        self.model.fit(train_data)
        self.is_trained = True

        # Calibrate threshold on validation set
        val_scores = self.model.decision_function(val_data)
        # Set threshold at 5th percentile of normal scores
        self.threshold = float(np.percentile(val_scores, 5))
        print(f"[Detector] Trained on {len(train_data)} flows. "
              f"Threshold calibrated at {self.threshold:.4f}")
        return self

    def score(self, features: pd.DataFrame) -> np.ndarray:
        """Return anomaly scores for input features."""
        if not self.is_trained:
            raise RuntimeError("Model must be trained before scoring.")
        return self.model.decision_function(features)

    def predict(self, features: pd.DataFrame) -> np.ndarray:
        """Return binary labels: 1 = anomalous, 0 = normal."""
        scores = self.score(features)
        return (scores < self.threshold).astype(int)

    def save(self, path: str = "models/ngfw_detector.pkl"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({"model": self.model, "threshold": self.threshold}, path)
        print(f"[Detector] Model saved to {path}")

    def load(self, path: str = "models/ngfw_detector.pkl"):
        data = joblib.load(path)
        self.model = data["model"]
        self.threshold = data["threshold"]
        self.is_trained = True
        print(f"[Detector] Model loaded from {path}")
        return self