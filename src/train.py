"""
Training Script for NGFW Anomaly Detector
Generates mock baseline data and trains the Isolation Forest model.
"""

import pandas as pd
import numpy as np
from feature_extraction import extract_features
from anomaly_detector import NGFWAnomalyDetector


def generate_mock_baseline_flows(n_flows: int = 1000) -> list:
    """Generate synthetic normal network flows for training."""
    flows = []
    np.random.seed(42)
    for _ in range(n_flows):
        pkt_sizes = np.random.normal(500, 100, np.random.randint(5, 20)).tolist()
        iats = np.random.exponential(0.01, len(pkt_sizes)).tolist()
        flow = {
            "pkt_sizes": pkt_sizes,
            "inter_arrival_times": iats,
            "duration": np.random.uniform(0.1, 10.0),
            "bytes_forward": sum(pkt_sizes),
            "bytes_reverse": np.random.uniform(100, 1000),
            "packet_count": len(pkt_sizes),
            "protocol": np.random.choice([6, 17]),  # TCP or UDP
        }
        flows.append(flow)
    return flows


if __name__ == "__main__":
    print("[Training] Generating mock baseline data...")
    baseline_flows = generate_mock_baseline_flows(1000)

    print("[Training] Extracting features...")
    baseline_features = extract_features(baseline_flows)

    print("[Training] Training anomaly detector...")
    detector = NGFWAnomalyDetector()
    detector.train(baseline_features)

    print("[Training] Saving model...")
    detector.save("models/ngfw_detector.pkl")

    print("[Training] Done! Model ready for use.")