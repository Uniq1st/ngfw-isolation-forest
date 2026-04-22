"""
NGFW Main Pipeline
Ties together traffic capture, feature extraction,
anomaly detection, and automated response.
"""

import time
import pandas as pd
from feature_extraction import extract_features
from anomaly_detector import NGFWAnomalyDetector
from response_module import block_anomalous_flow

# ── Configuration ─────────────────────────────────────────────────────────────
MODEL_PATH = "models/ngfw_detector.pkl"
SCAN_INTERVAL = 1.0  # seconds between scan cycles


def run_pipeline(detector: NGFWAnomalyDetector, live_flows: list):
    """Process a batch of live flows and respond to anomalies."""
    if not live_flows:
        return

    features = extract_features(live_flows)
    predictions = detector.predict(features)

    for i, pred in enumerate(predictions):
        if pred == 1:  # anomalous
            src_ip = live_flows[i].get("src_ip", "unknown")
            proto  = live_flows[i].get("protocol_name", "tcp")
            print(f"[Pipeline] Anomaly detected: {src_ip} ({proto}) — blocking.")
            block_anomalous_flow(src_ip=src_ip, protocol=proto)


if __name__ == "__main__":
    print("[NGFW] Starting Isolation Forest NGFW pipeline...")
    detector = NGFWAnomalyDetector()

    try:
        detector.load(MODEL_PATH)
        print("[NGFW] Loaded pre-trained model.")
    except Exception:
        print("[NGFW] No pre-trained model found. Please run training first.")
        exit(1)

    print("[NGFW] Pipeline active. Monitoring network flows...")
    # Test with mock anomalous flow
    test_flow = {
        "src_ip": "192.168.1.100",
        "protocol_name": "tcp",
        "pkt_sizes": [1500] * 50,  # Large packets (anomalous)
        "inter_arrival_times": [0.001] * 49,
        "duration": 0.1,
        "bytes_forward": 75000,
        "bytes_reverse": 1000,
        "packet_count": 50,
        "protocol": 6
    }
    run_pipeline(detector, [test_flow])
    print("[NGFW] Test completed. Exiting.")