"""
Feature Extraction Engine
Converts raw network flows into structured feature vectors
for Isolation Forest anomaly detection.
"""

import pandas as pd
import numpy as np


def extract_features(flow_records: list) -> pd.DataFrame:
    """
    Extract flow-level features from raw packet/flow records.

    Args:
        flow_records: list of dicts with raw flow data

    Returns:
        DataFrame with engineered feature vectors
    """
    features = []
    for flow in flow_records:
        feat = {
            "pkt_size_mean": np.mean(flow.get("pkt_sizes", [0])),
            "pkt_size_std":  np.std(flow.get("pkt_sizes",  [0])),
            "pkt_size_min":  np.min(flow.get("pkt_sizes",  [0])),
            "pkt_size_max":  np.max(flow.get("pkt_sizes",  [0])),
            "iat_mean":      np.mean(flow.get("inter_arrival_times", [0])),
            "iat_std":       np.std(flow.get("inter_arrival_times",  [0])),
            "flow_duration": flow.get("duration", 0),
            "byte_fwd":      flow.get("bytes_forward", 0),
            "byte_rev":      flow.get("bytes_reverse", 0),
            "pkt_count":     flow.get("packet_count", 0),
            "protocol":      flow.get("protocol", 0),
            "entropy":       _traffic_entropy(flow.get("pkt_sizes", [0])),
        }
        features.append(feat)
    return pd.DataFrame(features)


def _traffic_entropy(values: list) -> float:
    """Compute Shannon entropy of a list of values."""
    if not values:
        return 0.0
    values = np.array(values, dtype=float)
    values = values / (values.sum() + 1e-9)
    return float(-np.sum(values * np.log2(values + 1e-9)))