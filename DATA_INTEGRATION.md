# Real Data Integration Guide
## NGFW Isolation Forest - Production Data Setup

**Purpose**: Replace mock data with real-world attack datasets for rigorous evaluation.

---

## Part 1: Download Real Datasets

### Option A: NSL-KDD (Recommended for Thesis - Smaller)

**Dataset Details:**
- Size: 125,973 flows
- Training: 41,000 flows (80% normal, 20% attacks)
- Testing: 22,000 flows (labeled)
- Attacks: DoS, Probe, R2L, U2R

**Download Steps:**

1. **Visit the dataset source:**
   ```bash
   # Go to: http://www.unb.ca/cic/datasets/nsl-kdd.html
   # Or use direct download:
   
   cd data/
   wget https://www.unb.ca/cic/datasets/nsl-kdd/NSL-KDD.zip
   unzip NSL-KDD.zip
   ```

2. **File Structure:**
   ```
   NSL-KDD/
   ├── KDDTrain+.txt          # Training data (125,973 records)
   ├── KDDTest+.txt           # Test data (22,544 records)
   ├── KDDTrain+_20Percent.txt # Smaller training subset
   └── column_names.txt        # Feature descriptions
   ```

3. **NSL-KDD Features (41 total):**
   ```
   duration, protocol_type, service, flag, src_bytes, dst_bytes,
   land, wrong_fragment, urgent, hot, num_failed_logins, 
   logged_in, num_compromised, root_shell, su_attempted,
   num_root, num_file_creations, num_shells, num_access_files,
   num_outbound_cmds, is_host_login, is_guest_login,
   count, srv_count, serror_rate, srv_serror_rate,
   rerror_rate, srv_rerror_rate, same_srv_rate,
   diff_srv_rate, srv_diff_host_rate,
   dst_host_count, dst_host_srv_count, dst_host_same_srv_rate,
   dst_host_diff_srv_rate, dst_host_same_src_port_rate,
   dst_host_srv_diff_host_rate, dst_host_serror_rate,
   dst_host_srv_serror_rate, dst_host_rerror_rate,
   dst_host_srv_rerror_rate, class (label)
   ```

---

### Option B: CICIDS2018 (More Modern - Larger)

**Dataset Details:**
- Size: 2.8M flows (11 days of network traffic)
- Balanced attacks and normal traffic
- 14 types of attacks
- Modern network protocols

**Download Steps:**

1. **Visit the dataset source:**
   ```bash
   # Go to: https://www.unb.ca/cic/datasets/ids-2018.html
   # Requires registration (free)
   # Or use Canadian server:
   
   cd data/
   wget https://www.unb.ca/cic/datasets/ids-2018/Monday-WorkingHours.pcap
   wget https://www.unb.ca/cic/datasets/ids-2018/Thursday-WorkingHours.pcap
   ```

2. **File Format:**
   - PCAP binary format (network packet captures)
   - Requires `scapy` or `pyshark` to parse
   - Very large (~40 GB for full dataset)

3. **Alternative: Use CSV version:**
   ```bash
   # Pre-processed CSV available from:
   # https://www.kaggle.com/solarmora/ids2018csv
   # Download: Friday-WorkingHours.csv (smaller, ~700 MB)
   
   # Contains all flows with labels and extracted features
   ```

---

## Part 2: Data Preprocessing

### Create Data Loader Module

Create `src/data_loader.py`:

```python
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from pathlib import Path

class NSLKDDLoader:
    """Load and preprocess NSL-KDD dataset."""
    
    @staticmethod
    def load_nsl_kdd(file_path, sample_size=None):
        """
        Load NSL-KDD dataset and convert to flow records format.
        
        Args:
            file_path: Path to KDDTrain+.txt or KDDTest+.txt
            sample_size: Limit records (for testing)
            
        Returns:
            List of flow dicts, list of labels
        """
        # Define column names (from NSL-KDD documentation)
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
            'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
            'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
            'num_outbound_cmds', 'is_host_login', 'is_guest_login',
            'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
            'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate', 'label'
        ]
        
        # Load CSV
        df = pd.read_csv(file_path, names=columns, header=None)
        
        if sample_size:
            df = df.sample(n=sample_size, random_state=42)
        
        # Extract labels
        labels = (df['label'] != 'normal').astype(int).tolist()
        
        # Convert to flow record format (compatible with feature_extraction.py)
        flows = []
        for idx, row in df.iterrows():
            flow = {
                'duration': float(row['duration']),
                'protocol': self._encode_protocol(row['protocol_type']),
                'protocol_name': row['protocol_type'],
                'pkt_sizes': [int(row['src_bytes']), int(row['dst_bytes'])],
                'inter_arrival_times': [float(row['duration'] / max(1, row['count']))],
                'bytes_forward': int(row['src_bytes']),
                'bytes_reverse': int(row['dst_bytes']),
                'packet_count': int(row['count']),
                'src_bytes': int(row['src_bytes']),
                'dst_bytes': int(row['dst_bytes']),
                'hot': int(row['hot']),
                'num_failed_logins': int(row['num_failed_logins']),
                'serror_rate': float(row['serror_rate']),
                'rerror_rate': float(row['rerror_rate']),
                'same_srv_rate': float(row['same_srv_rate']),
            }
            flows.append(flow)
        
        return flows, labels
    
    @staticmethod
    def _encode_protocol(protocol_name):
        """Convert protocol name to number."""
        protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
        return protocol_map.get(protocol_name.lower(), 0)


class CICIDS2018Loader:
    """Load CICIDS2018 CSV (pre-processed flows)."""
    
    @staticmethod
    def load_cicids2018_csv(file_path, sample_size=None):
        """
        Load CICIDS2018 CSV dataset.
        
        Args:
            file_path: Path to CSV file
            sample_size: Limit records
            
        Returns:
            List of flow dicts, list of labels
        """
        df = pd.read_csv(file_path)
        
        if sample_size:
            df = df.sample(n=sample_size, random_state=42)
        
        # Extract label (CICIDS2018 uses 'Label' column)
        labels = (df['Label'] != 'BENIGN').astype(int).tolist()
        
        flows = []
        for idx, row in df.iterrows():
            flow = {
                'duration': float(row['Flow Duration']) / 1e6,  # Convert to seconds
                'protocol': int(row['Protocol']),
                'protocol_name': ['icmp', 'tcp', 'udp'][int(row['Protocol']) % 3],
                'pkt_sizes': [float(row['Fwd Pkt Len Max']), float(row['Bwd Pkt Len Max'])],
                'inter_arrival_times': [float(row['Flow IAT Mean']) / 1e6],
                'bytes_forward': float(row['Total Fwd Pkts']),
                'bytes_reverse': float(row['Total Bwd Pkts']),
                'packet_count': float(row['Total Fwd Pkts']) + float(row['Total Bwd Pkts']),
            }
            flows.append(flow)
        
        return flows, labels
```

---

## Part 3: Updated Training Script

Create `src/train_with_real_data.py`:

```python
"""
Training script for real-world datasets.
"""

import pandas as pd
from data_loader import NSLKDDLoader, CICIDS2018Loader
from feature_extraction import extract_features
from anomaly_detector import NGFWAnomalyDetector
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix
import json

def evaluate_model(detector, test_features, test_labels):
    """Evaluate and print metrics."""
    predictions = detector.predict(test_features)
    
    # Calculate metrics
    precision, recall, f1, _ = precision_recall_fscore_support(
        test_labels, predictions, average='binary', zero_division=0
    )
    
    # False positive rate
    tn, fp, fn, tp = confusion_matrix(test_labels, predictions).ravel()
    fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0
    
    results = {
        'precision': round(precision, 3),
        'recall': round(recall, 3),
        'f1_score': round(f1, 3),
        'fpr_percent': round(fpr, 2),
        'tp': int(tp),
        'fp': int(fp),
        'tn': int(tn),
        'fn': int(fn),
    }
    
    return results

if __name__ == "__main__":
    # Option 1: NSL-KDD
    print("[Training] Loading NSL-KDD dataset...")
    train_flows, train_labels = NSLKDDLoader.load_nsl_kdd(
        'data/NSL-KDD/KDDTrain+.txt'
    )
    test_flows, test_labels = NSLKDDLoader.load_nsl_kdd(
        'data/NSL-KDD/KDDTest+.txt'
    )
    
    print(f"[Training] Loaded {len(train_flows)} training flows, {len(test_flows)} test flows")
    
    # Extract features
    print("[Training] Extracting features...")
    train_features = extract_features(train_flows)
    test_features = extract_features(test_flows)
    
    # Train detector (use normal traffic only)
    print("[Training] Training on normal traffic only...")
    normal_mask = pd.Series(train_labels) == 0
    baseline_features = train_features[normal_mask]
    
    detector = NGFWAnomalyDetector()
    detector.train(baseline_features, validation_split=0.15)
    
    # Evaluate on test set
    print("[Training] Evaluating on test set...")
    results = evaluate_model(detector, test_features, test_labels)
    
    print("\n" + "="*50)
    print("EVALUATION RESULTS (NSL-KDD)")
    print("="*50)
    for metric, value in results.items():
        print(f"{metric:20s}: {value}")
    
    # Save model
    detector.save("models/ngfw_detector_nslkdd.pkl")
    
    # Save results
    with open("results/evaluation_nslkdd.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("\n✅ Model trained and saved to models/ngfw_detector_nslkdd.pkl")
```

---

## Part 4: What's Missing (Checklist)

### ✅ Already Have
- [x] Feature extraction pipeline
- [x] Isolation Forest model wrapper
- [x] Response module (Suricata rules)
- [x] Main orchestrator
- [x] Design documentation
- [x] Testing methodology

### ❌ Missing for Complete Thesis

| Component | Priority | Status |
|-----------|----------|--------|
| Real dataset loader | **HIGH** | ❌ Missing |
| Baseline comparison models | **HIGH** | ❌ Missing |
| Cross-validation testing | **HIGH** | ❌ Missing |
| Evaluation metrics export | **HIGH** | ❌ Missing |
| Unit tests | **MEDIUM** | ❌ Missing |
| Configuration file (config.yaml) | **MEDIUM** | ❌ Missing |
| Logging framework | **MEDIUM** | ❌ Missing |
| Performance benchmarks | **MEDIUM** | ❌ Missing |
| Adversarial testing suite | **LOW** | ❌ Missing |

---

## Part 5: Implementation Steps

### Step 1: Download Data (5 min)
```bash
cd /Users/uniq1st/ngfw-isolation-forest/data

# Download NSL-KDD (recommended for start)
wget https://www.unb.ca/cic/datasets/nsl-kdd/NSL-KDD.zip
unzip NSL-KDD.zip

# Or download from your browser:
# http://www.unb.ca/cic/datasets/nsl-kdd.html
```

### Step 2: Create Data Loader (15 min)
1. Create `src/data_loader.py` (copy code above)
2. Test it:
   ```bash
   python3 -c "from src.data_loader import NSLKDDLoader; flows, labels = NSLKDDLoader.load_nsl_kdd('data/NSL-KDD/KDDTrain+.txt'); print(f'Loaded {len(flows)} flows')"
   ```

### Step 3: Train on Real Data (10 min)
1. Create `src/train_with_real_data.py` (copy code above)
2. Run it:
   ```bash
   python3 src/train_with_real_data.py
   ```
3. Check results in `results/evaluation_nslkdd.json`

### Step 4: Create Baseline Models (30 min)
Create `src/baseline_models.py`:

```python
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import precision_recall_fscore_support

class BaselineModels:
    @staticmethod
    def random_forest(X_train, y_train, X_test, y_test):
        """Train Random Forest baseline."""
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        # Train on labeled data
        rf.fit(X_train[y_train==0], y_train[y_train==0])
        predictions = rf.predict(X_test) > 0.5
        p, r, f1, _ = precision_recall_fscore_support(y_test, predictions, average='binary')
        return {'precision': p, 'recall': r, 'f1': f1}
    
    @staticmethod
    def one_class_svm(X_train, y_train, X_test, y_test):
        """One-Class SVM baseline."""
        ocs = OneClassSVM(nu=0.05, kernel='rbf')
        ocs.fit(X_train[y_train==0])
        predictions = ocs.predict(X_test) == -1
        p, r, f1, _ = precision_recall_fscore_support(y_test, predictions, average='binary')
        return {'precision': p, 'recall': r, 'f1': f1}
    
    @staticmethod
    def lof(X_train, y_train, X_test, y_test):
        """Local Outlier Factor baseline."""
        lof = LocalOutlierFactor(n_neighbors=20, novelty=True)
        lof.fit(X_train[y_train==0])
        predictions = lof.predict(X_test) == -1
        p, r, f1, _ = precision_recall_fscore_support(y_test, predictions, average='binary')
        return {'precision': p, 'recall': r, 'f1': f1}
```

### Step 5: Create Comparison Script (20 min)
Create `src/compare_models.py` to run all baselines and ML model, compare results.

---

## Part 6: Quick Start Commands

```bash
# 1. Download data
cd data/ && wget [NSL-KDD link] && unzip NSL-KDD.zip

# 2. Train on real data
python3 src/train_with_real_data.py

# 3. View results
cat results/evaluation_nslkdd.json

# 4. Run detection on test set
python3 src/main.py  # (update to use test data)

# 5. Generate evaluation report
python3 src/compare_models.py > results/comparison_report.txt
```

---

## Part 7: Final Thesis Integration

Update your Final Report with:

```
5. EXPERIMENTS

5.1 Datasets
- NSL-KDD: 41,000 training flows (80% normal, 20% attacks)
- Test Set: 22,000 flows

5.2 Evaluation Metrics
- Precision, Recall, F1-Score
- False Positive Rate (FPR)
- ROC-AUC Curve

5.3 Baselines
- Rule-based (if/else filters)
- Random Forest
- One-Class SVM  
- Local Outlier Factor

5.4 Results
[Insert table from evaluation_nslkdd.json]

5.5 Comparison
Isolation Forest achieves XX% F1 vs YY% baseline
```

---

**Next**: Do Step 1-2 first (download data, create loader), then run training. Let me know if you hit any errors!
