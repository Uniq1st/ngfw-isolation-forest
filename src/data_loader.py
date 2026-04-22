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
        
        # Extract labels (1 = attack, 0 = normal)
        labels = (df['label'] != 'normal').astype(int).tolist()
        
        # Convert to flow record format (compatible with feature_extraction.py)
        flows = []
        for idx, row in df.iterrows():
            flow = {
                'duration': float(row['duration']),
                'protocol': NSLKDDLoader._encode_protocol(row['protocol_type']),
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
