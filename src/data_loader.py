import pandas as pd
import numpy as np

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
        # Read the file with proper handling
        lines = []
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    lines.append(line)
        
        # Parse CSV manually to be robust
        flows = []
        labels = []
        
        for line in lines:
            parts = line.split(',')
            if len(parts) < 42:
                continue
            
            try:
                # Parse the columns
                duration = float(parts[0])
                protocol = parts[1].strip()
                src_bytes = float(parts[4])
                dst_bytes = float(parts[5])
                count = float(parts[22])
                label = parts[-2].strip()  # Label is second-to-last column
                
                # Create flow record
                flow = {
                    'duration': duration,
                    'protocol': NSLKDDLoader._encode_protocol(protocol),
                    'protocol_name': protocol,
                    'pkt_sizes': [src_bytes, dst_bytes] if src_bytes > 0 or dst_bytes > 0 else [1, 1],
                    'inter_arrival_times': [max(0.001, duration / max(1, count))],
                    'bytes_forward': src_bytes,
                    'bytes_reverse': dst_bytes,
                    'packet_count': int(count),
                }
                flows.append(flow)
                
                # Extract label (1 = attack, 0 = normal)
                is_attack = 0 if label == 'normal' else 1
                labels.append(is_attack)
                
            except (ValueError, IndexError):
                continue
        
        # Sample if requested
        if sample_size and len(flows) > sample_size:
            indices = np.random.choice(len(flows), sample_size, replace=False)
            flows = [flows[i] for i in indices]
            labels = [labels[i] for i in indices]
        
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
