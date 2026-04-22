"""
Automated Response Module
Generates Suricata blocking rules for anomalous flows.
"""

import subprocess
import os
import time
from datetime import datetime


SURICATA_RULES_DIR = "rules/"  # Local directory for testing
DYNAMIC_RULES_FILE = os.path.join(SURICATA_RULES_DIR, "ngfw_dynamic.rules")
SID_BASE = 9000000  # Start SID for dynamically generated rules


def generate_suricata_rule(src_ip: str, dst_port: int = None,
                            protocol: str = "tcp", sid: int = None) -> str:
    """
    Generate a Suricata drop rule for a given source IP.

    Args:
        src_ip: Source IP address to block
        dst_port: Optional destination port filter
        protocol: Network protocol (tcp/udp/icmp)
        sid: Suricata rule SID (auto-assigned if None)

    Returns:
        Suricata rule string
    """
    if sid is None:
        sid = SID_BASE + int(time.time() * 1000) % 1000000

    port_filter = f"any -> any {dst_port}" if dst_port else "any -> any any"
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    rule = (
        f'drop {protocol} {src_ip} any -> any any '
        f'(msg:"NGFW ML-Block: Anomalous traffic from {src_ip}"; '
        f'sid:{sid}; rev:1; classtype:anomaly-detected; '
        f'metadata:generated_at {ts};)'
    )
    return rule


def apply_rule(rule: str, reload: bool = True) -> bool:
    """
    Write a rule to the dynamic rules file and reload Suricata.

    Args:
        rule: Suricata rule string
        reload: Whether to send SIGUSR2 to Suricata to reload rules

    Returns:
        True if successful
    """
    try:
        os.makedirs(os.path.dirname(DYNAMIC_RULES_FILE), exist_ok=True)
        with open(DYNAMIC_RULES_FILE, "a") as f:
            f.write(rule + "\n")
        print(f"[Response] Rule written: {rule[:80]}...")

        if reload:
            result = subprocess.run(
                ["suricatasc", "-c", "reload-rules"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                print("[Response] Suricata rules reloaded successfully.")
            else:
                print(f"[Response] Suricata reload warning: {result.stderr}")
        return True
    except Exception as e:
        print(f"[Response] Error applying rule: {e}")
        return False


def block_anomalous_flow(src_ip: str, protocol: str = "tcp") -> bool:
    """Full pipeline: generate and apply a blocking rule."""
    rule = generate_suricata_rule(src_ip=src_ip, protocol=protocol)
    return apply_rule(rule)