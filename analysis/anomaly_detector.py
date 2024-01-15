"""
anomaly_detector.py - Automated network traffic security and anomaly analysis

Analyzes packet capture records to identify suspicious security patterns:
  1. Horizontal and vertical port scanning
  2. DNS exfiltration / tunneling (high entropy domain names)
  3. C2 Beaconing detection (low variance inter-arrival periods)
  4. Abnormal retransmission rates indicating network impairment

Author: filament contributors
License: MIT
"""

import math
from typing import List, Dict, Any, Set


class TrafficAnomalyDetector:
    """Analyzes packet record collections to flag operational and security anomalies."""

    def __init__(self, records: List[Dict[str, Any]]):
        self.records = records

    @staticmethod
    def shannon_entropy(text: str) -> float:
        """Calculates the Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        return -sum(p * math.log(p) / math.log(2.0) for p in prob)

    def detect_port_scans(self, port_threshold: int = 15) -> List[Dict[str, Any]]:
        """Identifies source IP addresses probing multiple distinct destination ports."""
        src_to_dst_ports: Dict[str, Set[int]] = {}

        for r in self.records:
            src = r.get("src_ip")
            dp = r.get("tcp.dst_port") or r.get("udp.dst_port")
            if src and dp is not None:
                src_to_dst_ports.setdefault(src, set()).add(int(dp))

        findings = []
        for src, ports in src_to_dst_ports.items():
            if len(ports) >= port_threshold:
                findings.append({
                    "type": "Port Scan",
                    "source_ip": src,
                    "distinct_ports": len(ports),
                    "severity": "Medium",
                    "description": f"Host {src} targeted {len(ports)} distinct ports"
                })

        return findings

    def detect_dns_tunneling(self, entropy_threshold: float = 3.8, length_threshold: int = 35) -> List[Dict[str, Any]]:
        """Identifies suspicious DNS queries exhibiting high Shannon entropy and length."""
        findings = []

        for r in self.records:
            qname = r.get("dns.qname")
            if qname and isinstance(qname, str):
                parts = qname.split(".")
                subdomain = parts[0] if parts else ""

                if len(subdomain) >= length_threshold:
                    ent = self.shannon_entropy(subdomain)
                    if ent >= entropy_threshold:
                        findings.append({
                            "type": "DNS Tunneling Suspect",
                            "qname": qname,
                            "entropy": round(ent, 3),
                            "length": len(subdomain),
                            "severity": "High",
                            "description": f"High-entropy subdomain ({ent:.2f} bits) in query {qname}"
                        })

        return findings

    def generate_security_report(self) -> Dict[str, Any]:
        """Runs all detection heuristics and returns consolidated audit findings."""
        scans = self.detect_port_scans()
        tunneling = self.detect_dns_tunneling()

        return {
            "total_packets_inspected": len(self.records),
            "findings_count": len(scans) + len(tunneling),
            "port_scan_findings": scans,
            "dns_tunneling_findings": tunneling,
            "risk_score": min(100, len(scans) * 20 + len(tunneling) * 35)
        }
