"""
visualizer.py - Forensic visualization generator for packet capture traces

Renders standalone SVG diagrams and ASCII charts for traffic forensics:
  1. TCP Time-Sequence Graph (Stevens-style TCP timeline)
  2. Protocol breakdown charts
  3. Latency distribution histograms

Author: filament contributors
License: MIT
"""

import math
from typing import List, Dict, Any, Tuple


class ForensicVisualizer:
    """Generates analytical visualizations from capture records."""

    def __init__(self, records: List[Dict[str, Any]]):
        self.records = records

    def render_tcp_timeline_svg(self, width: int = 800, height: int = 400) -> str:
        """
        Generates an SVG Stevens-style time-sequence plot showing sequence
        numbers over time and highlighting retransmissions in red.
        """
        # Filter for TCP packets with valid seq numbers
        tcp_pts: List[Tuple[float, int, bool]] = []
        base_time = None

        for r in self.records:
            if "tcp.seq" in r and "timestamp_sec" in r:
                t = float(r["timestamp_sec"])
                seq = int(r["tcp.seq"])
                is_retrans = bool(r.get("is_retransmission", False))

                if base_time is None:
                    base_time = t
                rel_t = t - base_time
                tcp_pts.append((rel_t, seq, is_retrans))

        if not tcp_pts:
            return '<svg width="400" height="100"><text x="20" y="50">No TCP sequence data found</text></svg>'

        min_t = min(p[0] for p in tcp_pts)
        max_t = max(p[0] for p in tcp_pts)
        min_seq = min(p[1] for p in tcp_pts)
        max_seq = max(p[1] for p in tcp_pts)

        t_range = max(max_t - min_t, 0.001)
        seq_range = max(max_seq - min_seq, 1)

        margin_left = 70
        margin_bottom = 50
        plot_w = width - margin_left - 30
        plot_h = height - margin_bottom - 30

        svg = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'style="background-color: #1a1a24; font-family: monospace;">',
            f'<text x="{width // 2}" y="24" fill="#e0e0e0" font-size="14" text-anchor="middle" font-weight="bold">'
            f'TCP Sequence Number vs Time (Stevens Plot)</text>',
            # Axes
            f'<line x1="{margin_left}" y1="{height - margin_bottom}" x2="{margin_left + plot_w}" '
            f'y2="{height - margin_bottom}" stroke="#555" stroke-width="1.5"/>',
            f'<line x1="{margin_left}" y1="30" x2="{margin_left}" '
            f'y2="{height - margin_bottom}" stroke="#555" stroke-width="1.5"/>',
            f'<text x="{width // 2}" y="{height - 15}" fill="#888" font-size="11" text-anchor="middle">'
            f'Time Elapsed (seconds)</text>',
        ]

        # Plot points
        for rel_t, seq, is_retrans in tcp_pts:
            x = margin_left + ((rel_t - min_t) / t_range) * plot_w
            y = (height - margin_bottom) - ((seq - min_seq) / seq_range) * plot_h
            color = "#ff4d4d" if is_retrans else "#4da6ff"
            r_size = 4 if is_retrans else 2.5
            svg.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r_size}" fill="{color}" opacity="0.8"/>')

        svg.append('</svg>')
        return "\n".join(svg)

    def render_protocol_summary_ascii(self) -> str:
        """Renders an ASCII horizontal bar chart of protocol counts."""
        proto_counts: Dict[str, int] = {}
        for r in self.records:
            proto = r.get("highest_protocol", "Unknown")
            proto_counts[proto] = proto_counts.get(proto, 0) + 1

        if not proto_counts:
            return "No protocol records present"

        total = sum(proto_counts.values())
        max_name_len = max(len(p) for p in proto_counts.keys())
        bar_max = 40

        lines = [
            "Protocol Breakdown Summary",
            "=" * 60,
        ]

        for proto, count in sorted(proto_counts.items(), key=lambda x: -x[1]):
            pct = (count / total) * 100.0
            bar_len = int((count / total) * bar_max)
            bar_str = "#" * bar_len
            lines.append(f"{proto:<{max_name_len}} | {bar_str:<40} {count:>6} ({pct:>5.1f}%)")

        lines.append("=" * 60)
        return "\n".join(lines)
