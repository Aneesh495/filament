"""
filament_bridge.py - Python data science bridge for Filament packet captures

Converts Filament capture outputs and PCAP data into pandas DataFrames
for exploratory data analysis, time-series forecasting, and machine learning.

Author: filament contributors
License: MIT
"""

import json
import struct
import datetime
from typing import List, Dict, Any, Optional

try:
    import pandas as pd
    import numpy as np
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False


class FilamentBridge:
    """Ingests Filament JSON traces and converts them to structured Python representations."""

    def __init__(self):
        self.packets: List[Dict[str, Any]] = []

    def load_json_lines(self, filepath: str) -> int:
        """Reads newline-delimited JSON packet records emitted by the Filament CLI."""
        count = 0
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                self.packets.append(record)
                count += 1
        return count

    def add_packet(self, packet_dict: Dict[str, Any]) -> None:
        """Appends an individual packet dictionary."""
        self.packets.append(packet_dict)

    def to_dataframe(self) -> Any:
        """Converts collected packet records into a pandas DataFrame."""
        if not HAS_PANDAS:
            raise RuntimeError("pandas is required for DataFrame conversion. Install with: pip install pandas")

        if not self.packets:
            return pd.DataFrame()

        df = pd.DataFrame(self.packets)

        # Standardize timestamp column if present
        if "timestamp" in df.columns:
            df["datetime"] = pd.to_datetime(df["timestamp"])
            df.set_index("datetime", inplace=False)

        return df

    def compute_conversations(self) -> Any:
        """Aggregates packets into 5-tuple conversations with duration and byte totals."""
        if not HAS_PANDAS:
            raise RuntimeError("pandas is required for conversation computation")

        df = self.to_dataframe()
        if df.empty or "src_ip" not in df.columns:
            return pd.DataFrame()

        # Group by 5-tuple
        group_cols = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
        valid_cols = [c for c in group_cols if c in df.columns]

        if not valid_cols:
            return pd.DataFrame()

        agg_dict = {
            "length": ["count", "sum"],
        }
        if "timestamp" in df.columns:
            agg_dict["timestamp"] = ["min", "max"]

        convs = df.groupby(valid_cols).agg(agg_dict).reset_index()
        convs.columns = ["_".join(col).strip("_") for col in convs.columns.values]
        return convs


def parse_raw_pcap_header(data: bytes) -> Dict[str, Any]:
    """Inspects a 24-byte classic PCAP header without external C dependencies."""
    if len(data) < 24:
        raise ValueError("Buffer too short for PCAP global header")

    magic = struct.unpack("<I", data[0:4])[0]
    swapped = False

    if magic == 0xa1b2c3d4:
        endian = "<"
    elif magic == 0xd4c3b2a1:
        endian = ">"
        swapped = True
    else:
        raise ValueError(f"Unrecognized PCAP magic: 0x{magic:08x}")

    version_major, version_minor, thiszone, sigfigs, snaplen, linktype = struct.unpack(
        f"{endian}HHIIII", data[4:24]
    )

    return {
        "magic": hex(magic),
        "swapped": swapped,
        "version": f"{version_major}.{version_minor}",
        "snaplen": snaplen,
        "linktype": linktype
    }
