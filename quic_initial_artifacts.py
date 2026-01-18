from scapy.all import rdpcap, UDP              # Read packets and access UDP payloads
from collections import defaultdict            # Group artifacts by connection
from pathlib import Path                       
import json                                    

from quic_initial_header import parse_initial_header  # Parse QUIC Initial headers


class QuicInitialArtifacts:
    # Container for per-connection QUIC Initial artifacts
    def __init__(self, version, dcid_len, scid_len):
        self.version = version
        self.dcid_len = dcid_len
        self.scid_len = scid_len
        self.packet_sizes = []

    def add_packet(self, size):
        # Record size of each Initial packet
        self.packet_sizes.append(size)

    def to_dict(self):
        # Convert collected artifacts into structured features
        return {
            "version": f"0x{self.version:08x}",
            "dcid_len": self.dcid_len,
            "scid_len": self.scid_len,
            "initial_packet_count": len(self.packet_sizes),
            "packet_sizes": self.packet_sizes,
            "avg_packet_size": sum(self.packet_sizes) / len(self.packet_sizes)
            if self.packet_sizes else 0,
            "min_packet_size": min(self.packet_sizes)
            if self.packet_sizes else 0,
            "max_packet_size": max(self.packet_sizes)
            if self.packet_sizes else 0,
            "padding_compliant": all(size >= 1200 for size in self.packet_sizes)
        }


def is_quic_initial(payload: bytes) -> bool:
    # Identify QUIC Initial packets via long header and packet type bits
    if len(payload) < 6:
        return False
    first = payload[0]
    return (first & 0x80) and ((first & 0x30) >> 4 == 0x0)


def extract_initial_artifacts(pcap_path):
    # Extract QUIC Initial artifacts from a PCAP
    packets = rdpcap(str(pcap_path))

    # Store artifacts grouped by Destination Connection ID
    artifacts = {}

    for pkt in packets:
        if UDP not in pkt:
            continue

        payload = bytes(pkt[UDP].payload)
        if not is_quic_initial(payload):
            continue

        try:
            header = parse_initial_header(payload)
        except Exception:
            continue

        dcid_hex = header.dcid.hex()

        if dcid_hex not in artifacts:
            artifacts[dcid_hex] = QuicInitialArtifacts(
                version=header.version,
                dcid_len=len(header.dcid),
                scid_len=len(header.scid),
            )

        artifacts[dcid_hex].add_packet(len(payload))

    return artifacts


def main():
    import sys

    # Allow standalone testing on a PCAP
    if len(sys.argv) != 2:
        print("Usage: python quic_initial_artifacts.py <pcap>")
        sys.exit(1)

    pcap = Path(sys.argv[1])
    if not pcap.exists():
        print("PCAP not found")
        sys.exit(1)

    artifacts = extract_initial_artifacts(pcap)

    print(f"[+] Found {len(artifacts)} QUIC Initial connections\n")

    for dcid, art in artifacts.items():
        print(f"DCID: {dcid}")
        print(json.dumps(art.to_dict(), indent=2))
        print("-" * 40)


if __name__ == "__main__":
    main()
