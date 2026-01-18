from scapy.all import rdpcap, UDP      # Read packets and access UDP payloads
from pathlib import Path               # Handle file paths safely
import sys                             # Read command-line arguments


class QuicInitialHeader:
    # Lightweight container for parsed QUIC Initial header fields
    def __init__(self, version, dcid, scid, offset):
        self.version = version
        self.dcid = dcid
        self.scid = scid
        self.offset = offset  # Offset where SCID ends in the packet

    def __repr__(self):
        # Human-readable representation for debugging
        return (
            f"QUIC Initial Header("
            f"version=0x{self.version:08x}, "
            f"dcid={self.dcid.hex()}, "
            f"scid={self.scid.hex()}, "
            f"offset={self.offset})"
        )


def parse_initial_header(payload: bytes) -> QuicInitialHeader:
    # Parse minimal QUIC Initial long header fields
    offset = 0

    # Skip first byte (long header + packet type)
    offset += 1

    # Extract QUIC version field
    version = int.from_bytes(payload[offset:offset + 4], "big")
    offset += 4

    # Extract Destination Connection ID
    dcid_len = payload[offset]
    offset += 1
    dcid = payload[offset:offset + dcid_len]
    offset += dcid_len

    # Extract Source Connection ID
    scid_len = payload[offset]
    offset += 1
    scid = payload[offset:offset + scid_len]
    offset += scid_len

    return QuicInitialHeader(version, dcid, scid, offset)


def find_and_parse_initials(pcap_path):
    # Locate and parse all QUIC Initial packets in a PCAP
    packets = rdpcap(str(pcap_path))
    headers = []

    for pkt in packets:
        if UDP not in pkt:
            continue

        payload = bytes(pkt[UDP].payload)
        if len(payload) < 6:
            continue

        first_byte = payload[0]

        # Check for QUIC long header and Initial packet type
        if not (first_byte & 0x80):
            continue
        if ((first_byte & 0x30) >> 4) != 0x0:
            continue

        try:
            header = parse_initial_header(payload)
            headers.append(header)
        except Exception:
            continue

    return headers


def main():
    # Allow standalone testing on a PCAP
    if len(sys.argv) != 2:
        print("Usage: python quic_initial_header.py <pcap>")
        sys.exit(1)

    pcap = Path(sys.argv[1])
    if not pcap.exists():
        print("PCAP not found")
        sys.exit(1)

    headers = find_and_parse_initials(pcap)

    print(f"[+] Parsed {len(headers)} QUIC Initial headers")

    if headers:
        print("[+] Example:")
        print(headers[0])


if __name__ == "__main__":
    main()
