import hashlib        # Generate stable fingerprint hashes
import json           # Serialize features deterministically


def build_fingerprint(artifact: dict):
    # Convert QUIC Initial artifacts into a normalized fingerprint

    # Parse and normalize core QUIC features
    version = int(artifact["version"], 16)
    dcid_len = artifact["dcid_len"]
    scid_len = artifact["scid_len"]
    initial_count = artifact["initial_packet_count"]
    avg_size = int(artifact["avg_packet_size"])
    padding = artifact["padding_compliant"]

    # Build human-readable fingerprint identifier
    fingerprint_id = (
        f"v{version}_"
        f"d{dcid_len}_"
        f"s{scid_len}_"
        f"i{initial_count}_"
        f"p{avg_size}"
    )

    # Create stable hash for clustering or ML use
    raw = json.dumps(
        {
            "version": version,
            "dcid_len": dcid_len,
            "scid_len": scid_len,
            "initial_count": initial_count,
            "avg_size": avg_size,
            "padding": padding,
        },
        sort_keys=True
    ).encode()

    fingerprint_hash = hashlib.sha256(raw).hexdigest()[:16]

    # Return fingerprint and normalized feature set
    return {
        "fingerprint_id": fingerprint_id,
        "fingerprint_hash": fingerprint_hash,
        "features": {
            "version": version,
            "dcid_len": dcid_len,
            "scid_len": scid_len,
            "initial_count": initial_count,
            "avg_initial_size": avg_size,
            "padding_compliant": padding,
        }
    }
