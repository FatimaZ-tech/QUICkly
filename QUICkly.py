import argparse
import json
from pathlib import Path
from collections import defaultdict

from zeek_runner import ZeekRunner
from quic_initial_artifacts import extract_initial_artifacts
from rule_engine import QuicRuleEngine


def is_baseline_only(result: dict) -> bool:
    """
    Suppress fingerprints that only exhibit expected baseline behavior.
    """
    logic = result.get("logic_rules", [])
    yara = result.get("yara_rules", [])

    if not logic and len(yara) == 1:
        if yara[0]["rule"] == "QUIC_Zero_SCID":
            return True

    return False


def main():
    parser = argparse.ArgumentParser(
        description="QUIC Initial Forensics Tool (with mandatory Zeek validation)"
    )
    parser.add_argument(
        "pcap",
        help="Path to PCAP file containing network traffic"
    )
    parser.add_argument(
        "--yara-rules",
        default="rules/yara/quic_initial.yar",
        help="Path to YARA rules"
    )

    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        print("[!] PCAP not found")
        return


    # Mandatory Zeek validation
    print("[+] Running Zeek validation...")

    zr = ZeekRunner()
    outdir = zr.run(pcap_path)

    try:
        zr.validate_quic(outdir)
        print("[+] Zeek validation passed: QUIC traffic detected")
    except RuntimeError:
        print("[!] Zeek validation failed: no QUIC traffic found")
        print("[!] Aborting analysis")
        return

    # QUIC Initial artifact extraction
    print("[+] Extracting QUIC Initial artifacts...")
    artifacts = extract_initial_artifacts(pcap_path)

    if not artifacts:
        print("[!] No QUIC Initial packets found")
        return

    # Rule analysis (deduplicated + contextual)
    engine = QuicRuleEngine(args.yara_rules)

    fingerprint_counts = defaultdict(int)
    results_by_fp = {}

    for artifact_obj in artifacts.values():
        artifact = artifact_obj.to_dict()
        result = engine.analyze_artifact(artifact)

        fp_hash = result["fingerprint_hash"]
        fingerprint_counts[fp_hash] += 1
        results_by_fp[fp_hash] = result


    # Reporting

    for fp_hash, result in results_by_fp.items():
        if is_baseline_only(result):
            continue

        result["occurrences"] = fingerprint_counts[fp_hash]

        print("=" * 60)
        print(f"Fingerprint: {result['fingerprint_id']}")
        print(f"Occurrences: {result['occurrences']}")
        print(json.dumps(result, indent=2))
        print("=" * 60)


if __name__ == "__main__":
    main()
