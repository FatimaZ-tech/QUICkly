import subprocess          # Run Zeek as an external process
import shutil              # Remove old Zeek output directories
from pathlib import Path   # Safe, cross-platform path handling


class ZeekRunner:
    def __init__(self, zeek_binary="zeek"):
        # Store Zeek executable name or path
        self.zeek = zeek_binary

    def run(self, pcap_path, output_dir="zeek_output"):
        # Normalize input and output paths
        pcap_path = Path(pcap_path).resolve()
        output_dir = Path(output_dir).resolve()

        # Ensure PCAP exists before running Zeek
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        # Remove previous Zeek output to avoid stale logs
        if output_dir.exists():
            shutil.rmtree(output_dir)
        output_dir.mkdir(parents=True)

        print(f"[+] Running Zeek on {pcap_path}")

        # Execute Zeek in offline mode on the PCAP
        result = subprocess.run(
            [self.zeek, "-r", str(pcap_path)],
            cwd=str(output_dir),
            capture_output=True,
            text=True
        )

        # Abort if Zeek execution failed
        if result.returncode != 0:
            raise RuntimeError(
                "Zeek execution failed\n"
                f"STDERR:\n{result.stderr}\n"
                f"STDOUT:\n{result.stdout}"
            )

        print("[+] Zeek finished successfully")
        return output_dir

    def validate_quic(self, output_dir):
        # Check whether Zeek detected QUIC traffic
        quic_log = Path(output_dir) / "quic.log"

        if not quic_log.exists():
            raise RuntimeError("quic.log not found — no QUIC traffic detected")

        if quic_log.stat().st_size == 0:
            raise RuntimeError("quic.log is empty — QUIC traffic not detected")

        print("[+] QUIC traffic confirmed")
        return quic_log

    def parse_quic_log(self, quic_log_path):
        # Parse Zeek quic.log into structured dictionaries
        entries = []
        fields = []

        with open(quic_log_path, "r") as f:
            for line in f:
                # Extract column names from Zeek header
                if line.startswith("#fields"):
                    fields = line.strip().split()[1:]
                elif line.startswith("#"):
                    continue
                else:
                    values = line.strip().split("\t")
                    entries.append(dict(zip(fields, values)))

        print(f"[+] Parsed {len(entries)} QUIC connections")
        return entries
