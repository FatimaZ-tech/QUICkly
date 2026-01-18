import json                     # Serialize artifacts for YARA scanning
import yara                     # Apply YARA rules
from typing import Dict         # Type hints for clarity

from quic_logic_rules import QuicLogicRuleEngine
from quic_initial_fingerprint import build_fingerprint


class QuicRuleEngine:
    """
    Combines protocol logic rules and YARA rules
    to analyze QUIC Initial fingerprints.
    """

    def __init__(self, yara_rule_path: str):
        # Initialize logic-based rule engine
        self.logic_engine = QuicLogicRuleEngine()

        # Load YARA rules from file
        self.yara_rules = yara.compile(filepath=yara_rule_path)

    def analyze_artifact(self, artifact: Dict) -> Dict:
        """
        Build fingerprint from artifact, apply all rules,
        and return combined analysis results.
        """

        # Generate a normalized fingerprint from raw artifact
        fingerprint = build_fingerprint(artifact)

        # Apply deterministic protocol and numeric rules
        logic_hits = [
            r.to_dict() for r in self.logic_engine.apply(fingerprint)
        ]

        # Apply YARA rules on serialized artifact + fingerprint
        yara_hits = []
        matches = self.yara_rules.match(
            data=json.dumps({**artifact, **fingerprint})
        )

        for m in matches:
            yara_hits.append({
                "rule": m.rule,
                "meta": m.meta
            })

        # Lightweight summary flags for higher-level reasoning
        summary = {
            "logic_hit_count": len(logic_hits),
            "yara_hit_count": len(yara_hits),
            "has_only_zero_scid": (
                len(logic_hits) == 0
                and len(yara_hits) == 1
                and yara_hits[0]["rule"] == "QUIC_Zero_SCID"
            )
        }

        # Return unified forensic result
        return {
            "fingerprint_id": fingerprint["fingerprint_id"],
            "fingerprint_hash": fingerprint["fingerprint_hash"],
            "logic_rules": logic_hits,
            "yara_rules": yara_hits,
            "summary": summary,
        }
