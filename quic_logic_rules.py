from typing import List, Dict   # Type hints for rule inputs and outputs


class LogicRuleResult:
    # Container for a single logic rule match
    def __init__(self, rule: str, severity: str, basis: str, reason: str):
        self.rule = rule
        self.severity = severity
        self.basis = basis
        self.reason = reason

    def to_dict(self) -> Dict:
        # Convert rule result into serializable dictionary
        return {
            "rule": self.rule,
            "severity": self.severity,
            "basis": self.basis,
            "reason": self.reason,
        }


class QuicLogicRuleEngine:


    # Applies deterministic protocol and numeric rules to QUIC Initial fingerprints.

    
    def apply(self, fingerprint: Dict) -> List[LogicRuleResult]:
        # Run all logic rules on a single fingerprint
        results = []

        results.extend(self.initial_padding_violation(fingerprint))
        results.extend(self.abnormal_initial_flight(fingerprint))
        results.extend(self.unusual_quic_version(fingerprint))
        results.extend(self.fixed_initial_size_pattern(fingerprint))

        return results

    # Rule 1 — RFC 9000: Initial padding violation
    def initial_padding_violation(self, fp: Dict) -> List[LogicRuleResult]:
        # Check whether Initial packets violate minimum padding requirement
        f = fp["features"]

        if not f.get("padding_compliant", True):
            return [
                LogicRuleResult(
                    rule="initial_padding_violation",
                    severity="high",
                    basis="RFC 9000",
                    reason="QUIC Initial packets smaller than 1200 bytes",
                )
            ]

        return []

    # Rule 2 — Abnormal Initial flight size
    def abnormal_initial_flight(self, fp: Dict) -> List[LogicRuleResult]:
        # Detect unusually large numbers of Initial packets
        f = fp["features"]
        count = f.get("initial_count", 0)

        if count > 3:
            return [
                LogicRuleResult(
                    rule="abnormal_initial_flight",
                    severity="low",
                    basis="Empirical browser behavior",
                    reason=f"Initial packet count unusually high ({count})",
                )
            ]

        return []

    # Rule 3 — Unusual QUIC version
    def unusual_quic_version(self, fp: Dict) -> List[LogicRuleResult]:
        # Flag QUIC versions other than standard QUIC v1
        f = fp["features"]
        version = f.get("version")

        # QUIC v1 = 1
        if version != 1:
            return [
                LogicRuleResult(
                    rule="unusual_quic_version",
                    severity="medium",
                    basis="RFC / deployment reality",
                    reason=f"Non-standard QUIC version observed ({version})",
                )
            ]

        return []

    
    # Rule 4 — Fixed Initial packet size pattern
    def fixed_initial_size_pattern(self, fp: Dict) -> List[LogicRuleResult]:
        # Detect rigid Initial packet sizes across the connection
        f = fp["features"]
        avg_size = f.get("avg_initial_size", 0)
        min_size = f.get("min_packet_size", avg_size)
        max_size = f.get("max_packet_size", avg_size)

        if min_size == max_size and avg_size != 1200:
            return [
                LogicRuleResult(
                    rule="fixed_initial_size_pattern",
                    severity="low",
                    basis="Forensic heuristic",
                    reason=f"All Initial packets have fixed size ({avg_size} bytes)",
                )
            ]

        return []
