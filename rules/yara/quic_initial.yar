/*
 QUIC Initial YARA Rules
 -----------------------
 These rules operate on JSON-serialized QUIC Initial artifacts.
 They are heuristic and indicate non-browser or unusual implementations.
*/

rule QUIC_Short_DCID
{
    meta:
        description = "Short QUIC Destination Connection ID length"
        basis = "Empirical browser behavior"
        severity = "medium"

    strings:
        $dcid_0 = "\"dcid_len\": 0"
        $dcid_4 = "\"dcid_len\": 4"

    condition:
        any of them
}

rule QUIC_Zero_SCID
{
    meta:
        description = "Zero-length QUIC Source Connection ID"
        basis = "Empirical browser behavior"
        severity = "medium"

    strings:
        $scid_zero = "\"scid_len\": 0"

    condition:
        $scid_zero
}

rule QUIC_Known_NonBrowser_Fingerprint
{
    meta:
        description = "Known non-browser QUIC Initial fingerprint pattern"
        basis = "Observed implementation fingerprint"
        severity = "low"

    strings:
        /*
         Example fingerprint patterns:
         v1_d4_s0_i*
         v1_d0_s0_i*
        */
        $fp1 = "\"fingerprint_id\": \"v1_d4_s0"
        $fp2 = "\"fingerprint_id\": \"v1_d0_s0"

    condition:
        any of them
}
