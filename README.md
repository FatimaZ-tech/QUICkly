# QUICkly (QUIC Initial Forensics)
Quickly is an experimental forensic tool that analyses QUIC Initial packets from PCAP files to extract connection level behavioural fingerprints and apply deterministic logic rules and YARA-style signatures.

Unlike most post 2020 QUIC security research that relies on machine learning over encrypted traffic, this project explores a transparent approach to QUIC forensics, focusing on the properties of the QUIC handshake phase.

This repository is part of an ongoing research, and rule tuning and baseline suppression are actively being refined.

---

## What QUICkly Does

* Zeek-based QUIC validation  
* QUIC Initial packet identification (no payload decryption)  
* Connection-level artifact aggregation (per DCID)  
* Stable behavioral fingerprint construction  
* Deterministic logic rules based on RFCs and empirical behavior  
* YARA rules applied to structured QUIC artifacts  

---

## Implemented Rules

### Logic Rules (Deterministic)

| Rule                         | Description                         | Basis                      |
| ---------------------------- | ----------------------------------- | -------------------------- |
| `initial_padding_violation`  | Initial packets < 1200 bytes        | RFC 9000                   |
| `abnormal_initial_flight`    | Unusually high Initial packet count | Empirical browser behavior |
| `unusual_quic_version`       | Non-standard QUIC version           | RFC / deployment reality   |
| `fixed_initial_size_pattern` | Identical Initial packet sizes      | Forensic heuristic         |

### YARA Rules (Signature-Based)

* Zero-length Source Connection ID (SCID)  
* Short or unusual DCID length patterns  
* Known non-browser Initial fingerprint structures  

> **Note:** Some rules intentionally flag standardized browser behavior.  
> These matches are treated as implementation fingerprints, not indicators of malicious activity.

---

## Current Limitations

* Initial phase analysis only (no application data inspection)  
* Some heuristic rules generate expected false positives on modern browsers  
* Offline PCAP analysis only (no live capture)  
* No malicious factual labeling  
* Rule tuning and baseline suppression are ongoing  

These limitations are **explicitly acknowledged** and are part of the active research scope. The tool is currently being tuned.

---

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/FatimaZ-tech/QUICkly.git
cd QUICkly
pip install -r requirements.txt
```
---

## How to Run QUICkly

```bash
python QUICkly.py test.pcap
```

---

## License

This project is licensed under the **MIT License**.

You are free to use, modify, and distribute this software for research, educational, and operational purposes, provided that the original copyright notice and license are included.

See the `LICENSE` file for full license text.

---

## Author

Developed by **Fatima Zakir** as part of ongoing research in Digital Forensics & Incident Response (DFIR).

