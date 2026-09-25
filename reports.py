"""Verification and Security Report Generation Module for SDVS.

Generates structured, downloadable integrity reports and certificates.
Strictly does not include passwords, secret keys, or sensitive plaintext payloads.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


def generate_text_report(
    filename: str,
    file_size_bytes: int,
    file_size_human: str,
    sha256_digest: str,
    sha1_digest: Optional[str] = None,
    verification_status: str = "VERIFIED",
    verification_method: str = "Two-Document Hash Comparison",
    expected_hash: Optional[str] = None,
    notes: Optional[str] = None,
) -> str:
    """Generates a standardized, readable ASCII verification report."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    divider = "=" * 72
    sub_divider = "-" * 72

    report_lines = [
        divider,
        "          SECURE DOCUMENT VERIFICATION SYSTEM (SDVS) REPORT",
        "                Cryptographic Integrity & Audit Certificate",
        divider,
        f"Generated At          : {now_str}",
        f"Document Name         : {Path(filename).name}",
        f"File Size             : {file_size_human} ({file_size_bytes:,} bytes)",
        f"Verification Status   : {verification_status.upper()}",
        f"Verification Method   : {verification_method}",
        sub_divider,
        "CRYPTOGRAPHIC FINGERPRINTS:",
        f"  SHA-256 (NIST Standard) : {sha256_digest}",
    ]

    if sha1_digest:
        report_lines.append(f"  SHA-1 (Legacy / Weak)   : {sha1_digest}")

    if expected_hash:
        report_lines.append(f"  Expected Reference Hash : {expected_hash}")

    report_lines.extend([
        sub_divider,
        "SECURITY & INTEGRITY SUMMARY:",
    ])

    if "VERIFIED" in verification_status.upper():
        report_lines.append("  [PASS] Cryptographic digests match identically.")
        report_lines.append("  [PASS] No bit-level modification or unauthorized alteration detected.")
    else:
        report_lines.append("  [FAIL] Cryptographic digest mismatch detected.")
        report_lines.append("  [FAIL] Document has been tampered with, corrupted, or differs from baseline.")

    report_lines.extend([
        sub_divider,
        "STANDARDS & COMPLIANCE NOTICE:",
        "  - SHA-256 is the primary recommended cryptographic integrity standard.",
        "  - SHA-1 is included strictly for educational and legacy validation purposes.",
        "  - All verification routines use constant-time comparison to prevent side-channel timing attacks.",
        "  - SDVS operates 100% locally with zero external network transmission.",
        divider,
    ])

    if notes:
        report_lines.extend([
            f"Additional Notes: {notes}",
            divider,
        ])

    return "\n".join(report_lines)
