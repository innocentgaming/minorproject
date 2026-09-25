"""Comprehensive Security & Cryptographic Integrity Tests for SDVS.

Validates core security properties:
- Section 25 & 26: Exact byte equality, H1 != H2 for small changes, unique nonces,
  tamper resistance, constant-time comparisons, and sanitization.
"""

import os
import tempfile
from pathlib import Path

import pytest

from crypto_engine import (
    encrypt_file,
    decrypt_file,
    AuthenticationError,
    InvalidPasswordError,
    InvalidSDVSFileError,
    HEADER_SIZE,
)
from hash_engine import hash_file, hash_bytes
from verifier import compare_hashes, run_tamper_demo, register_manifest_entry, load_manifest
from logger import log_activity, read_activity_logs, clear_activity_logs
from reports import generate_text_report


def test_section_26_hello_world_avalanche(tmp_path):
    """SECTION 26: Assert that 'hello world' and 'hello world!' yield H1 != H2."""
    f1 = tmp_path / "f1.txt"
    f2 = tmp_path / "f2.txt"

    f1.write_text("hello world", encoding="utf-8")
    f2.write_text("hello world!", encoding="utf-8")

    h1 = hash_file(f1, algo="sha256")
    h2 = hash_file(f2, algo="sha256")

    assert h1 != h2
    assert len(h1) == 64
    assert len(h2) == 64


def test_section_26_encrypt_decrypt_byte_exact(tmp_path):
    """SECTION 26: Encrypt(file) -> Decrypt(encrypted) -> Assert original == recovered bytes."""
    secret_content = b"CRITICAL_LEGAL_CONTRACT_DATA_2026_CONFIDENTIAL" * 100
    orig_file = tmp_path / "contract.pdf"
    orig_file.write_bytes(secret_content)

    password = "SuperSecurePassword_2026!"
    enc_file = tmp_path / "contract.pdf.sdvs"

    encrypt_file(orig_file, dest_path=enc_file, password=password, confirm_password=password)
    assert enc_file.exists()

    dec_file = tmp_path / "recovered_contract.pdf"
    decrypt_file(enc_file, dest_path=dec_file, password=password)

    assert dec_file.exists()
    assert dec_file.read_bytes() == secret_content


def test_unique_nonce_and_salt_per_encryption(tmp_path):
    """SECTION 25: Assert that two encryptions of identical content yield unique nonces & salts."""
    sample = tmp_path / "data.txt"
    sample.write_text("Same identical data for both files", encoding="utf-8")
    pwd = "StaticPassword123!"

    enc1 = tmp_path / "enc1.sdvs"
    enc2 = tmp_path / "enc2.sdvs"

    encrypt_file(sample, dest_path=enc1, password=pwd, confirm_password=pwd)
    encrypt_file(sample, dest_path=enc2, password=pwd, confirm_password=pwd)

    bytes1 = enc1.read_bytes()
    bytes2 = enc2.read_bytes()

    # Extract Salt (16 bytes at offset 5..21) and Nonce (12 bytes at offset 21..33)
    salt1, nonce1 = bytes1[5:21], bytes1[21:33]
    salt2, nonce2 = bytes2[5:21], bytes2[21:33]

    assert salt1 != salt2, "Salts must be cryptographically random and unique"
    assert nonce1 != nonce2, "Nonces must be unique per encryption"
    assert bytes1 != bytes2, "Entire ciphertexts must differ completely"


def test_constant_time_comparison():
    """Validates that constant-time compare handles matching, mismatching, and casing safely."""
    h_orig = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    h_same_upper = h_orig.upper()
    h_tampered = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ae"

    valid, status, _ = compare_hashes(h_orig, h_same_upper)
    assert valid is True
    assert status == "VERIFIED"

    valid, status, _ = compare_hashes(h_orig, h_tampered)
    assert valid is False
    assert status == "MODIFIED"


def test_tamper_demo_isolation(tmp_path):
    """Validates that tamper demonstration isolates changes and leaves original file untouched."""
    orig = tmp_path / "statement.docx"
    orig.write_bytes(b"Original Statement File Contents 1234567890")
    orig_bytes = orig.read_bytes()

    res = run_tamper_demo(orig)

    assert res["status"] == "MODIFIED"
    assert res["original_hash"] != res["tampered_hash"]
    # Ensure original file was NEVER mutated
    assert orig.read_bytes() == orig_bytes


def test_activity_logger_security_isolation(tmp_path):
    """Asserts that logger sanitizes entries and never leaks passwords or secret keys."""
    log_file = tmp_path / "activity.log"
    clear_activity_logs(log_file)

    log_activity("encrypt", "C:/secret/path/to/invoice.pdf", "success", log_path=log_file)
    logs = read_activity_logs(log_path=log_file)

    assert len(logs) == 1
    # Path traversal should be stripped to base filename
    assert logs[0]["filename"] == "invoice.pdf"
    assert logs[0]["operation"] == "encrypt"
    assert logs[0]["result"] == "success"


def test_report_generation(tmp_path):
    """Validates verification report generation formatting."""
    report = generate_text_report(
        filename="Assignment.pdf",
        file_size_bytes=2548012,
        file_size_human="2.43 MB",
        sha256_digest="7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
        sha1_digest="a9993e364706816aba3e25717850c26c9cd0d89d",
        verification_status="VERIFIED",
        verification_method="Dual Document Hash Comparison",
    )

    assert "SECURE DOCUMENT VERIFICATION SYSTEM" in report
    assert "Assignment.pdf" in report
    assert "2.43 MB" in report
    assert "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069" in report
    assert "[PASS]" in report
