"""Tests for verifier, manifest system, tamper demonstration, and audit logger."""

from pathlib import Path
import pytest
from verifier import (
    register_manifest_entry,
    load_manifest,
    get_manifest_entry,
    compare_hashes,
    run_tamper_demo,
)
from hash_engine import hash_file
from logger import log_activity, read_activity_logs


def test_t7_single_character_modification_detected(tmp_path):
    """T7: Changing a single character/byte of a document results in MODIFIED."""
    original = tmp_path / "original.txt"
    original.write_text("Hello World! Secure Document Verification.", encoding="utf-8")
    original_hash = hash_file(original, algo="sha256")

    # Modify single character
    tampered = tmp_path / "tampered.txt"
    tampered.write_text("Hello World? Secure Document Verification.", encoding="utf-8")
    tampered_hash = hash_file(tampered, algo="sha256")

    assert original_hash != tampered_hash
    is_valid, status, msg = compare_hashes(tampered_hash, original_hash)
    assert not is_valid
    assert status == "MODIFIED"
    assert "The file does not match the expected hash." in msg


def test_manifest_registration_and_no_duplicates(tmp_path):
    """Registering a file creates a record, and re-registering updates without duplicate keys."""
    manifest_file = tmp_path / "manifest.json"

    # Initial registration
    entry1 = register_manifest_entry(
        filename="report.pdf",
        algorithm="sha256",
        digest="aaa111",
        size_bytes=1000,
        manifest_path=manifest_file,
    )
    manifest = load_manifest(manifest_file)
    assert len(manifest) == 1
    assert "report.pdf" in manifest
    assert manifest["report.pdf"]["digest"] == "aaa111"

    # Second registration with new hash (e.g. updated version of same document)
    entry2 = register_manifest_entry(
        filename="report.pdf",
        algorithm="sha256",
        digest="bbb222",
        size_bytes=1050,
        manifest_path=manifest_file,
    )
    manifest = load_manifest(manifest_file)
    assert len(manifest) == 1  # No duplicate key
    assert manifest["report.pdf"]["digest"] == "bbb222"
    assert manifest["report.pdf"]["size_bytes"] == 1050


def test_pasted_hash_normalization():
    """Hashes pasted with uppercase letters, leading/trailing whitespace must match."""
    expected_clean = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    pasted_dirty = "  BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD \n"

    is_valid, status, _ = compare_hashes(expected_clean, pasted_dirty)
    assert is_valid
    assert status == "VERIFIED"


def test_tamper_demo_non_empty_file(abc_file):
    """Tamper demo flips 1 bit, reports MODIFIED, and leaves original file untouched."""
    original_bytes = abc_file.read_bytes()
    original_hash = hash_file(abc_file)

    demo_result = run_tamper_demo(abc_file)

    assert demo_result["status"] == "MODIFIED"
    assert demo_result["original_hash"] == original_hash
    assert demo_result["tampered_hash"] != original_hash
    assert "A one-bit change produced a different hash." in demo_result["message"]

    # Verify original file remains completely unmodified
    assert abc_file.read_bytes() == original_bytes
    assert hash_file(abc_file) == original_hash


def test_tamper_demo_empty_file(empty_file):
    """Tamper demo handles empty files cleanly."""
    original_hash = hash_file(empty_file)
    demo_result = run_tamper_demo(empty_file)

    assert demo_result["status"] == "MODIFIED"
    assert demo_result["original_hash"] == original_hash
    assert demo_result["tampered_hash"] != original_hash
    assert empty_file.read_bytes() == b""


def test_activity_logger(tmp_path):
    """Activity logger logs records and never exposes passwords."""
    log_file = tmp_path / "activity.log"
    log_activity("encrypt", "secret.pdf", "success", log_path=log_file)
    log_activity("verify", "secret.pdf", "VERIFIED", log_path=log_file)
    log_activity("decrypt", "secret.pdf.sdvs", "failed: Wrong password or file was modified", log_path=log_file)

    entries = read_activity_logs(log_path=log_file)
    assert len(entries) == 3
    # Newest is first
    assert entries[0]["operation"] == "decrypt"
    assert "failed" in entries[0]["result"]
    assert entries[1]["operation"] == "verify"
    assert entries[2]["operation"] == "encrypt"

    raw_log = log_file.read_text(encoding="utf-8")
    # Verify no secret keywords leaked
    assert "password" not in raw_log.lower() or "wrong password" in raw_log.lower()
    assert "key" not in raw_log.lower()
