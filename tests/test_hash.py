"""Tests for cryptographic hash engine (SHA-256, SHA-1)."""

import hashlib
import pytest
from hash_engine import (
    hash_file,
    hash_bytes,
    normalize_algorithm,
    UnsupportedAlgorithmError,
    FileAccessError,
)

EXPECTED_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
EXPECTED_ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
EXPECTED_ABC_SHA1 = "a9993e364706816aba3e25717850c26c9cd0d89d"


def test_t1_sha256_empty_file(empty_file):
    """T1: SHA-256 of an empty file must match standard NIST vector."""
    digest = hash_file(empty_file, algo="sha256")
    assert digest == EXPECTED_EMPTY_SHA256


def test_t2_sha256_abc_file(abc_file):
    """T2: SHA-256 of 'abc' must match standard NIST vector."""
    digest = hash_file(abc_file, algo="sha256")
    assert digest == EXPECTED_ABC_SHA256


def test_t3_sha1_abc_file(abc_file):
    """T3: SHA-1 of 'abc' must match standard NIST vector."""
    digest = hash_file(abc_file, algo="sha1")
    assert digest == EXPECTED_ABC_SHA1


def test_algorithm_normalization(abc_file):
    """Verifies that case variants and hyphens normalize properly."""
    for variant in ["SHA-256", "SHA256", "sha256", "sha-256", "SHA_256"]:
        assert hash_file(abc_file, algo=variant) == EXPECTED_ABC_SHA256

    for variant in ["SHA-1", "SHA1", "sha1", "sha-1", "SHA_1"]:
        assert hash_file(abc_file, algo=variant) == EXPECTED_ABC_SHA1


def test_unsupported_algorithm(abc_file):
    """Reject unsupported algorithms such as MD5, SHA384 with clear message."""
    with pytest.raises(UnsupportedAlgorithmError) as exc_info:
        hash_file(abc_file, algo="md5")
    assert "Choose SHA-256 or SHA-1" in str(exc_info.value)

    with pytest.raises(UnsupportedAlgorithmError) as exc_info:
        hash_file(abc_file, algo="sha512")
    assert "Choose SHA-256 or SHA-1" in str(exc_info.value)


def test_missing_or_unreadable_file(tmp_path):
    """File that does not exist raises FileAccessError."""
    missing = tmp_path / "does_not_exist.txt"
    with pytest.raises(FileAccessError) as exc_info:
        hash_file(missing, algo="sha256")
    assert "Couldn't open the file." in str(exc_info.value)


def test_chunked_streaming_consistency(random_200kb_file):
    """Ensure chunked 64 KB reading matches full hashlib digest."""
    streamed_digest = hash_file(random_200kb_file, algo="sha256")
    expected_digest = hashlib.sha256(random_200kb_file.read_bytes()).hexdigest().lower()
    assert streamed_digest == expected_digest


def test_hash_bytes():
    """Verify in-memory hash_bytes helper."""
    assert hash_bytes(b"abc", algo="sha256") == EXPECTED_ABC_SHA256
    assert hash_bytes(b"abc", algo="sha1") == EXPECTED_ABC_SHA1
