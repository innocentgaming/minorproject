"""Tests for AES-256-GCM crypto engine."""

import os
from pathlib import Path
import pytest
from crypto_engine import (
    encrypt_file,
    decrypt_file,
    derive_key,
    AuthenticationError,
    InvalidPasswordError,
    InvalidSDVSFileError,
    CryptoFileAccessError,
    HEADER_SIZE,
    MAGIC,
    VERSION,
)
from hash_engine import hash_file

TEST_PASSWORD = "StrongMasterPassword123!"


def test_t4_encrypt_decrypt_200kb_roundtrip(random_200kb_file, tmp_path):
    """T4: Encrypt and decrypt a 200 KB file; output hash must equal original hash."""
    orig_hash = hash_file(random_200kb_file)
    encrypted_file = encrypt_file(
        random_200kb_file,
        dest_path=tmp_path / "enc.sdvs",
        password=TEST_PASSWORD,
        confirm_password=TEST_PASSWORD,
    )
    assert encrypted_file.exists()

    decrypted_file = decrypt_file(
        encrypted_file,
        dest_path=tmp_path / "dec.bin",
        password=TEST_PASSWORD,
    )
    assert decrypted_file.exists()
    dec_hash = hash_file(decrypted_file)

    assert dec_hash == orig_hash
    assert decrypted_file.read_bytes() == random_200kb_file.read_bytes()


def test_t5_wrong_password_fails_and_no_part_file(abc_file, tmp_path):
    """T5: Decryption with wrong password raises error and cleans up temporary files."""
    encrypted_file = encrypt_file(
        abc_file,
        dest_path=tmp_path / "doc.sdvs",
        password=TEST_PASSWORD,
        confirm_password=TEST_PASSWORD,
    )

    out_target = tmp_path / "doc_recovered.txt"
    with pytest.raises(AuthenticationError) as exc_info:
        decrypt_file(encrypted_file, dest_path=out_target, password="WrongPassword999!")

    assert "Wrong password or file was modified" in str(exc_info.value)
    assert not out_target.exists()

    # Ensure no leftover .part files exist
    part_files = list(tmp_path.glob("*.part*"))
    assert len(part_files) == 0


def test_t6_flip_ciphertext_byte(abc_file, tmp_path):
    """T6: Flipping a single byte in the ciphertext must cause GCM tag validation failure."""
    encrypted_file = encrypt_file(
        abc_file,
        dest_path=tmp_path / "doc.sdvs",
        password=TEST_PASSWORD,
        confirm_password=TEST_PASSWORD,
    )

    data = bytearray(encrypted_file.read_bytes())
    # Header is 33 bytes; flip byte at offset 34 (first ciphertext byte)
    target_offset = HEADER_SIZE + 1
    data[target_offset] ^= 0x01
    encrypted_file.write_bytes(data)

    out_target = tmp_path / "decrypted_tampered.txt"
    with pytest.raises(AuthenticationError) as exc_info:
        decrypt_file(encrypted_file, dest_path=out_target, password=TEST_PASSWORD)

    assert "Wrong password or file was modified" in str(exc_info.value)
    assert not out_target.exists()
    assert len(list(tmp_path.glob("*.part*"))) == 0


def test_t8_encrypt_same_file_twice_differs(abc_file, tmp_path):
    """T8: Encrypting the same file twice produces completely different ciphertexts."""
    enc1 = encrypt_file(
        abc_file,
        dest_path=tmp_path / "enc1.sdvs",
        password=TEST_PASSWORD,
        confirm_password=TEST_PASSWORD,
    )
    enc2 = encrypt_file(
        abc_file,
        dest_path=tmp_path / "enc2.sdvs",
        password=TEST_PASSWORD,
        confirm_password=TEST_PASSWORD,
    )

    bytes1 = enc1.read_bytes()
    bytes2 = enc2.read_bytes()

    assert bytes1 != bytes2
    # Salts (offset 5..21) must differ
    assert bytes1[5:21] != bytes2[5:21]
    # Nonces (offset 21..33) must differ
    assert bytes1[21:33] != bytes2[21:33]


def test_t9_empty_and_large_file_roundtrip(empty_file, tmp_path):
    """T9: Round trip encryption and decryption of an empty file and a 512KB file."""
    # Empty file
    enc_empty = encrypt_file(
        empty_file,
        dest_path=tmp_path / "empty.sdvs",
        password=TEST_PASSWORD,
        confirm_password=TEST_PASSWORD,
    )
    dec_empty = decrypt_file(
        enc_empty,
        dest_path=tmp_path / "empty_dec.txt",
        password=TEST_PASSWORD,
    )
    assert dec_empty.read_bytes() == b""

    # Large file (512 KB)
    large_src = tmp_path / "large.bin"
    large_data = os.urandom(512 * 1024)
    large_src.write_bytes(large_data)

    enc_large = encrypt_file(
        large_src,
        dest_path=tmp_path / "large.sdvs",
        password=TEST_PASSWORD,
        confirm_password=TEST_PASSWORD,
    )
    dec_large = decrypt_file(
        enc_large,
        dest_path=tmp_path / "large_dec.bin",
        password=TEST_PASSWORD,
    )
    assert dec_large.read_bytes() == large_data


def test_t10_truncated_or_invalid_sdvs_file(tmp_path):
    """T10: Truncated files or invalid magic bytes raise InvalidSDVSFileError."""
    short_file = tmp_path / "short.sdvs"
    short_file.write_bytes(b"SDVS\x0112345678")  # Too short (< 49 bytes)

    with pytest.raises(InvalidSDVSFileError) as exc_info:
        decrypt_file(short_file, password=TEST_PASSWORD)
    assert "Not a valid SDVS file" in str(exc_info.value)

    # Invalid MAGIC
    bad_magic = tmp_path / "bad_magic.sdvs"
    bad_magic.write_bytes(b"NOPE" + os.urandom(50))
    with pytest.raises(InvalidSDVSFileError) as exc_info:
        decrypt_file(bad_magic, password=TEST_PASSWORD)
    assert "Not a valid SDVS file" in str(exc_info.value)

    # Invalid VERSION
    bad_ver = tmp_path / "bad_ver.sdvs"
    bad_ver.write_bytes(b"SDVS\x02" + os.urandom(50))
    with pytest.raises(InvalidSDVSFileError) as exc_info:
        decrypt_file(bad_ver, password=TEST_PASSWORD)
    assert "Not a valid SDVS file" in str(exc_info.value)


def test_header_aad_tampering(abc_file, tmp_path):
    """Tampering with header elements (salt, nonce) fails AAD validation."""
    encrypted_file = encrypt_file(
        abc_file,
        dest_path=tmp_path / "doc.sdvs",
        password=TEST_PASSWORD,
        confirm_password=TEST_PASSWORD,
    )

    data = bytearray(encrypted_file.read_bytes())
    # Tamper with Salt at offset 10
    data[10] ^= 0x01
    encrypted_file.write_bytes(data)

    with pytest.raises(AuthenticationError) as exc_info:
        decrypt_file(encrypted_file, password=TEST_PASSWORD)
    assert "Wrong password or file was modified" in str(exc_info.value)


def test_password_validation_rules(abc_file):
    """Test empty, short, and mismatched password validation rules."""
    # Empty password
    with pytest.raises(InvalidPasswordError) as exc_info:
        encrypt_file(abc_file, password="")
    assert "Please enter a password." in str(exc_info.value)

    # Below 8 characters
    with pytest.raises(InvalidPasswordError) as exc_info:
        encrypt_file(abc_file, password="short")
    assert "Use at least 8 characters for the password." in str(exc_info.value)

    # Mismatch
    with pytest.raises(InvalidPasswordError) as exc_info:
        encrypt_file(abc_file, password="ValidPassword1", confirm_password="ValidPassword2")
    assert "Passwords don't match." in str(exc_info.value)


def test_original_file_remains_unchanged(abc_file, tmp_path):
    """Ensure encryption and decryption never alter or remove the original source file."""
    initial_bytes = abc_file.read_bytes()
    initial_hash = hash_file(abc_file)

    enc = encrypt_file(
        abc_file,
        dest_path=tmp_path / "test.sdvs",
        password=TEST_PASSWORD,
        confirm_password=TEST_PASSWORD,
    )
    assert abc_file.exists()
    assert abc_file.read_bytes() == initial_bytes
    assert hash_file(abc_file) == initial_hash
