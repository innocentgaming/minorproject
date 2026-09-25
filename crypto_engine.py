"""AES-256-GCM Cryptographic Engine for Secure Document Verification System (SDVS).

Implements streaming AES-256-GCM with Scrypt key derivation, random 16-byte salt,
random 12-byte nonce, 33-byte AAD header, and secure temporary .part file handling.
"""

import os
from pathlib import Path
from typing import Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# SDVS Protocol Constants
MAGIC = b"SDVS"
VERSION = b"\x01"
SALT_SIZE = 16
NONCE_SIZE = 12
HEADER_SIZE = len(MAGIC) + len(VERSION) + SALT_SIZE + NONCE_SIZE  # 33 bytes
TAG_SIZE = 16  # AES-GCM authentication tag size
MIN_FILE_SIZE = HEADER_SIZE + TAG_SIZE  # 49 bytes (empty file ciphertext = 0 bytes)

# Scrypt KDF Parameters
SCRYPT_N = 2**15  # 32768
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LENGTH = 32  # 256 bits

CHUNK_SIZE = 64 * 1024  # 64 KB streaming buffer
MIN_PASSWORD_LENGTH = 8


class SDVSError(Exception):
    """Base exception for SDVS cryptographic errors."""
    pass


class InvalidPasswordError(SDVSError):
    """Raised when the password does not satisfy requirements."""
    pass


class InvalidSDVSFileError(SDVSError):
    """Raised when the file is not a valid SDVS formatted binary."""
    pass


class AuthenticationError(SDVSError):
    """Raised when decryption fails due to invalid password or modified data."""
    pass


class CryptoFileAccessError(SDVSError):
    """Raised when file reading or writing fails."""
    pass


def validate_password_for_encryption(password: str, confirm_password: Optional[str] = None) -> None:
    """Validates password requirements for encryption."""
    if not password:
        raise InvalidPasswordError("Please enter a password.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise InvalidPasswordError("Use at least 8 characters for the password.")
    if confirm_password is not None and password != confirm_password:
        raise InvalidPasswordError("Passwords don't match.")


def validate_password_for_decryption(password: str) -> None:
    """Validates password input for decryption."""
    if not password:
        raise InvalidPasswordError("Please enter a password.")


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte AES key from password and salt using Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=KEY_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(
    source_path: Union[str, Path],
    dest_path: Optional[Union[str, Path]] = None,
    password: str = "",
    confirm_password: Optional[str] = None,
) -> Path:
    """Encrypts any file using AES-256-GCM with Scrypt key derivation.

    Streams data in 64 KB chunks to a temporary .part file before atomically
    renaming to the final destination (.sdvs). If any error occurs, the .part
    file is deleted.

    Args:
        source_path: Path to plaintext source file.
        dest_path: Optional target path. Defaults to source_path + ".sdvs".
        password: Password (min 8 chars).
        confirm_password: Confirmation password.

    Returns:
        Path to the encrypted .sdvs file.
    """
    src = Path(source_path)
    if not src.is_file():
        raise CryptoFileAccessError("Couldn't open the file.")

    validate_password_for_encryption(password, confirm_password)

    if dest_path is None:
        target = src.with_name(src.name + ".sdvs")
    else:
        target = Path(dest_path)

    part_path = target.with_name(f"{target.name}.part_{os.urandom(6).hex()}")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = MAGIC + VERSION + salt + nonce

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(header)

    try:
        with open(src, "rb") as fin, open(part_path, "wb") as fout:
            fout.write(header)
            while chunk := fin.read(CHUNK_SIZE):
                fout.write(encryptor.update(chunk))
            fout.write(encryptor.finalize())
            tag = encryptor.tag
            fout.write(tag)

        # Atomically replace destination with .part file
        part_path.replace(target)
        return target
    except Exception as e:
        if part_path.exists():
            try:
                part_path.unlink()
            except OSError:
                pass
        if isinstance(e, SDVSError):
            raise
        raise CryptoFileAccessError(f"Encryption failed: {str(e)}") from e


def decrypt_file(
    source_path: Union[str, Path],
    dest_path: Optional[Union[str, Path]] = None,
    password: str = "",
) -> Path:
    """Decrypts an .sdvs file using AES-256-GCM and Scrypt.

    Validates header AAD and 16-byte GCM tag. Decrypts into a temporary
    .part file. If authentication fails, the .part file is immediately
    purged and an AuthenticationError is raised.

    Args:
        source_path: Path to encrypted .sdvs file.
        dest_path: Optional target plaintext path.
        password: Password for decryption.

    Returns:
        Path to the decrypted plaintext file.
    """
    src = Path(source_path)
    if not src.is_file():
        raise CryptoFileAccessError("Couldn't open the file.")

    validate_password_for_decryption(password)

    file_size = src.stat().st_size
    if file_size < MIN_FILE_SIZE:
        raise InvalidSDVSFileError("Not a valid SDVS file")

    if dest_path is None:
        name = src.name
        if name.endswith(".sdvs"):
            out_name = name[:-5]
        else:
            out_name = f"{name}.decrypted"
        target = src.with_name(out_name)
    else:
        target = Path(dest_path)

    part_path = target.with_name(f"{target.name}.part_{os.urandom(6).hex()}")

    try:
        with open(src, "rb") as fin:
            header = fin.read(HEADER_SIZE)
            if len(header) != HEADER_SIZE:
                raise InvalidSDVSFileError("Not a valid SDVS file")

            magic = header[:4]
            version = header[4:5]
            salt = header[5:21]
            nonce = header[21:33]

            if magic != MAGIC or version != VERSION:
                raise InvalidSDVSFileError("Not a valid SDVS file")

            # Read GCM tag from last 16 bytes
            fin.seek(file_size - TAG_SIZE)
            tag = fin.read(TAG_SIZE)
            if len(tag) != TAG_SIZE:
                raise InvalidSDVSFileError("Not a valid SDVS file")

            key = derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(header)

            ciphertext_remaining = file_size - HEADER_SIZE - TAG_SIZE

            # Reset pointer to start of ciphertext
            fin.seek(HEADER_SIZE)

            with open(part_path, "wb") as fout:
                bytes_to_read = ciphertext_remaining
                while bytes_to_read > 0:
                    current_chunk = min(CHUNK_SIZE, bytes_to_read)
                    chunk = fin.read(current_chunk)
                    if not chunk:
                        raise InvalidSDVSFileError("Not a valid SDVS file")
                    fout.write(decryptor.update(chunk))
                    bytes_to_read -= len(chunk)

                # Finalize GCM verification
                try:
                    fout.write(decryptor.finalize())
                except InvalidTag as it_err:
                    raise AuthenticationError("Wrong password or file was modified") from it_err

        # Successfully authenticated; rename temporary part to target
        part_path.replace(target)
        return target
    except Exception as e:
        # Critical security guarantee: purge any decrypted plaintext
        if part_path.exists():
            try:
                part_path.unlink()
            except OSError:
                pass
        if isinstance(e, SDVSError):
            raise
        raise CryptoFileAccessError(f"Decryption failed: {str(e)}") from e
