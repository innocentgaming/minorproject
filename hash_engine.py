"""Cryptographic hash engine for Secure Document Verification System (SDVS).

Supports SHA-256 (default, secure) and SHA-1 (legacy, weak) with 64 KB streaming chunks.
"""

import hashlib
from pathlib import Path
from typing import Union

CHUNK_SIZE = 64 * 1024  # 64 KB chunks

SUPPORTED_ALGORITHMS = {
    "sha256": hashlib.sha256,
    "sha1": hashlib.sha1,
}

ALGORITHM_ALIASES = {
    "sha256": "sha256",
    "sha-256": "sha256",
    "sha_256": "sha256",
    "sha1": "sha1",
    "sha-1": "sha1",
    "sha_1": "sha1",
}


class HashEngineError(Exception):
    """Base exception for hash engine operations."""
    pass


class UnsupportedAlgorithmError(HashEngineError):
    """Raised when an unsupported hashing algorithm is requested."""
    pass


class FileAccessError(HashEngineError):
    """Raised when the target file cannot be accessed or read."""
    pass


def normalize_algorithm(algo: str) -> str:
    """Normalizes algorithm name and validates against supported algorithms.

    Raises:
        UnsupportedAlgorithmError: If algorithm is not SHA-256 or SHA-1.
    """
    if not algo or not isinstance(algo, str):
        raise UnsupportedAlgorithmError("Choose SHA-256 or SHA-1")

    clean_name = algo.strip().lower()
    normalized = ALGORITHM_ALIASES.get(clean_name)

    if not normalized or normalized not in SUPPORTED_ALGORITHMS:
        raise UnsupportedAlgorithmError("Choose SHA-256 or SHA-1")

    return normalized


def hash_file(file_path: Union[str, Path], algo: str = "sha256") -> str:
    """Computes the cryptographic hash of a file in 64 KB streaming chunks.

    Args:
        file_path: Path to the file to be hashed.
        algo: Name of algorithm ('sha256' or 'sha1').

    Returns:
        Lowercase hexadecimal digest string.

    Raises:
        UnsupportedAlgorithmError: If algorithm is invalid.
        FileAccessError: If file does not exist or cannot be read.
    """
    normalized_algo = normalize_algorithm(algo)
    path = Path(file_path)

    if not path.is_file():
        raise FileAccessError("Couldn't open the file.")

    hasher = SUPPORTED_ALGORITHMS[normalized_algo]()

    try:
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                hasher.update(chunk)
    except (OSError, IOError, PermissionError) as e:
        raise FileAccessError("Couldn't open the file.") from e

    return hasher.hexdigest().lower()


def hash_bytes(data: bytes, algo: str = "sha256") -> str:
    """Computes the cryptographic hash of in-memory bytes.

    Args:
        data: Bytes to hash.
        algo: Name of algorithm ('sha256' or 'sha1').

    Returns:
        Lowercase hexadecimal digest string.
    """
    normalized_algo = normalize_algorithm(algo)
    hasher = SUPPORTED_ALGORITHMS[normalized_algo]()
    hasher.update(data)
    return hasher.hexdigest().lower()
