"""Verification and Manifest Management Engine for SDVS.

Handles manifest persistence, constant-time hash comparisons (hmac.compare_digest),
and safe, isolated 1-bit tamper demonstrations.
"""

import hmac
import json
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from hash_engine import hash_file, normalize_algorithm

DEFAULT_MANIFEST_PATH = Path("data") / "manifest.json"


def get_manifest_path(custom_path: Optional[Union[str, Path]] = None) -> Path:
    """Returns the manifest path and ensures parent directory exists."""
    path = Path(custom_path) if custom_path is not None else DEFAULT_MANIFEST_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def load_manifest(manifest_path: Optional[Union[str, Path]] = None) -> Dict[str, Dict[str, Any]]:
    """Loads manifest data from json file. Creates file with {} if missing or corrupted."""
    path = get_manifest_path(manifest_path)
    if not path.exists():
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
            return {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_manifest(
    manifest_data: Dict[str, Dict[str, Any]],
    manifest_path: Optional[Union[str, Path]] = None,
) -> None:
    """Safely saves manifest data to json file."""
    path = get_manifest_path(manifest_path)
    temp_file = path.with_name(f"{path.name}.tmp")
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2, ensure_ascii=False)
    temp_file.replace(path)


def register_manifest_entry(
    filename: str,
    algorithm: str,
    digest: str,
    size_bytes: int,
    manifest_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Registers or updates a file hash in the manifest.

    Updates existing entry if filename already exists (no duplicates).
    """
    clean_filename = Path(filename).name
    normalized_algo = normalize_algorithm(algorithm)
    clean_digest = digest.strip().lower()
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    entry = {
        "filename": clean_filename,
        "algorithm": normalized_algo,
        "digest": clean_digest,
        "size_bytes": int(size_bytes),
        "timestamp": timestamp,
    }

    manifest = load_manifest(manifest_path)
    manifest[clean_filename] = entry
    save_manifest(manifest, manifest_path)
    return entry


def get_manifest_entry(
    filename: str,
    manifest_path: Optional[Union[str, Path]] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieves an existing manifest record for a given filename."""
    clean_filename = Path(filename).name
    manifest = load_manifest(manifest_path)
    return manifest.get(clean_filename)


def delete_manifest_entry(
    filename: str,
    manifest_path: Optional[Union[str, Path]] = None,
) -> bool:
    """Deletes an entry from the manifest if it exists."""
    clean_filename = Path(filename).name
    manifest = load_manifest(manifest_path)
    if clean_filename in manifest:
        del manifest[clean_filename]
        save_manifest(manifest, manifest_path)
        return True
    return False


def clear_manifest(manifest_path: Optional[Union[str, Path]] = None) -> None:
    """Clears all records from the manifest."""
    save_manifest({}, manifest_path)



def compare_hashes(actual_hash: str, expected_hash: str) -> Tuple[bool, str, str]:
    """Compares actual and expected hashes using constant-time comparison.

    Normalizes inputs by stripping whitespace and converting to lowercase.

    Returns:
        (is_verified, status_code, message)
        is_verified: True if match, False otherwise
        status_code: "VERIFIED" or "MODIFIED"
        message: Human readable explanation
    """
    clean_actual = actual_hash.strip().lower()
    clean_expected = expected_hash.strip().lower()

    # hmac.compare_digest protects against timing attacks
    if hmac.compare_digest(clean_actual, clean_expected):
        return True, "VERIFIED", "The file is unchanged."
    else:
        return False, "MODIFIED", "The file does not match the expected hash."


def run_tamper_demo(source_file_path: Union[str, Path]) -> Dict[str, Any]:
    """Demonstrates tamper detection without modifying the original file.

    Process:
    1. Reads original file.
    2. Copies to an isolated temporary directory.
    3. Computes original SHA-256 hash.
    4. Flips the lowest bit (XOR 1) of the first byte (or injects 1 byte if empty).
    5. Computes tampered SHA-256 hash.
    6. Verifies mismatch (MODIFIED).
    7. Cleans up temp files.

    Returns:
        dict containing original_hash, tampered_hash, status, and message.
    """
    src = Path(source_file_path)
    if not src.is_file():
        raise FileNotFoundError("Couldn't open the file.")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_copy = Path(temp_dir) / src.name
        shutil.copy2(src, temp_copy)

        original_hash = hash_file(temp_copy, algo="sha256")

        # Tamper with the copy
        with open(temp_copy, "r+b") as f:
            first_byte = f.read(1)
            f.seek(0)
            if not first_byte:
                # If file was empty, write one single byte to demonstrate tamper
                f.write(b"\x01")
            else:
                # Flip lowest bit of first byte
                tampered_byte = bytes([first_byte[0] ^ 0x01])
                f.write(tampered_byte)

        tampered_hash = hash_file(temp_copy, algo="sha256")
        is_match, status, _ = compare_hashes(tampered_hash, original_hash)

        return {
            "original_hash": original_hash,
            "tampered_hash": tampered_hash,
            "status": status,
            "message": "A one-bit change produced a different hash." if not is_match else "No change detected.",
        }
