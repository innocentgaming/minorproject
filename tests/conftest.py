"""Pytest fixtures for Secure Document Verification System (SDVS)."""

import os
import sys
from pathlib import Path
import pytest

# Ensure parent directory is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


@pytest.fixture
def temp_workspace(tmp_path):
    """Provides an isolated directory for test artifacts."""
    return tmp_path


@pytest.fixture
def empty_file(tmp_path):
    """Creates an empty file."""
    f = tmp_path / "empty.txt"
    f.write_bytes(b"")
    return f


@pytest.fixture
def abc_file(tmp_path):
    """Creates a file with 'abc' ASCII content."""
    f = tmp_path / "abc.txt"
    f.write_bytes(b"abc")
    return f


@pytest.fixture
def random_200kb_file(tmp_path):
    """Generates a 200 KB random binary test file."""
    f = tmp_path / "sample_200kb.bin"
    f.write_bytes(os.urandom(200 * 1024))
    return f


@pytest.fixture
def sample_pdf_file(tmp_path):
    """Creates a simulated PDF header binary file."""
    f = tmp_path / "document.pdf"
    content = b"%PDF-1.4\n1 0 obj\n<< /Title (Academic Project) >>\nendobj\n%%EOF"
    f.write_bytes(content)
    return f
