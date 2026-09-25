# Secure Document Verification System (SDVS)

**A Production-Quality Academic Mini-Project in Applied Cryptography & Document Security**

---

## 1. Project Title
**Secure Document Verification System (SDVS)**  
*Confidentiality, Integrity Fingerprinting, and Micro-Tamper Detection for Arbitrary Binary Assets*

---

## 2. Problem Statement
In enterprise, legal, academic, and government settings, sensitive documents (contracts, academic transcripts, medical records, source binaries, and reports) face dual security risks:
1. **Confidentiality Breach:** Unauthorized third parties gaining access to unencrypted files in transit or at rest.
2. **Silent Tampering:** Malicious or accidental modification of contents, where even a single bit or punctuation flip can invert financial terms, change grades, or alter executable code.

Standard file sharing lacks cryptographic integrity guarantees. Legacy hash algorithms (e.g., MD5, SHA-1) suffer from collision vulnerabilities, unauthenticated symmetric ciphers (e.g., AES-CBC, AES-ECB) are susceptible to padding oracle and bit-flipping attacks, and simplistic password hashing is easily defeated by GPU-accelerated rainbow tables.

**SDVS** solves these vulnerabilities by combining **AES-256-GCM authenticated encryption**, **Scrypt memory-hard key derivation**, **SHA-256 cryptographic fingerprinting**, **constant-time digest verification**, and **isolated 1-bit tamper demonstration** in a 100% local, zero-network architecture.

---

## 3. Objectives
- **O1. Confidentiality:** Protect arbitrary documents using military-grade AES-256 in Galois/Counter Mode (GCM).
- **O2. Document Fingerprinting:** Generate collision-resistant SHA-256 fingerprints alongside legacy SHA-1 benchmarks.
- **O3. Tamper Detection:** Reliably detect even a single-byte or single-bit alteration in any file.
- **O4. Usability:** Guarantee that all core security workflows (encrypt, decrypt, hash, verify) execute within 3 steps.
- **O5. Demonstrability:** Provide a safe, built-in tamper demonstration that mutates a temporary copy to illustrate the Avalanche Effect without compromising the user's original file.

---

## 4. Key Features
- **True Authenticated Encryption (AEAD):** AES-256-GCM ensures both confidentiality and plaintext/ciphertext integrity via a 16-byte authentication tag.
- **Associated Authenticated Data (AAD):** The 33-byte SDVS protocol header is cryptographically bound into the GCM tag; altering the header or metadata causes decryption to abort.
- **Scrypt Password Key Derivation:** $N=32768, r=8, p=1$ forces high memory and CPU cost to defeat brute-force and ASIC/GPU attacks.
- **Unique Salt & Nonce Per Encryption:** 16-byte random salt and 12-byte random nonce ensure that encrypting the identical file with the identical password yields completely different ciphertexts.
- **Memory-Safe 64 KB Chunk Streaming:** Handles arbitrary file sizes with constant memory footprint.
- **Plaintext Leakage Prevention:** Decryption streams into a temporary `.part` file; on authentication failure, the temporary file is immediately purged.
- **Constant-Time Verification:** Uses `hmac.compare_digest()` to eliminate side-channel timing attacks.
- **Local Manifest Ledger:** Automatically maintains `data/manifest.json` with idempotent updates (no duplicates).
- **Sanitized Activity Audit Log:** Real-time logging to `data/activity.log` with strict isolation (passwords and keys are never logged).
- **Zero External Network Dependencies:** Operates completely offline—no cloud telemetry, no analytics, no external API calls.

---

## 5. System Architecture & Layers

SDVS is architected across three decoupled layers:

```
┌─────────────────────────────────────────────────────────────┐
│                       LAYER 1: UI                           │
│                         app.py                              │
│       (Streamlit: Encrypt/Decrypt, Hash, Verify, Demo)      │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
┌──────────────▼──────────────────────────────▼───────────────┐
│                 LAYER 2: SECURITY ENGINES                   │
│  crypto_engine.py   │  hash_engine.py  │    verifier.py     │
│  (AES-256-GCM +     │  (SHA-256,       │ (Manifest manager, │
│   Scrypt + AAD)     │   SHA-1, 64KB)   │  constant-time cmp)│
│                     └────────┬─────────┘                    │
│                              │                              │
│                       logger.py                             │
│                  (Audit trail manager)                      │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
┌──────────────▼──────────────────────────────▼───────────────┐
│                    LAYER 3: STORAGE                         │
│             data/manifest.json │ data/activity.log          │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. Technology Stack
| Component | Technology | Version | Rationale |
| :--- | :--- | :--- | :--- |
| **Language** | Python | 3.9+ (tested on 3.14) | Robust standard library, type hints, portable. |
| **Cryptography** | `cryptography` | 50.0.1+ | Audited C-bindings for AES-GCM and Scrypt KDF. |
| **Hashing & HMAC** | `hashlib`, `hmac` | Python Standard Library | Optimized native C implementations. |
| **User Interface** | `streamlit` | 1.30+ | Rapid, reactive, modern web presentation. |
| **Testing** | `pytest` | 8.0+ | Automated test runner with fixtures. |
| **System Libs** | `tempfile`, `pathlib`, `shutil`, `os` | Python Standard Library | Safe atomic file operations and memory isolation. |

---

## 7. Project Structure
```
sdvs/
│
├── app.py                  # Layer 1: Streamlit interactive interface
├── crypto_engine.py        # Layer 2: AES-256-GCM, Scrypt, SDVS binary framing
├── hash_engine.py          # Layer 2: 64 KB chunked SHA-256 and SHA-1 hashing
├── verifier.py             # Layer 2: Manifest storage, HMAC verification, tamper demo
├── logger.py               # Layer 2: Activity auditing (strictly sanitizes secrets)
├── requirements.txt        # Package dependencies
├── README.md               # Comprehensive documentation and viva guide
│
├── data/
│   ├── manifest.json       # Idempotent hash records database
│   └── activity.log        # Timestamped audit ledger
│
└── tests/
    ├── conftest.py         # Pytest fixtures (files, vectors, workspaces)
    ├── test_hash.py        # NIST test vectors and algorithm validation
    ├── test_crypto.py      # AES-GCM, Scrypt, wrong password, AAD tampering tests
    └── test_verifier.py    # 1-bit detection, manifest updates, tamper demo tests
```

---

## 8. Installation & Setup

### Prerequisites
- Python 3.9 or newer installed.
- Git (optional, for cloning).

### Step 1: Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 9. Running the Application
Launch the Streamlit web dashboard:
```bash
streamlit run app.py
```
Or run via python module:
```bash
python -m streamlit run app.py
```
The interface will open in your default browser at `http://localhost:8501`.

---

## 10. Running the Automated Test Suite
To execute the comprehensive test suite with verbose output:
```bash
pytest tests/ -v
```
Or via python module:
```bash
python -m pytest tests/ -v
```

---

## 11. In-Depth Cryptographic Engineering

### 11.1 Why AES-256-GCM Instead of AES-CBC?
- **Confidentiality vs. Authenticity:** AES in Cipher Block Chaining (CBC) mode only encrypts data. It provides zero mathematical guarantee that the ciphertext was not tampered with. Without a separate MAC (Encrypt-then-MAC), CBC is vulnerable to bit-flipping attacks and padding oracle attacks.
- **AEAD Design:** Galois/Counter Mode (GCM) is an **Authenticated Encryption with Associated Data (AEAD)** algorithm. It computes a 128-bit authentication tag using Galois field multiplication ($\text{GF}(2^{128})$). If even one bit of ciphertext or AAD is modified, tag verification fails unconditionally.
- **Parallel Processing:** GCM uses CTR mode under the hood, enabling high throughput on multicore hardware with AES-NI instructions.

### 11.2 Why Scrypt Instead of Standard SHA-256 or PBKDF2?
- **Speed is a Flaw in Password Hashing:** SHA-256 can be evaluated billions of times per second on commodity GPUs. A weak or medium user password hashed with plain SHA-256 can be cracked in seconds via brute-force or rainbow tables.
- **Memory-Hardness:** Scrypt is designed to require large amounts of RAM ($N=32768, r=8, p=1$ requires $\approx 32\text{ MB}$ of memory per derivation). This prevents mass parallelization on ASICs and GPUs, drastically raising the hardware cost of dictionary attacks.

### 11.3 Salt and Nonce Dynamics
- **Random 16-byte Salt:** Derived uniquely via `os.urandom(16)` per encryption. Prevents rainbow table reuse; encrypting the identical file twice produces distinct keys.
- **Random 12-byte Nonce:** A 96-bit nonce is generated randomly via `os.urandom(12)`. In GCM, reusing a nonce with the same key breaks authenticity (allowing polynomial tag reconstruction). Because each encryption creates a fresh Scrypt salt, the derived key is unique, and the nonce provides independent uniqueness.

### 11.4 SHA-256 vs. SHA-1
- **SHA-256:** The current gold standard for cryptographic hashing. Employs a 256-bit digest space ($2^{128}$ collision resistance). No known practical collision attack exists.
- **SHA-1 (Legacy):** Produces a 160-bit digest. In 2017, the SHAttered attack produced practical collisions. In SDVS, SHA-1 is preserved strictly for legacy comparison and clearly flagged as weak in the UI.

---

## 12. SDVS Binary File Format Specification

Encrypted documents are stored with the extension `.sdvs`. The file structure is laid out as follows:

```
+-------------------------------------------------------------------+
| Offset | Length   | Field      | Description                      |
+--------+----------+------------+----------------------------------+
| 0      | 4 bytes  | MAGIC      | ASCII "SDVS" (0x53 0x44 0x56 0x53) |
| 4      | 1 byte   | VERSION    | Protocol version byte (0x01)     |
| 5      | 16 bytes | SALT       | Cryptographic Scrypt Salt        |
| 21     | 12 bytes | NONCE      | AES-GCM 96-bit Nonce             |
| 33     | N bytes  | CIPHERTEXT | AES-256-GCM Encrypted Payload     |
| 33+N   | 16 bytes | GCM TAG    | 128-bit Authentication Tag       |
+-------------------------------------------------------------------+
```

### Additional Authenticated Data (AAD) Protection
The first 33 bytes (Magic + Version + Salt + Nonce) are authenticated as **AAD** during AES-GCM initialization:
```python
encryptor.authenticate_additional_data(header_33_bytes)
```
If an adversary edits the magic bytes, changes the version, or alters the salt/nonce in transit, GCM tag verification fails immediately, aborting decryption before any plaintext is released.

---

## 13. Plaintext Leakage Prevention & Streaming Lifecycle

During streaming decryption, plaintext chunks are produced as ciphertext is processed. However, **GCM tag validity cannot be proven until the entire stream has been read and the final 16 bytes are authenticated**:

```
.sdvs file ──► Read Header & Tag ──► Initialize Decryptor
                     │
                     ▼
         Stream to temporary .part file
                     │
              Finalize Tag?
             /             \
       [PASS]               [FAIL]
          │                    │
Atomic Rename to Target    Unlink .part file immediately
Plaintext Available        Zero Plaintext Left On Disk
```

---

## 14. Manifest & Verification Engine

### Manifest Format (`data/manifest.json`)
The manifest stores file fingerprints indexed by filename:
```json
{
  "contract.pdf": {
    "filename": "contract.pdf",
    "algorithm": "sha256",
    "digest": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "size_bytes": 1048576,
    "timestamp": "2026-09-20T14:32:10"
  }
}
```
- **No Duplicates:** Re-registering `contract.pdf` updates the existing entry in-place.
- **Constant-Time Comparison:** Hashes are verified using `hmac.compare_digest(actual, expected)`. This protects against side-channel timing attacks that could reveal digest prefixes based on comparison response duration.

---

## 15. Safe 1-Bit Tamper Demonstration

The Avalanche Effect is a fundamental property of cryptographic hashes: changing one bit in the input causes $\approx 50\%$ of the output bits to flip unpredictably.

SDVS demonstrates this live in Tab 4:
1. An isolated copy of the user's file is created in a temporary directory.
2. The original SHA-256 digest is calculated.
3. The lowest bit of the first byte is inverted: `byte[0] ^ 0x01`.
4. The tampered SHA-256 digest is calculated.
5. The UI displays both hashes and the `MODIFIED` verdict.
6. The temporary directory is wiped. The user's original document is **never altered**.

---

## 16. Threat Model & Security Boundaries

| Threat Vector | Attack Scenario | SDVS Defense Strategy |
| :--- | :--- | :--- |
| **T1: Ciphertext Interception** | Eavesdropper steals `.sdvs` file. | AES-256-GCM + Scrypt renders brute-force computationally infeasible. |
| **T2: Ciphertext Alteration** | Attacker flips bits in encrypted file. | GCM 16-byte authentication tag detects modification; decryption aborts. |
| **T3: Header Manipulation** | Attacker tampers with Salt or Nonce. | Header is authenticated as AAD; verification fails instantly. |
| **T4: Dictionary / GPU Attacks** | Attacker attempts wordlist attack on password. | Scrypt memory cost ($N=32768, 32\text{ MB RAM}$) throttles cracking rate. |
| **T5: Rainbow Tables** | Attacker pre-computes hashes for passwords. | 16-byte cryptographically secure random salt per file renders rainbow tables useless. |
| **T6: Document Tampering** | Attacker alters text in a signed PDF. | SHA-256 hash mismatch results in instant `MODIFIED` verdict. |
| **T7: Coordinated Tampering** | Attacker alters document and manifest together. | **Documented Limitation:** Manifest is local JSON. Future work: HMAC or digital signatures. |
| **T8: SHA-1 Collision** | Attacker exploits SHA-1 weakness. | SHA-256 is default; SHA-1 displays prominent legacy/weak warning. |
| **T9: Keylogger / Malware** | Compromised host OS logs keystrokes. | Out of scope for application-level cryptography. |

---

## 17. Limitations & Future Scope

### System Limitations
1. **Signer Identity:** A hash proves file integrity (whether it changed), not file authorship (who made it).
2. **Local Manifest Vulnerability:** If an attacker has write access to both the target file and `data/manifest.json`, they can rewrite both simultaneously.
3. **Password Irrecoverability:** No backdoor exists. If the password is forgotten, data cannot be recovered.
4. **Browser Buffer Memory:** While SDVS backend engines stream in 64 KB chunks, Streamlit's web uploader loads the payload into memory before streaming to disk.

### Future Roadmap
1. **Public-Key Digital Signatures:** Integrate RSA-4096 and ECDSA (Ed25519) to verify authorship alongside integrity.
2. **HMAC Manifest Authentication:** Sign `manifest.json` using a secret key to prevent coordinated tampering.
3. **QR Code Fingerprinting:** Embed verification digests into scannable QR seals for physical printouts.
4. **Batch Directory Auditing:** Scan entire directory trees and report anomalous modifications.

---

## 18. Viva Voce Examination Questions & Answers

**Q1: What is the primary difference between AES-CBC and AES-GCM?**  
*Answer:* AES-CBC provides only confidentiality. It does not verify authenticity or integrity, leaving it open to bit-flipping and padding oracle attacks unless paired with a separate MAC. AES-GCM is an AEAD cipher that provides confidentiality and authenticity simultaneously in a single, high-performance pass using Galois Counter Mode.

**Q2: What is the purpose of Additional Authenticated Data (AAD)?**  
*Answer:* AAD allows plaintext metadata (such as headers, file versions, and nonces) to be included in the cryptographic tag calculation without being encrypted. This guarantees that an attacker cannot tamper with the protocol header or substitute parameters.

**Q3: Why can't we use simple SHA-256 to hash user passwords into AES keys?**  
*Answer:* SHA-256 is designed for extreme speed, which makes it vulnerable to brute-force cracking on modern hardware (billions of hashes/sec on GPUs). Scrypt is a memory-hard key derivation function that forces high memory and CPU consumption, making hardware-accelerated dictionary attacks impractical.

**Q4: What happens if an AES-GCM nonce is reused with the same key?**  
*Answer:* Nonce reuse in AES-GCM compromises authenticity and enables an attacker to reconstruct the authentication key (Galois hash key $H$), completely destroying the integrity protection and potentially decrypting ciphertexts. SDVS prevents this by generating a unique 16-byte Scrypt salt and 12-byte nonce for every single encryption.

**Q5: Why does SDVS write decrypted data to a temporary `.part` file first?**  
*Answer:* In streaming GCM, the decryptor produces plaintext chunks before reading the final authentication tag. If the password is wrong or the ciphertext was altered, the error is only thrown upon calling `finalize()`. By writing to a `.part` file and unlinking it on failure, SDVS guarantees that unauthenticated plaintext is never exposed to the user or left on disk.

**Q6: What is the Avalanche Effect?**  
*Answer:* A property of cryptographic hash functions where a slight change in the input (such as flipping a single bit) causes a radical, uncorrelated change in the output digest (approximately 50% of the bits flip).

**Q7: Why does SDVS use `hmac.compare_digest()` instead of `==`?**  
*Answer:* The standard Python equality operator `==` compares strings character-by-character and terminates early on the first non-matching byte. This creates timing variations that can be measured over a network to deduce the expected hash byte-by-byte. `hmac.compare_digest()` performs a constant-time comparison, eliminating timing side channels.

**Q8: Does an intact hash prove who sent the document?**  
*Answer:* No. A hash proves data integrity (that the bits have not changed since the hash was generated), not data origin. To prove authenticity and authorship, asymmetric cryptography (digital signatures like RSA or Ed25519) is required.

---

## 19. Academic Declaration
This project is an original, fully local implementation of applied cryptographic concepts built in accordance with standard academic engineering principles. All cryptographic primitives are implemented using audited, standard libraries (`cryptography`, `hashlib`, `hmac`). No simulated or hardcoded crypto functions are used.
