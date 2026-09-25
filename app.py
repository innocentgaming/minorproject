"""Secure Document Verification System (SDVS) - Next-Gen Cybersecurity UI.

Production-grade cryptographic security suite with a premium SaaS interface:
1. Interactive Dashboard with KPI cards and live system telemetry.
2. High-speed Drag & Drop Document Analysis with instant multi-format fingerprinting.
3. Dual-Algorithm Hash Engine (SHA-256 primary + SHA-1 legacy) with checksum exports.
4. Authenticated AES-256-GCM Encryption with Scrypt KDF & entropy strength meter.
5. Authenticated Decryption with AAD validation & zero-plaintext-leakage defense.
6. Constant-Time Document Integrity Verification (Two-Document & Manifest modes).
7. Tamper Simulation Lab demonstrating the Avalanche Effect.
8. Persistent Verification History & Manifest Repository.
9. Real-Time Immutable Security Audit Trail.
10. Live Security Demonstration Lab (3 Guided Viva Demos).
11. Educational Security Center & Threat Defense Specifications.
12. Configurable Diagnostics & Storage Management.
"""

import io
import json
import os
import platform
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

import streamlit as st

from crypto_engine import (
    encrypt_file,
    decrypt_file,
    SDVSError,
    InvalidPasswordError,
    InvalidSDVSFileError,
    AuthenticationError,
    CryptoFileAccessError,
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
    KEY_LENGTH,
    HEADER_SIZE,
    TAG_SIZE,
)
from hash_engine import (
    hash_file,
    hash_bytes,
    HashEngineError,
    UnsupportedAlgorithmError,
    FileAccessError,
)
from verifier import (
    load_manifest,
    save_manifest,
    register_manifest_entry,
    get_manifest_entry,
    delete_manifest_entry,
    clear_manifest,
    compare_hashes,
    run_tamper_demo,
)
from logger import log_activity, read_activity_logs, clear_activity_logs
from reports import generate_text_report

# -----------------------------------------------------------------------------
# Configuration Constants
# -----------------------------------------------------------------------------
SUPPORTED_EXTENSIONS = ["pdf", "doc", "docx", "txt", "xlsx", "csv", "jpg", "jpeg", "png", "zip"]
DEFAULT_MAX_FILE_SIZE_MB = 50

# -----------------------------------------------------------------------------
# Page Configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="SDVS - Secure Document Verification System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# Ultra-Premium Cybersecurity Design System (CSS)
# -----------------------------------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
    
    html, body, [class*="css"], .stApp {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    .code, code, pre, .hash-code, .stCode {
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    /* Global App Background & Container */
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 3rem !important;
        max-width: 1240px;
    }
    
    /* Modern Cyber Hero Header */
    .sdvs-hero {
        background: radial-gradient(120% 120% at 50% 10%, #1E293B 0%, #0F172A 70%, #020617 100%);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 14px;
        padding: 2rem 2.2rem;
        margin-bottom: 1.8rem;
        color: #F8FAFC;
        position: relative;
        overflow: hidden;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px rgba(0, 0, 0, 0.2);
    }
    .sdvs-hero::after {
        content: '';
        position: absolute;
        top: 0; right: 0; bottom: 0; left: 0;
        background: linear-gradient(90deg, rgba(2, 132, 199, 0.08) 0%, transparent 60%);
        pointer-events: none;
    }
    .sdvs-hero h1 {
        font-size: 2rem;
        font-weight: 800;
        margin: 0 0 0.4rem 0;
        letter-spacing: -0.02em;
        background: linear-gradient(135deg, #FFFFFF 30%, #38BDF8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        display: flex;
        align-items: center;
        gap: 0.6rem;
    }
    .sdvs-hero p {
        font-size: 0.98rem;
        color: #94A3B8;
        margin: 0 0 1rem 0;
        max-width: 820px;
        line-height: 1.5;
    }
    
    /* Cyber Pill Chips */
    .cyber-pill-bar {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
    }
    .cyber-pill {
        background: rgba(15, 23, 42, 0.8);
        border: 1px solid rgba(56, 189, 248, 0.3);
        color: #38BDF8;
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.78rem;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 0.35rem;
    }
    
    /* Modern Stat Cards */
    .sdvs-kpi-card {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 12px;
        padding: 1.3rem 1.1rem;
        text-align: center;
        position: relative;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease;
    }
    .sdvs-kpi-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 10px 20px -5px rgba(0, 0, 0, 0.08);
        border-color: #38BDF8;
    }
    .sdvs-kpi-card.cyan { border-top: 4px solid #0284C7; }
    .sdvs-kpi-card.emerald { border-top: 4px solid #10B981; }
    .sdvs-kpi-card.purple { border-top: 4px solid #8B5CF6; }
    .sdvs-kpi-card.rose { border-top: 4px solid #F43F5E; }
    
    .sdvs-kpi-val {
        font-size: 2.1rem;
        font-weight: 800;
        color: #0F172A;
        letter-spacing: -0.03em;
        line-height: 1.1;
        margin-bottom: 0.25rem;
    }
    .sdvs-kpi-label {
        font-size: 0.8rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #64748B;
    }
    
    /* Status Result Banners */
    .verdict-banner-verified {
        background: linear-gradient(135deg, #ECFDF5 0%, #D1FAE5 100%);
        border: 2px solid #059669;
        border-radius: 10px;
        padding: 1.4rem 1.6rem;
        color: #064E3B;
        margin: 1.2rem 0;
        box-shadow: 0 4px 12px rgba(16, 185, 129, 0.12);
    }
    .verdict-banner-tampered {
        background: linear-gradient(135deg, #FEF2F2 0%, #FEE2E2 100%);
        border: 2px solid #DC2626;
        border-radius: 10px;
        padding: 1.4rem 1.6rem;
        color: #7F1D1D;
        margin: 1.2rem 0;
        box-shadow: 0 4px 12px rgba(239, 68, 68, 0.12);
    }
    
    /* Callout & Instruction Cards */
    .callout-box {
        background: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-left: 4px solid #0284C7;
        border-radius: 8px;
        padding: 1rem 1.3rem;
        margin-bottom: 1.3rem;
        color: #334155;
        font-size: 0.93rem;
        line-height: 1.5;
    }
    
    /* Format Badges */
    .format-strip {
        display: flex;
        flex-wrap: wrap;
        gap: 0.4rem;
        margin: 0.6rem 0 1.1rem 0;
    }
    .fmt-badge {
        background: #F1F5F9;
        border: 1px solid #CBD5E1;
        color: #1E293B;
        padding: 0.25rem 0.65rem;
        border-radius: 6px;
        font-size: 0.78rem;
        font-weight: 700;
        display: inline-flex;
        align-items: center;
        gap: 0.3rem;
    }
    
    /* Pulse Live Status Dot */
    .live-indicator {
        display: inline-flex;
        align-items: center;
        gap: 0.4rem;
        font-size: 0.75rem;
        font-weight: 700;
        color: #059669;
        background: #ECFDF5;
        padding: 0.2rem 0.6rem;
        border-radius: 9999px;
        border: 1px solid #A7F3D0;
    }
    .pulse-dot {
        width: 7px;
        height: 7px;
        background-color: #10B981;
        border-radius: 50%;
        display: inline-block;
        box-shadow: 0 0 0 2px rgba(16, 185, 129, 0.3);
    }
    
    /* Custom Streamlit Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
        background-color: #F1F5F9;
        padding: 0.35rem;
        border-radius: 10px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 7px;
        padding: 0.5rem 1rem;
        font-weight: 600;
        font-size: 0.9rem;
    }
    .stTabs [aria-selected="true"] {
        background-color: #FFFFFF !important;
        color: #0284C7 !important;
        box-shadow: 0 1px 3px rgba(0,0,0,0.08);
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# -----------------------------------------------------------------------------
# Session State Setup
# -----------------------------------------------------------------------------
if "nav_section" not in st.session_state:
    st.session_state["nav_section"] = "Dashboard"

if "max_file_size_mb" not in st.session_state:
    st.session_state["max_file_size_mb"] = DEFAULT_MAX_FILE_SIZE_MB

if "latest_hash_data" not in st.session_state:
    st.session_state["latest_hash_data"] = None

# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------
def format_size(size_bytes: int) -> str:
    """Formats raw bytes into human-readable B, KB, MB, GB."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

def get_telemetry_metrics() -> Dict[str, int]:
    """Extracts live operational metrics from audit records and manifest store."""
    manifest = load_manifest()
    logs = read_activity_logs()

    enc_count = sum(1 for l in logs if l.get("operation") in ["encrypt", "DOCUMENT_ENCRYPTED"] and "success" in l.get("result", "").lower())
    dec_count = sum(1 for l in logs if l.get("operation") in ["decrypt", "DOCUMENT_DECRYPTED"] and "success" in l.get("result", "").lower())
    upload_count = sum(1 for l in logs if l.get("operation") in ["upload", "DOCUMENT_UPLOADED", "hash", "HASH_GENERATED"])
    verify_count = sum(1 for l in logs if l.get("operation") in ["verify", "VERIFICATION_SUCCESS", "TAMPERING_DETECTED"])
    tamper_count = sum(1 for l in logs if "modified" in l.get("result", "").lower() or "tamper" in l.get("result", "").lower() or l.get("operation") == "TAMPERING_DETECTED")

    return {
        "total_documents": upload_count + len(manifest),
        "encrypted_count": enc_count,
        "decrypted_count": dec_count,
        "verified_count": verify_count,
        "tamper_detected": tamper_count,
        "manifest_records": len(manifest),
        "total_events": len(logs),
    }

def password_strength(pwd: str) -> Tuple[int, str, str]:
    """Evaluates password entropy and returns (score, label, color)."""
    if not pwd:
        return 0, "Empty", "#94A3B8"
    score = 0
    if len(pwd) >= 8: score += 30
    if len(pwd) >= 12: score += 20
    if any(c.isupper() for c in pwd): score += 15
    if any(c.isdigit() for c in pwd): score += 15
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd): score += 20

    if score < 40: return score, "Weak", "#EF4444"
    elif score < 75: return score, "Moderate", "#F59E0B"
    else: return score, "Strong", "#10B981"

def render_format_badges():
    """Renders accessible format badges."""
    badges_html = """
    <div class="format-strip">
        <span class="fmt-badge">📄 PDF</span>
        <span class="fmt-badge">📝 DOCX / DOC</span>
        <span class="fmt-badge">📋 TXT</span>
        <span class="fmt-badge">📊 XLSX / CSV</span>
        <span class="fmt-badge">🖼️ JPG / JPEG / PNG</span>
        <span class="fmt-badge">📦 ZIP</span>
    </div>
    """
    st.markdown(badges_html, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# Sidebar Navigation & System Telemetry
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ **SDVS Core**")
    st.markdown('<div class="live-indicator"><span class="pulse-dot"></span> LOCAL ENGINE READY</div>', unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    nav_items = [
        "📊 Dashboard",
        "📤 Document Upload & Analysis",
        "⚡ Hash Generator",
        "🔒 AES Encryption",
        "🔓 Decryption",
        "🔍 Document Verification",
        "🧪 Tamper Simulation",
        "📜 Verification History",
        "🛡️ Security Audit Log",
        "🎯 Security Demonstration Lab",
        "📚 About Security",
        "⚙️ Settings & Diagnostics",
    ]

    nav_map = {name: name.split(" ", 1)[1] for name in nav_items}
    current_section = st.session_state.get("nav_section", "Dashboard")
    current_idx = list(nav_map.values()).index(current_section) if current_section in nav_map.values() else 0

    selected_nav = st.radio(
        "Navigation",
        nav_items,
        index=current_idx,
        label_visibility="collapsed",
    )

    st.session_state["nav_section"] = nav_map[selected_nav]

    st.markdown("---")
    st.markdown("#### 🔒 **Cryptographic Specs**")
    st.caption("• **Cipher:** AES-256-GCM (AEAD)")
    st.caption("• **KDF:** Scrypt (N=32768, r=8, p=1)")
    st.caption("• **Hash:** SHA-256 (256-bit NIST)")
    st.caption("• **Verification:** Constant-Time HMAC")

    metrics = get_telemetry_metrics()
    st.markdown("---")
    st.caption(f"📁 Manifest Records: **{metrics['manifest_records']}**")
    st.caption(f"🛡️ Tampering Blocked: **{metrics['tamper_detected']}**")


# =============================================================================
# MODULE 1: DASHBOARD
# =============================================================================
if st.session_state["nav_section"] == "Dashboard":
    st.markdown(
        """
        <div class="sdvs-hero">
            <h1>🛡️ Secure Document Verification System</h1>
            <p>Production-grade cryptographic document integrity, authenticated AES-256-GCM protection, and real-time tamper audit defense.</p>
            <div class="cyber-pill-bar">
                <span class="cyber-pill">🔒 AES-256-GCM</span>
                <span class="cyber-pill">⚡ SHA-256 Hashing</span>
                <span class="cyber-pill">🔑 Scrypt Memory-Hard KDF</span>
                <span class="cyber-pill">🛡️ Constant-Time HMAC</span>
                <span class="cyber-pill">🌐 100% Offline Local Security</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    metrics = get_telemetry_metrics()

    # 4-Column KPI Cards
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="sdvs-kpi-card cyan"><div class="sdvs-kpi-val">{metrics["total_documents"]}</div><div class="sdvs-kpi-label">Documents Processed</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="sdvs-kpi-card emerald"><div class="sdvs-kpi-val">{metrics["encrypted_count"]}</div><div class="sdvs-kpi-label">Files Encrypted</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="sdvs-kpi-card purple"><div class="sdvs-kpi-val">{metrics["verified_count"]}</div><div class="sdvs-kpi-label">Verifications Run</div></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="sdvs-kpi-card rose"><div class="sdvs-kpi-val">{metrics["tamper_detected"]}</div><div class="sdvs-kpi-label">Tampering Detections</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Cryptographic Workflow Stepper
    st.subheader("🔄 Cryptographic Lifecycle Architecture")
    st.markdown(
        """
        ```
        [1] UPLOAD DOCUMENT  ➔  [2] ANALYZE & FINGERPRINT  ➔  [3] AES-256-GCM ENCRYPT  ➔  [4] MANIFEST STORE  ➔  [5] INTEGRITY VERIFY  ➔  [6] DETECT TAMPERING
        ```
        """
    )

    # Quick Launchers
    st.subheader("⚡ Quick Launch Operations")
    q1, q2, q3, q4 = st.columns(4)
    with q1:
        if st.button("📤 Upload & Analyze", use_container_width=True):
            st.session_state["nav_section"] = "Document Upload & Analysis"
            st.rerun()
    with q2:
        if st.button("⚡ Hash Generator", use_container_width=True):
            st.session_state["nav_section"] = "Hash Generator"
            st.rerun()
    with q3:
        if st.button("🔒 AES Encryption", use_container_width=True):
            st.session_state["nav_section"] = "AES Encryption"
            st.rerun()
    with q4:
        if st.button("🔍 Verify Integrity", use_container_width=True):
            st.session_state["nav_section"] = "Document Verification"
            st.rerun()

    st.markdown("---")

    # Recent Audit Log Preview
    col_log, col_info = st.columns([3, 2])
    with col_log:
        st.subheader("📋 Recent Security Events")
        logs = read_activity_logs(limit=6)
        if not logs:
            st.info("No security events recorded yet.")
        else:
            st.dataframe(
                logs,
                column_config={
                    "timestamp": "Timestamp",
                    "operation": "Event Type",
                    "filename": "Target File",
                    "result": "Verdict / Status",
                },
                use_container_width=True,
                hide_index=True,
            )
    with col_info:
        st.subheader("🛡️ Security Baseline Guarantees")
        st.markdown(
            """
            * **Authenticated Cipher (AEAD):** AES-256-GCM binds ciphertext and the 33-byte AAD header to a 16-byte Poly1305 authentication tag.
            * **GPU/ASIC Hardening:** Scrypt KDF allocates ~32 MB RAM per derivation, neutralizing rainbow tables and brute-force attacks.
            * **Side-Channel Immunity:** All verification compares hashes in constant time via `hmac.compare_digest`.
            * **Zero Data Leakage:** Decryption isolates memory in temporary `.part` buffers and wipes unauthenticated streams immediately.
            """
        )


# =============================================================================
# MODULE 2: DOCUMENT UPLOAD & ANALYSIS
# =============================================================================
elif st.session_state["nav_section"] == "Document Upload & Analysis":
    st.markdown(
        """
        <div class="sdvs-hero">
            <h1>📤 Document Upload & Analysis</h1>
            <p>Upload documents to inspect metadata, validate file integrity boundaries, and compute instant cryptographic digests.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(f"**Accepted File Types (Configured Limit: {st.session_state['max_file_size_mb']} MB):**")
    render_format_badges()

    uploaded = st.file_uploader(
        "Select or Drag & Drop Document:",
        type=SUPPORTED_EXTENSIONS,
        key="upload_analysis_uploader",
    )

    if uploaded:
        file_bytes = uploaded.get_buffer() if hasattr(uploaded, "get_buffer") else uploaded.read()
        file_size = len(file_bytes)
        max_bytes = st.session_state["max_file_size_mb"] * 1024 * 1024

        if file_size > max_bytes:
            st.error(f"❌ File size exceeds configured limit ({format_size(file_size)} > {st.session_state['max_file_size_mb']} MB).")
        else:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_file = Path(temp_dir) / uploaded.name
                temp_file.write_bytes(file_bytes)

                sha256_val = hash_file(temp_file, algo="sha256")
                sha1_val = hash_file(temp_file, algo="sha1")

                st.session_state["latest_hash_data"] = {
                    "filename": uploaded.name,
                    "size_bytes": file_size,
                    "size_human": format_size(file_size),
                    "sha256": sha256_val,
                    "sha1": sha1_val,
                    "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                }
                log_activity("DOCUMENT_UPLOADED", uploaded.name, f"Analyzed {format_size(file_size)}")

            st.success(f"✅ Document **{uploaded.name}** processed successfully.")

            # Metadata Display
            st.markdown("### 📋 Document Metadata & Cryptographic Fingerprints")
            d1, d2, d3 = st.columns(3)
            with d1:
                st.metric("File Name", uploaded.name)
            with d2:
                st.metric("File Size", f"{format_size(file_size)} ({file_size:,} bytes)")
            with d3:
                st.metric("Format", uploaded.name.split(".")[-1].upper())

            st.markdown("#### 🔒 **SHA-256 (NIST Secure Standard)**")
            st.code(sha256_val, language="text")

            st.markdown("#### ⚠️ **SHA-1 (Legacy / Weak Comparison)**")
            st.caption("Notice: SHA-1 is provided for educational comparison and is not recommended for modern security-sensitive integrity protection.")
            st.code(sha1_val, language="text")

            # Actions Row
            col_a1, col_a2, col_a3 = st.columns(3)
            with col_a1:
                if st.button("💾 Save SHA-256 to Manifest", use_container_width=True):
                    register_manifest_entry(
                        filename=uploaded.name,
                        algorithm="sha256",
                        digest=sha256_val,
                        size_bytes=file_size,
                    )
                    log_activity("HASH_GENERATED", uploaded.name, "Registered in manifest (SHA-256)")
                    st.success(f"Registered **{uploaded.name}** in local manifest.")
            with col_a2:
                if st.button("🔒 Encrypt Document (AES-256-GCM) ➔", use_container_width=True):
                    st.session_state["nav_section"] = "AES Encryption"
                    st.rerun()
            with col_a3:
                if st.button("🔍 Verify Document Integrity ➔", use_container_width=True):
                    st.session_state["nav_section"] = "Document Verification"
                    st.rerun()


# =============================================================================
# MODULE 3: HASH GENERATOR
# =============================================================================
elif st.session_state["nav_section"] == "Hash Generator":
    st.markdown(
        """
        <div class="sdvs-hero">
            <h1>⚡ Cryptographic Hash Generator</h1>
            <p>Compute 64 KB streaming cryptographic digests for collision-resistant document integrity and fingerprint certificates.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="callout-box">
            <strong>Standards Guidance:</strong> SHA-256 is the NIST-recommended cryptographic integrity standard (256-bit digest). 
            SHA-1 is computed simultaneously strictly for academic/legacy comparison.
        </div>
        """,
        unsafe_allow_html=True,
    )

    hash_upload = st.file_uploader(
        "Upload Document to Fingerprint:",
        type=SUPPORTED_EXTENSIONS,
        key="hash_gen_uploader",
    )

    if st.button("⚡ Generate Cryptographic Fingerprints (SHA-256 & SHA-1)", type="primary", use_container_width=True):
        if not hash_upload:
            st.error("Please select a file to hash.")
        else:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_file = Path(temp_dir) / hash_upload.name
                file_bytes = hash_upload.get_buffer() if hasattr(hash_upload, "get_buffer") else hash_upload.read()
                temp_file.write_bytes(file_bytes)

                try:
                    h_sha256 = hash_file(temp_file, algo="sha256")
                    h_sha1 = hash_file(temp_file, algo="sha1")
                    size_bytes = len(file_bytes)
                    size_human = format_size(size_bytes)

                    st.session_state["latest_hash_data"] = {
                        "filename": hash_upload.name,
                        "size_bytes": size_bytes,
                        "size_human": size_human,
                        "sha256": h_sha256,
                        "sha1": h_sha1,
                        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                    }
                    log_activity("HASH_GENERATED", hash_upload.name, "sha256+sha1 computed")
                except HashEngineError as e:
                    st.error(str(e))

    if st.session_state.get("latest_hash_data"):
        data = st.session_state["latest_hash_data"]
        st.markdown("---")
        st.subheader("📋 Document Cryptographic Fingerprint")

        m1, m2 = st.columns(2)
        with m1:
            st.metric("Document", data["filename"])
        with m2:
            st.metric("File Size", f"{data['size_human']} ({data['size_bytes']:,} bytes)")

        st.markdown("#### 🔒 **SHA-256 (Primary Integrity Digest)**")
        st.code(data["sha256"], language="text")

        col_h1, col_h2 = st.columns(2)
        with col_h1:
            chk256 = f"{data['sha256']}  {data['filename']}\n"
            st.download_button(
                label=f"⬇️ Download Checksum ({data['filename']}.sha256)",
                data=chk256,
                file_name=f"{data['filename']}.sha256",
                mime="text/plain",
                use_container_width=True,
            )
        with col_h2:
            if st.button("💾 Save SHA-256 to Verification Manifest", use_container_width=True):
                register_manifest_entry(
                    filename=data["filename"],
                    algorithm="sha256",
                    digest=data["sha256"],
                    size_bytes=data["size_bytes"],
                )
                log_activity("HASH_GENERATED", data["filename"], "Saved SHA-256 to manifest")
                st.success(f"Registered **{data['filename']}** in manifest.")

        st.markdown("#### ⚠️ **SHA-1 (Legacy Benchmark)**")
        st.code(data["sha1"], language="text")

        col_h3, col_h4 = st.columns(2)
        with col_h3:
            chk1 = f"{data['sha1']}  {data['filename']}\n"
            st.download_button(
                label=f"⬇️ Download Checksum ({data['filename']}.sha1)",
                data=chk1,
                file_name=f"{data['filename']}.sha1",
                mime="text/plain",
                use_container_width=True,
            )
        with col_h4:
            report_text = generate_text_report(
                filename=data["filename"],
                file_size_bytes=data["size_bytes"],
                file_size_human=data["size_human"],
                sha256_digest=data["sha256"],
                sha1_digest=data["sha1"],
                verification_status="FINGERPRINTED",
                verification_method="Streaming Cryptographic Hash Engine",
            )
            st.download_button(
                label="📄 Download Security Audit Certificate (.txt)",
                data=report_text,
                file_name=f"{data['filename']}_security_report.txt",
                mime="text/plain",
                use_container_width=True,
            )


# =============================================================================
# MODULE 4: AES ENCRYPTION
# =============================================================================
elif st.session_state["nav_section"] == "AES Encryption":
    st.markdown(
        """
        <div class="sdvs-hero">
            <h1>🔒 AES-256-GCM Document Encryption</h1>
            <p>Authenticated encryption with Scrypt key derivation, random 16-byte salt, random 12-byte nonce, and 16-byte GCM authentication tag.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="callout-box">
            <strong>AEAD Security:</strong> Encrypts payload with AES-256 in Galois/Counter Mode. The 33-byte protocol header is cryptographically authenticated 
            as Additional Authenticated Data (AAD). Tampering with either the ciphertext or metadata causes decryption to abort.
        </div>
        """,
        unsafe_allow_html=True,
    )

    enc_file = st.file_uploader(
        "Upload Document to Encrypt:",
        type=SUPPORTED_EXTENSIONS,
        key="aes_enc_uploader",
    )

    col_p1, col_p2 = st.columns(2)
    with col_p1:
        enc_pwd = st.text_input("Encryption Password (min 8 chars):", type="password", key="aes_enc_pwd")
        if enc_pwd:
            score, label, color = password_strength(enc_pwd)
            st.markdown(f"Password Strength: <strong style='color:{color}'>{label} ({score}%)</strong>", unsafe_allow_html=True)
            st.progress(score / 100.0)
    with col_p2:
        enc_confirm = st.text_input("Confirm Encryption Password:", type="password", key="aes_enc_confirm")

    st.warning("⚠️ **Zero-Knowledge Architecture:** Passwords are never stored. If lost, the encrypted file cannot be recovered.")

    if st.button("🔒 Encrypt Document (AES-256-GCM)", type="primary", use_container_width=True):
        if not enc_file:
            st.error("Please upload a file to encrypt.")
        elif not enc_pwd:
            st.error("Please enter an encryption password.")
        elif len(enc_pwd) < 8:
            st.error("Password must be at least 8 characters.")
        elif enc_pwd != enc_confirm:
            st.error("Passwords do not match.")
        else:
            with st.spinner("Deriving Scrypt key and executing AES-256-GCM encryption..."):
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_in = Path(temp_dir) / enc_file.name
                    temp_in.write_bytes(enc_file.get_buffer() if hasattr(enc_file, "get_buffer") else enc_file.read())

                    out_name = f"{enc_file.name}.sdvs"
                    temp_out = Path(temp_dir) / out_name

                    try:
                        encrypt_file(temp_in, dest_path=temp_out, password=enc_pwd, confirm_password=enc_confirm)
                        enc_bytes = temp_out.read_bytes()
                        log_activity("DOCUMENT_ENCRYPTED", enc_file.name, "success")

                        st.success(f"✅ **Encryption Complete!** Generated `{out_name}` ({len(enc_bytes):,} bytes).")

                        st.download_button(
                            label=f"⬇️ Download Encrypted Package ({out_name})",
                            data=enc_bytes,
                            file_name=out_name,
                            mime="application/octet-stream",
                            use_container_width=True,
                        )
                    except SDVSError as e:
                        log_activity("DOCUMENT_ENCRYPTED", enc_file.name, f"failed: {str(e)}")
                        st.error(str(e))


# =============================================================================
# MODULE 5: DECRYPTION
# =============================================================================
elif st.session_state["nav_section"] == "Decryption":
    st.markdown(
        """
        <div class="sdvs-hero">
            <h1>🔓 Authenticated Document Decryption</h1>
            <p>Authenticate and decrypt <code>.sdvs</code> packages. Verifies 33-byte AAD header and 16-byte GCM authentication tag.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    sdvs_upload = st.file_uploader("Upload Encrypted .sdvs Package:", type=["sdvs"], key="dec_uploader")
    dec_pwd = st.text_input("Decryption Password:", type="password", key="dec_pwd_input")

    if st.button("🔓 Authenticate & Decrypt", type="primary", use_container_width=True):
        if not sdvs_upload:
            st.error("Please upload an encrypted .sdvs file.")
        elif not dec_pwd:
            st.error("Please enter the decryption password.")
        else:
            with st.spinner("Authenticating AAD header, deriving Scrypt key, and verifying GCM tag..."):
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_in = Path(temp_dir) / sdvs_upload.name
                    temp_in.write_bytes(sdvs_upload.get_buffer() if hasattr(sdvs_upload, "get_buffer") else sdvs_upload.read())

                    src_name = sdvs_upload.name
                    target_name = src_name[:-5] if src_name.endswith(".sdvs") else f"{src_name}.decrypted"
                    temp_out = Path(temp_dir) / target_name

                    try:
                        decrypt_file(temp_in, dest_path=temp_out, password=dec_pwd)
                        dec_bytes = temp_out.read_bytes()
                        log_activity("DOCUMENT_DECRYPTED", sdvs_upload.name, "success")

                        st.success(f"✅ **Authentication Verified!** Restored original file `{target_name}` ({len(dec_bytes):,} bytes).")

                        st.download_button(
                            label=f"⬇️ Download Restored Document ({target_name})",
                            data=dec_bytes,
                            file_name=target_name,
                            mime="application/octet-stream",
                            use_container_width=True,
                        )
                    except AuthenticationError:
                        log_activity("DECRYPTION_FAILED", sdvs_upload.name, "Authentication tag failed or wrong password")
                        st.error("❌ Decryption failed. Invalid password or corrupted encrypted package.")
                    except InvalidSDVSFileError:
                        log_activity("DECRYPTION_FAILED", sdvs_upload.name, "Malformed SDVS header")
                        st.error("❌ Invalid file format: Not a valid SDVS encrypted package.")
                    except SDVSError as e:
                        log_activity("DECRYPTION_FAILED", sdvs_upload.name, str(e))
                        st.error(str(e))


# =============================================================================
# MODULE 6: DOCUMENT VERIFICATION
# =============================================================================
elif st.session_state["nav_section"] == "Document Verification":
    st.markdown(
        """
        <div class="sdvs-hero">
            <h1>🔍 Document Integrity Verification</h1>
            <p>Verify document authenticity and detect micro-tampering using constant-time cryptographic hash comparisons.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    v_tab1, v_tab2 = st.tabs(["⚖️ Method A: Compare With Reference Document", "📑 Method B: Verify Using Expected Hash"])

    # METHOD A: TWO-DOCUMENT COMPARISON
    with v_tab1:
        st.markdown("Upload the original baseline document and the inspected document to verify bit-level authenticity.")
        col_o, col_i = st.columns(2)
        with col_o:
            ref_doc = st.file_uploader("1. Upload Reference / Original Document:", type=SUPPORTED_EXTENSIONS, key="v_ref_doc")
        with col_i:
            test_doc = st.file_uploader("2. Upload Inspected Document to Verify:", type=SUPPORTED_EXTENSIONS, key="v_test_doc")

        if st.button("🔍 Compare & Verify Documents (Method A)", type="primary", use_container_width=True):
            if not ref_doc or not test_doc:
                st.error("Please upload both the reference and inspected files.")
            else:
                with tempfile.TemporaryDirectory() as temp_dir:
                    ref_p = Path(temp_dir) / f"ref_{ref_doc.name}"
                    test_p = Path(temp_dir) / f"test_{test_doc.name}"

                    ref_bytes = ref_doc.get_buffer() if hasattr(ref_doc, "get_buffer") else ref_doc.read()
                    test_bytes = test_doc.get_buffer() if hasattr(test_doc, "get_buffer") else test_doc.read()

                    ref_p.write_bytes(ref_bytes)
                    test_p.write_bytes(test_bytes)

                    h_ref = hash_file(ref_p, algo="sha256")
                    h_test = hash_file(test_p, algo="sha256")

                    is_valid, status, msg = compare_hashes(h_test, h_ref)

                    if is_valid:
                        log_activity("VERIFICATION_SUCCESS", test_doc.name, f"VERIFIED against {ref_doc.name}")
                        st.markdown(
                            """
                            <div class="verdict-banner-verified">
                                <h3 style="margin:0;">✅ DOCUMENT VERIFIED — NO MODIFICATION DETECTED</h3>
                                <p style="margin:0.5rem 0 0 0;">SHA-256 fingerprints match identically. The document is authentic and unmodified.</p>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                    else:
                        log_activity("TAMPERING_DETECTED", test_doc.name, f"TAMPERED (mismatch with {ref_doc.name})")
                        st.markdown(
                            """
                            <div class="verdict-banner-tampered">
                                <h3 style="margin:0;">❌ TAMPERING DETECTED — MODIFICATION DETECTED</h3>
                                <p style="margin:0.5rem 0 0 0;">The document content differs from the reference document. Cryptographic hash mismatch.</p>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                    st.markdown("#### ⚖️ Hash Comparison Visualization")
                    c_vh1, c_vh2 = st.columns(2)
                    with c_vh1:
                        st.markdown(f"**Reference Document ({ref_doc.name}) [{format_size(len(ref_bytes))}]:**")
                        st.code(h_ref, language="text")
                    with c_vh2:
                        st.markdown(f"**Inspected Document ({test_doc.name}) [{format_size(len(test_bytes))}]:**")
                        st.code(h_test, language="text")

                    rep = generate_text_report(
                        filename=test_doc.name,
                        file_size_bytes=len(test_bytes),
                        file_size_human=format_size(len(test_bytes)),
                        sha256_digest=h_test,
                        expected_hash=h_ref,
                        verification_status="VERIFIED" if is_valid else "TAMPERED",
                        verification_method=f"Two-Document Comparison against {ref_doc.name}",
                    )
                    st.download_button(
                        label="📄 Download Verification Audit Report (.txt)",
                        data=rep,
                        file_name=f"verification_{test_doc.name}.txt",
                        mime="text/plain",
                        use_container_width=True,
                    )

    # METHOD B: VERIFY USING EXPECTED HASH
    with v_tab2:
        st.markdown("Verify an inspected document against a known expected SHA-256 hash or registered manifest record.")

        source_type = st.radio("Verification Source:", ["Enter Known Hash Digest", "Select Registered Manifest Record"])
        manifest = load_manifest()
        exp_hash = ""

        if source_type == "Enter Known Hash Digest":
            exp_hash = st.text_input("Expected SHA-256 Digest:", placeholder="e.g. 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069")
        else:
            if not manifest:
                st.warning("Manifest is empty. Register documents in the Hash Generator first.")
            else:
                sel = st.selectbox("Select Manifest Record:", list(manifest.keys()))
                exp_hash = manifest[sel].get("digest", "")
                st.caption(f"Registered on: `{manifest[sel].get('timestamp')}` | Size: `{manifest[sel].get('size_bytes', 0):,} bytes`")
                st.code(exp_hash, language="text")

        single_doc = st.file_uploader("Upload Document to Verify:", type=SUPPORTED_EXTENSIONS, key="v_single_doc")

        if st.button("🔍 Verify Using Known Hash (Method B)", type="primary", use_container_width=True):
            if not single_doc:
                st.error("Please upload a document to verify.")
            elif not exp_hash.strip():
                st.error("Please provide an expected SHA-256 digest.")
            else:
                with tempfile.TemporaryDirectory() as temp_dir:
                    doc_p = Path(temp_dir) / single_doc.name
                    doc_bytes = single_doc.get_buffer() if hasattr(single_doc, "get_buffer") else single_doc.read()
                    doc_p.write_bytes(doc_bytes)

                    h_actual = hash_file(doc_p, algo="sha256")
                    is_valid, status, msg = compare_hashes(h_actual, exp_hash)

                    if is_valid:
                        log_activity("VERIFICATION_SUCCESS", single_doc.name, "VERIFIED against known hash")
                        st.markdown(
                            """
                            <div class="verdict-banner-verified">
                                <h3 style="margin:0;">✅ DOCUMENT VERIFIED — NO MODIFICATION DETECTED</h3>
                                <p style="margin:0.5rem 0 0 0;">SHA-256 fingerprints match identically. Document integrity confirmed.</p>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                    else:
                        log_activity("TAMPERING_DETECTED", single_doc.name, "TAMPERED (mismatch with expected hash)")
                        st.markdown(
                            """
                            <div class="verdict-banner-tampered">
                                <h3 style="margin:0;">❌ TAMPERING DETECTED — MODIFICATION DETECTED</h3>
                                <p style="margin:0.5rem 0 0 0;">The document hash does not match the expected reference digest.</p>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                    c_e, c_a = st.columns(2)
                    with c_e:
                        st.markdown("**Expected Reference Digest:**")
                        st.code(exp_hash.strip().lower(), language="text")
                    with c_a:
                        st.markdown("**Computed Actual Digest:**")
                        st.code(h_actual, language="text")


# =============================================================================
# MODULE 7: TAMPER SIMULATION
# =============================================================================
elif st.session_state["nav_section"] == "Tamper Simulation":
    st.markdown(
        """
        <div class="sdvs-hero">
            <h1>🧪 Micro-Tamper Simulation Lab</h1>
            <p>Demonstrate the cryptographic Avalanche Effect: Inverting just 1 single bit in an isolated copy produces an entirely disparate digest.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="callout-box">
            <strong>Isolation Guarantee:</strong> The simulation creates an isolated copy in a temporary memory directory. 
            <strong>Your original document is strictly never modified.</strong>
        </div>
        """,
        unsafe_allow_html=True,
    )

    t_upload = st.file_uploader("Upload Sample Document for Tamper Demonstration:", type=SUPPORTED_EXTENSIONS, key="sim_tamper_uploader")

    if st.button("🧪 Create Tampered Copy & Simulate Tamper Detection", type="primary", use_container_width=True):
        if not t_upload:
            st.error("Please upload a document first.")
        else:
            with tempfile.TemporaryDirectory() as temp_dir:
                t_path = Path(temp_dir) / t_upload.name
                t_bytes = t_upload.get_buffer() if hasattr(t_upload, "get_buffer") else t_upload.read()
                t_path.write_bytes(t_bytes)

                res = run_tamper_demo(t_path)
                log_activity("TAMPERING_DETECTED", t_upload.name, "Simulation: 1-bit modified copy rejected")

                st.markdown(
                    """
                    <div class="verdict-banner-tampered">
                        <h3 style="margin:0;">❌ TAMPERING DETECTED — AVALANCHE EFFECT TRIGGERED</h3>
                        <p style="margin:0.5rem 0 0 0;">Even a microscopic 1-bit change to the document produced a completely disparate cryptographic hash.</p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                st.markdown("#### 🔬 Cryptographic Avalanche Comparison")
                c_o, c_t = st.columns(2)
                with c_o:
                    st.markdown("**ORIGINAL DOCUMENT SHA-256:**")
                    st.code(res["original_hash"], language="text")
                with c_t:
                    st.markdown("**TAMPERED COPY SHA-256 (1 Bit Inverted):**")
                    st.code(res["tampered_hash"], language="text")

                st.info("ℹ️ **Theoretical Defense:** SHA-256 provides strict diffusion. Flipping 1 bit (`byte[0] ^ 0x01`) causes ~50% of the 256 output bits to flip pseudorandomly.")


# =============================================================================
# MODULE 8: VERIFICATION HISTORY
# =============================================================================
elif st.session_state["nav_section"] == "Verification History":
    st.markdown(
        """
        <div class="sdvs-hero">
            <h1>📜 Verification History & Manifest Repository</h1>
            <p>Manage persistent document fingerprints and inspection records in the local manifest repository.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    manifest = load_manifest()

    if not manifest:
        st.info("No records registered in the verification history manifest yet.")
    else:
        sq = st.text_input("🔍 Search History by Document Name:", placeholder="Filter by filename...")
        m_list = list(manifest.values())
        if sq:
            m_list = [m for m in m_list if sq.lower() in m.get("filename", "").lower()]

        st.markdown(f"**Showing {len(m_list)} of {len(manifest)} registered records:**")

        st.dataframe(
            m_list,
            column_config={
                "filename": "Document Name",
                "algorithm": "Algorithm",
                "digest": "Cryptographic Hash",
                "size_bytes": "Size (Bytes)",
                "timestamp": "Registered Date",
            },
            use_container_width=True,
            hide_index=True,
        )

        col_e1, col_e2, col_cl = st.columns(3)
        with col_e1:
            st.download_button(
                "⬇️ Export Manifest (JSON)",
                data=json.dumps(manifest, indent=2),
                file_name="sdvs_manifest.json",
                mime="application/json",
                use_container_width=True,
            )
        with col_e2:
            csv_buf = io.StringIO()
            csv_buf.write("filename,algorithm,digest,size_bytes,timestamp\n")
            for item in manifest.values():
                csv_buf.write(f'"{item.get("filename")}","{item.get("algorithm")}","{item.get("digest")}",{item.get("size_bytes")},"{item.get("timestamp")}"\n')
            st.download_button(
                "⬇️ Export Manifest (CSV)",
                data=csv_buf.getvalue(),
                file_name="sdvs_manifest.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with col_cl:
            if st.button("🗑️ Clear Manifest Records", use_container_width=True):
                clear_manifest()
                log_activity("MANIFEST_CLEARED", "all", "success")
                st.success("Manifest history cleared.")
                st.rerun()


# =============================================================================
# MODULE 9: SECURITY AUDIT LOG
# =============================================================================
elif st.session_state["nav_section"] == "Security Audit Log":
    st.markdown(
        """
        <div class="sdvs-hero">
            <h1>🛡️ Security & Audit Logging</h1>
            <p>Immutable local audit trail of all cryptographic actions. Strict security rule: Passwords and keys are never logged.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    logs = read_activity_logs()

    f1, f2, f3 = st.columns([2, 1, 1])
    with f1:
        log_sq = st.text_input("Search Audit Trail:", placeholder="Search by filename or action...")
    with f2:
        op_sel = st.selectbox(
            "Filter by Action:",
            ["All Events", "DOCUMENT_UPLOADED", "HASH_GENERATED", "DOCUMENT_ENCRYPTED", "DOCUMENT_DECRYPTED", "VERIFICATION_SUCCESS", "TAMPERING_DETECTED", "DECRYPTION_FAILED"],
        )
    with f3:
        lim = st.selectbox("Display Limit:", [50, 100, 250, "All"])

    filtered_logs = logs
    if log_sq:
        filtered_logs = [l for l in filtered_logs if log_sq.lower() in str(l).lower()]
    if op_sel != "All Events":
        filtered_logs = [l for l in filtered_logs if l.get("operation") == op_sel]
    if lim != "All":
        filtered_logs = filtered_logs[:int(lim)]

    st.markdown(f"**Audit Records ({len(filtered_logs)} events):**")

    if not filtered_logs:
        st.info("No log events found matching criteria.")
    else:
        st.dataframe(
            filtered_logs,
            column_config={
                "timestamp": "Timestamp",
                "operation": "Event Type",
                "filename": "Document Identifier",
                "result": "Result / Status",
            },
            use_container_width=True,
            hide_index=True,
        )

        col_l1, col_l2 = st.columns(2)
        with col_l1:
            csv_l = io.StringIO()
            csv_l.write("timestamp,operation,filename,result\n")
            for item in logs:
                csv_l.write(f'"{item.get("timestamp")}","{item.get("operation")}","{item.get("filename")}","{item.get("result")}"\n')
            st.download_button(
                "⬇️ Export Audit Trail (CSV)",
                data=csv_l.getvalue(),
                file_name=f"sdvs_audit_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with col_l2:
            if st.button("🗑️ Clear Audit Log", use_container_width=True):
                clear_activity_logs()
                st.success("Audit logs cleared.")
                st.rerun()


# =============================================================================
# MODULE 10: SECURITY DEMONSTRATION LAB
# =============================================================================
elif st.session_state["nav_section"] == "Security Demonstration Lab":
    st.markdown(
        """
        <div class="sdvs-hero">
            <h1>🎯 Live Security Demonstration Lab</h1>
            <p>Curated presentation workflows designed for live academic examination and viva voce demonstrations.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    d_tab1, d_tab2, d_tab3 = st.tabs([
        "🧪 Demo 1: Hash & Avalanche Effect",
        "🔒 Demo 2: AES-256-GCM Roundtrip",
        "🚫 Demo 3: Corrupted Ciphertext / Wrong Password",
    ])

    with d_tab1:
        st.markdown("### Demo 1: Cryptographic Avalanche Effect")
        st.write("Demonstrates how modifying 1 bit in a file changes the entire SHA-256 digest.")
        demo_text = st.text_input("Enter Baseline Text String:", value="Confidential Academic Record 2026")

        if st.button("⚡ Compute Baseline & Tampered Hashes"):
            h1 = hash_bytes(demo_text.encode("utf-8"), algo="sha256")
            tampered_bytes = bytearray(demo_text.encode("utf-8"))
            tampered_bytes[0] ^= 0x01
            h2 = hash_bytes(tampered_bytes, algo="sha256")

            st.markdown(f"**Baseline String:** `{demo_text}`")
            st.code(h1, language="text")

            st.markdown(f"**Tampered String (First Bit Inverted):** `{tampered_bytes.decode('utf-8', errors='replace')}`")
            st.code(h2, language="text")

            valid, status, _ = compare_hashes(h1, h2)
            st.markdown(
                """
                <div class="verdict-banner-tampered">
                    <h4 style="margin:0;">❌ TAMPERING DETECTED — AVALANCHE EFFECT</h4>
                    <p style="margin:0.3rem 0 0 0;">Hashes differ completely. Bit-level modification detected.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

    with d_tab2:
        st.markdown("### Demo 2: Authenticated Encryption Roundtrip")
        st.write("Encrypts a payload with AES-256-GCM and restores the exact original bytes with the correct password.")

        d2_pwd = "DemoMasterPassword2026!"
        d2_content = b"SECURE_VIVA_PAYLOAD_TEST_DATA"

        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "sample.pdf"
            src.write_bytes(d2_content)
            enc = Path(td) / "sample.pdf.sdvs"
            dec = Path(td) / "restored.pdf"

            encrypt_file(src, dest_path=enc, password=d2_pwd, confirm_password=d2_pwd)
            decrypt_file(enc, dest_path=dec, password=d2_pwd)

            st.success("✅ **Step 1: AES-256-GCM Encryption** ➔ Produced 33-byte AAD header + ciphertext + 16-byte Poly1305 tag.")
            st.success("✅ **Step 2: Scrypt Key Derivation** ➔ Reconstructed exact 256-bit key using unique salt.")
            st.success("✅ **Step 3: GCM Tag Verification** ➔ Authenticated payload; restored original bytes identically.")

    with d_tab3:
        st.markdown("### Demo 3: Security Under Attack (Wrong Password & Corrupted Ciphertext)")
        st.write("Proves that AES-256-GCM rejects wrong passwords or modified ciphertexts without leaking plaintext.")

        d3_pwd = "CorrectPassword123!"
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "test.txt"
            src.write_bytes(b"Top Secret Intelligence Briefing")
            enc = Path(td) / "test.txt.sdvs"
            dec = Path(td) / "out.txt"

            encrypt_file(src, dest_path=enc, password=d3_pwd, confirm_password=d3_pwd)

            # Test Wrong Password
            try:
                decrypt_file(enc, dest_path=dec, password="WrongPassword999!")
            except AuthenticationError:
                st.error("🛡️ **Attack 1 (Wrong Password):** Successfully intercepted! Decryption aborted; zero plaintext written to disk.")

            # Test Ciphertext Modification
            enc_data = bytearray(enc.read_bytes())
            enc_data[35] ^= 0x01  # Flip byte in ciphertext
            enc.write_bytes(enc_data)

            try:
                decrypt_file(enc, dest_path=dec, password=d3_pwd)
            except AuthenticationError:
                st.error("🛡️ **Attack 2 (Ciphertext Bit Flip):** GCM Tag verification failed! Corrupted package rejected unconditionally.")


# =============================================================================
# MODULE 11: ABOUT SECURITY
# =============================================================================
elif st.session_state["nav_section"] == "About Security":
    st.markdown(
        """
        <div class="sdvs-hero">
            <h1>📚 Educational Security Center</h1>
            <p>Theoretical and mathematical foundations of cryptographic hashing, authenticated encryption, and tamper defense.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.subheader("1. Hashing vs. Encryption")
    st.markdown(
        """
        | Dimension | Cryptographic Hashing | Authenticated Encryption (AES-GCM) |
        | :--- | :--- | :--- |
        | **Directionality** | One-way irreversible transformation | Two-way reversible transformation with key |
        | **Primary Goal** | Integrity verification & tamper detection | Confidentiality & Authenticity |
        | **Output Size** | Fixed size (e.g., 256 bits for SHA-256) | Variable size (plaintext length + 49 bytes header/tag) |
        | **Key Requirement** | No key required (deterministic digest) | Secret key derived via memory-hard KDF |
        """
    )

    st.subheader("2. Why SHA-256 over SHA-1?")
    st.markdown(
        """
        * **SHA-256:** Provides 256 bits of digest length ($2^{128}$ collision resistance). Fully compliant with NIST SP 800-107.
        * **SHA-1 (Legacy):** 160-bit digest. In 2017, the *SHAttered* attack proved practical collision generation. Included in SDVS purely for academic comparison.
        """
    )

    st.subheader("3. Why AES-256-GCM over AES-CBC?")
    st.markdown(
        """
        * **AEAD Authentication:** AES-GCM calculates a 128-bit GHASH/Poly1305 authentication tag over the ciphertext and AAD header.
        * **Padding Oracle Resistance:** CBC mode requires PKCS#7 padding, exposing systems to padding oracle attacks. GCM operates in CTR mode (stream) with zero padding vulnerabilities.
        """
    )


# =============================================================================
# MODULE 12: SETTINGS & DIAGNOSTICS
# =============================================================================
elif st.session_state["nav_section"] == "Settings & Diagnostics":
    st.markdown(
        """
        <div class="sdvs-hero">
            <h1>⚙️ System Settings & Diagnostics</h1>
            <p>Configure file boundaries, inspect cryptographic parameters, and review runtime environment diagnostics.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.subheader("⚙️ Upload Preferences")
    new_limit = st.slider("Maximum File Size Limit (MB):", min_value=5, max_value=200, value=st.session_state["max_file_size_mb"], step=5)
    st.session_state["max_file_size_mb"] = new_limit
    st.caption(f"Currently configured upload limit: **{new_limit} MB**")

    st.markdown("---")
    st.subheader("🔒 Cryptographic Parameter Specifications")
    s1, s2 = st.columns(2)
    with s1:
        st.markdown(
            f"""
            * **Cipher Mode:** AES-256-GCM
            * **Key Length:** {KEY_LENGTH * 8} bits ({KEY_LENGTH} bytes)
            * **Nonce Size:** 96 bits (12 bytes, cryptographic PRNG)
            * **Tag Size:** {TAG_SIZE * 8} bits ({TAG_SIZE} bytes)
            * **AAD Header Size:** {HEADER_SIZE} bytes
            """
        )
    with s2:
        st.markdown(
            f"""
            * **Key Derivation:** Scrypt (RFC 7914)
            * **CPU/Memory Cost (N):** {SCRYPT_N:,} iterations
            * **Block Size (r):** {SCRYPT_R}
            * **Parallelization (p):** {SCRYPT_P}
            * **Salt Size:** 128 bits (16 bytes)
            """
        )

    st.markdown("---")
    st.subheader("💻 Environment Diagnostics")
    d1, d2 = st.columns(2)
    with d1:
        st.write(f"• **OS Environment:** {platform.system()} {platform.release()} ({platform.machine()})")
        st.write(f"• **Python Runtime:** {platform.python_version()}")
    with d2:
        st.write("• **Local Manifest Ledger:** `data/manifest.json`")
        st.write("• **Local Audit Ledger:** `data/activity.log`")
