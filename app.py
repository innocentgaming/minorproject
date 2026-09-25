"""Secure Document Verification System (SDVS) - Streamlit Application.

A production-grade, local cryptographic document security suite supporting:
PDF, DOCX, DOC, TXT, JPG, PNG, XLSX, ZIP, and generic binaries.

Modules:
1. Dashboard: Security metrics, health indicators, quick operations.
2. Document Encryption: AES-256-GCM + Scrypt KDF authenticated encryption/decryption.
3. Hash Generator: SHA-256 & SHA-1 fingerprinting with checksum downloads.
4. Document Verification: Two-Document comparison, Manifest checking, 1-bit Tamper Lab.
5. Verification History: Manifest record repository, live search, JSON/CSV exports.
6. Security Logs: Real-time immutable audit trail with filters and CSV export.
7. Settings: Cryptographic parameters, storage inspector, and system diagnostics.
"""

import io
import json
import os
import platform
import tempfile
from datetime import datetime
from pathlib import Path

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

# -----------------------------------------------------------------------------
# Supported Document Formats
# -----------------------------------------------------------------------------
SUPPORTED_EXTENSIONS = ["pdf", "docx", "doc", "txt", "jpg", "jpeg", "png", "xlsx", "xls", "zip"]
FORMAT_BADGES_HTML = """
<div style="display: flex; flex-wrap: wrap; gap: 0.4rem; margin: 0.6rem 0 1rem 0;">
    <span style="background:#E2E8F0; color:#1E293B; padding:0.2rem 0.6rem; border-radius:6px; font-size:0.8rem; font-weight:600;">📄 PDF</span>
    <span style="background:#E2E8F0; color:#1E293B; padding:0.2rem 0.6rem; border-radius:6px; font-size:0.8rem; font-weight:600;">📝 DOCX / DOC</span>
    <span style="background:#E2E8F0; color:#1E293B; padding:0.2rem 0.6rem; border-radius:6px; font-size:0.8rem; font-weight:600;">📋 TXT</span>
    <span style="background:#E2E8F0; color:#1E293B; padding:0.2rem 0.6rem; border-radius:6px; font-size:0.8rem; font-weight:600;">🖼️ JPG / JPEG</span>
    <span style="background:#E2E8F0; color:#1E293B; padding:0.2rem 0.6rem; border-radius:6px; font-size:0.8rem; font-weight:600;">🎨 PNG</span>
    <span style="background:#E2E8F0; color:#1E293B; padding:0.2rem 0.6rem; border-radius:6px; font-size:0.8rem; font-weight:600;">📊 XLSX / XLS</span>
    <span style="background:#E2E8F0; color:#1E293B; padding:0.2rem 0.6rem; border-radius:6px; font-size:0.8rem; font-weight:600;">📦 ZIP</span>
    <span style="background:#F1F5F9; color:#64748B; padding:0.2rem 0.6rem; border-radius:6px; font-size:0.8rem;">+ Any Binary</span>
</div>
"""

# -----------------------------------------------------------------------------
# Streamlit Page Configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="SDVS - Secure Document Verification System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# Custom CSS for Cybersecurity Aesthetics
# -----------------------------------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    .code, code, pre, .hash-code {
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    .app-header {
        background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 1.5rem 1.8rem;
        margin-bottom: 1.5rem;
        color: #F8FAFC;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    .app-header h1 {
        font-size: 1.8rem;
        font-weight: 700;
        margin: 0 0 0.3rem 0;
        color: #FFFFFF;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    .app-header p {
        font-size: 0.95rem;
        color: #94A3B8;
        margin: 0;
    }
    
    .sdvs-stat-card {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 1.2rem;
        text-align: center;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        transition: transform 0.15s ease, box-shadow 0.15s ease;
    }
    .sdvs-stat-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.08);
    }
    .sdvs-stat-val {
        font-size: 1.9rem;
        font-weight: 700;
        color: #0F172A;
        margin-bottom: 0.2rem;
    }
    .sdvs-stat-label {
        font-size: 0.82rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #64748B;
    }
    
    .verified-box {
        background-color: #F0FDF4;
        border: 2px solid #22C55E;
        border-radius: 10px;
        padding: 1.4rem;
        color: #14532D;
        margin-top: 1rem;
        margin-bottom: 1rem;
    }
    .modified-box {
        background-color: #FEF2F2;
        border: 2px solid #EF4444;
        border-radius: 10px;
        padding: 1.4rem;
        color: #7F1D1D;
        margin-top: 1rem;
        margin-bottom: 1rem;
    }
    
    .info-panel {
        background: #F8FAFC;
        border-left: 4px solid #0284C7;
        border-radius: 0 8px 8px 0;
        padding: 1rem 1.2rem;
        margin-bottom: 1.2rem;
        color: #334155;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# -----------------------------------------------------------------------------
# Initialize Session State
# -----------------------------------------------------------------------------
if "nav_section" not in st.session_state:
    st.session_state["nav_section"] = "Dashboard"

if "latest_hash" not in st.session_state:
    st.session_state["latest_hash"] = None

if "default_algo" not in st.session_state:
    st.session_state["default_algo"] = "SHA-256"

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
def get_stats():
    """Computes high-level usage stats from manifest and logs."""
    manifest = load_manifest()
    logs = read_activity_logs()
    
    enc_count = sum(1 for log in logs if log.get("operation") == "encrypt" and "success" in log.get("result", ""))
    dec_count = sum(1 for log in logs if log.get("operation") == "decrypt" and "success" in log.get("result", ""))
    hash_count = sum(1 for log in logs if log.get("operation") == "hash")
    verify_count = sum(1 for log in logs if log.get("operation") == "verify")
    manifest_count = len(manifest)
    
    return {
        "manifest_count": manifest_count,
        "enc_count": enc_count,
        "dec_count": dec_count,
        "hash_count": hash_count,
        "verify_count": verify_count,
        "total_logs": len(logs),
    }

def password_strength(pwd: str) -> tuple[int, str, str]:
    """Evaluates password strength and returns (score 0-100, label, color)."""
    if not pwd:
        return 0, "Empty", "#94A3B8"
    
    score = 0
    if len(pwd) >= 8:
        score += 30
    if len(pwd) >= 12:
        score += 20
    if any(c.isupper() for c in pwd):
        score += 15
    if any(c.isdigit() for c in pwd):
        score += 15
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd):
        score += 20
        
    if score < 40:
        return score, "Weak", "#EF4444"
    elif score < 75:
        return score, "Moderate", "#F59E0B"
    else:
        return score, "Strong", "#10B981"

# -----------------------------------------------------------------------------
# Sidebar Navigation
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🛡️ **SDVS Menu**")
    
    nav_options = [
        "📊 Dashboard",
        "🔒 Document Encryption",
        "⚡ Hash Generator",
        "🔍 Document Verification",
        "📜 Verification History",
        "🛡️ Security Logs",
        "⚙️ Settings",
    ]
    
    nav_map = {
        "📊 Dashboard": "Dashboard",
        "🔒 Document Encryption": "Document Encryption",
        "⚡ Hash Generator": "Hash Generator",
        "🔍 Document Verification": "Document Verification",
        "📜 Verification History": "Verification History",
        "🛡️ Security Logs": "Security Logs",
        "⚙️ Settings": "Settings",
    }
    
    current_key = st.session_state["nav_section"]
    current_idx = 0
    for idx, opt in enumerate(nav_options):
        if nav_map[opt] == current_key:
            current_idx = idx
            break
            
    selected_nav = st.radio(
        "Go to Module:",
        nav_options,
        index=current_idx,
        key="sidebar_nav_radio",
        label_visibility="collapsed",
    )
    
    st.session_state["nav_section"] = nav_map[selected_nav]
    
    st.markdown("---")
    st.markdown("#### 🔒 **Supported Formats**")
    st.caption("PDF, DOCX, DOC, TXT, JPG, PNG, XLSX, ZIP")
    
    st.markdown("---")
    st.markdown("#### ⚙️ **Security Engine**")
    st.caption("• **Cipher:** AES-256-GCM (Authenticated)")
    st.caption("• **KDF:** Scrypt (N=32768, r=8, p=1)")
    st.caption("• **Hashing:** SHA-256 (NIST standard)")
    st.caption("• **Comparison:** Constant-time `hmac.compare_digest`")
    
    st.markdown("---")
    stats = get_stats()
    st.caption(f"📁 Manifest: **{stats['manifest_count']}** files")
    st.caption(f"📝 Audit Logs: **{stats['total_logs']}** records")


# -----------------------------------------------------------------------------
# MODULE 1: DASHBOARD
# -----------------------------------------------------------------------------
if st.session_state["nav_section"] == "Dashboard":
    st.markdown(
        """
        <div class="app-header">
            <h1>🛡️ Secure Document Verification System</h1>
            <p>Cryptographic integrity verification, AES-256-GCM confidentiality suite, and tamper audit defense.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    # Supported Formats Banner
    st.markdown("**Supported Document Types:**")
    st.markdown(FORMAT_BADGES_HTML, unsafe_allow_html=True)
    
    # Stats row
    stats = get_stats()
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f"""
            <div class="sdvs-stat-card">
                <div class="sdvs-stat-val">🔒 {stats['enc_count']}</div>
                <div class="sdvs-stat-label">Files Encrypted</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"""
            <div class="sdvs-stat-card">
                <div class="sdvs-stat-val">⚡ {stats['hash_count']}</div>
                <div class="sdvs-stat-label">Hashes Computed</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f"""
            <div class="sdvs-stat-card">
                <div class="sdvs-stat-val">🔍 {stats['verify_count']}</div>
                <div class="sdvs-stat-label">Verifications Run</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            f"""
            <div class="sdvs-stat-card">
                <div class="sdvs-stat-val">📜 {stats['manifest_count']}</div>
                <div class="sdvs-stat-label">Manifest Records</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Quick Action Cards
    st.subheader("⚡ Quick Operations")
    q1, q2, q3 = st.columns(3)
    with q1:
        st.markdown("#### 🔒 Confidentiality")
        st.write("Encrypt documents (PDF, DOCX, XLSX, TXT, images, ZIP) with AES-256-GCM authenticated encryption.")
        if st.button("Open Document Encryption ➔", use_container_width=True):
            st.session_state["nav_section"] = "Document Encryption"
            st.rerun()
            
    with q2:
        st.markdown("#### ⚡ Fingerprinting")
        st.write("Compute collision-resistant SHA-256 cryptographic digests and export checksum files.")
        if st.button("Open Hash Generator ➔", use_container_width=True):
            st.session_state["nav_section"] = "Hash Generator"
            st.rerun()
            
    with q3:
        st.markdown("#### 🔍 Integrity Verification")
        st.write("Perform dual-document comparison or manifest checking with constant-time verification.")
        if st.button("Open Document Verification ➔", use_container_width=True):
            st.session_state["nav_section"] = "Document Verification"
            st.rerun()
            
    st.markdown("---")
    
    # Architecture & Recent events
    col_arch, col_recent = st.columns([1, 1])
    with col_arch:
        st.subheader("🛡️ Security Architecture")
        st.markdown(
            """
            * **Universal File Support:** Stream processing in 64 KB chunks handles arbitrary sizes and formats (PDF, DOCX, XLSX, TXT, JPG, PNG, ZIP, etc.).
            * **Zero Data Leakage:** All cryptographic transformations run purely on local hardware. No file or secret leaves your device.
            * **Authenticated Encryption (AEAD):** AES-GCM ensures both confidentiality and integrity with 16-byte Poly1305/GHASH authentication tags.
            * **Side-Channel Timing Protection:** Uses `hmac.compare_digest` to prevent timing attacks during hash comparisons.
            * **Brute-Force Hardening:** Scrypt KDF parameters (N=32768, r=8, p=1) thwart GPU/ASIC password cracking attempts.
            """
        )
    
    with col_recent:
        st.subheader("📋 Recent Security Events")
        recent_logs = read_activity_logs(limit=5)
        if not recent_logs:
            st.info("No activity records logged yet.")
        else:
            for log in recent_logs:
                op_icon = {
                    "encrypt": "🔒",
                    "decrypt": "🔓",
                    "hash": "⚡",
                    "verify": "🔍",
                    "manifest_save": "💾",
                    "tamper_demo": "🧪",
                }.get(log["operation"], "📌")
                
                st.markdown(
                    f"**{op_icon} {log['operation'].upper()}** &nbsp;|&nbsp; `{log['filename']}` &nbsp;|&nbsp; "
                    f"<span style='color:#64748B; font-size:0.85rem;'>{log['timestamp']}</span>",
                    unsafe_allow_html=True,
                )
                st.caption(f"Result: `{log['result']}`")


# -----------------------------------------------------------------------------
# MODULE 2: DOCUMENT ENCRYPTION
# -----------------------------------------------------------------------------
elif st.session_state["nav_section"] == "Document Encryption":
    st.markdown(
        """
        <div class="app-header">
            <h1>🔒 Document Encryption & Decryption</h1>
            <p>Authenticated AES-256-GCM cipher with Scrypt key derivation. Rejects tampered files and enforces confidentiality.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    enc_tab, dec_tab = st.tabs(["🔒 Encrypt Document", "🔓 Decrypt Document"])
    
    # TAB: ENCRYPT
    with enc_tab:
        st.markdown(
            """
            <div class="info-panel">
                <strong>Standard:</strong> AES-256-GCM authenticated encryption (32-byte key, 16-byte random salt, 12-byte random nonce, 33-byte AAD header).
            </div>
            """,
            unsafe_allow_html=True,
        )
        
        st.markdown("**Supported Document Formats:**")
        st.markdown(FORMAT_BADGES_HTML, unsafe_allow_html=True)
        
        uploaded_file = st.file_uploader(
            "Upload Document to Encrypt (PDF, DOCX, DOC, TXT, JPG, PNG, XLSX, ZIP, etc.):",
            type=SUPPORTED_EXTENSIONS,
            key="enc_file_uploader",
        )
        
        col_p1, col_p2 = st.columns(2)
        with col_p1:
            enc_pwd = st.text_input("Encryption Password:", type="password", key="enc_password_input")
            if enc_pwd:
                score, label, color = password_strength(enc_pwd)
                st.markdown(
                    f"Password Strength: <strong style='color:{color}'>{label} ({score}%)</strong>",
                    unsafe_allow_html=True,
                )
                st.progress(score / 100.0)
        with col_p2:
            enc_confirm = st.text_input("Confirm Encryption Password:", type="password", key="enc_confirm_input")
            
        st.warning("⚠️ **Crucial Notice:** SDVS uses zero-knowledge local cryptography. If you lose this password, the file cannot be decrypted.")
        
        if st.button("🔒 Encrypt Document (AES-256-GCM)", type="primary", use_container_width=True):
            if not uploaded_file:
                st.error("Please upload a file to encrypt.")
            elif not enc_pwd:
                st.error("Please enter a password.")
            elif len(enc_pwd) < 8:
                st.error("Use at least 8 characters for the password.")
            elif enc_pwd != enc_confirm:
                st.error("Passwords don't match.")
            else:
                with st.spinner("Deriving Scrypt key & encrypting via AES-256-GCM..."):
                    with tempfile.TemporaryDirectory() as temp_dir:
                        temp_in = Path(temp_dir) / uploaded_file.name
                        temp_in.write_bytes(uploaded_file.get_buffer() if hasattr(uploaded_file, "get_buffer") else uploaded_file.read())
                        
                        out_filename = f"{uploaded_file.name}.sdvs"
                        temp_out = Path(temp_dir) / out_filename
                        
                        try:
                            encrypt_file(temp_in, dest_path=temp_out, password=enc_pwd, confirm_password=enc_confirm)
                            encrypted_bytes = temp_out.read_bytes()
                            log_activity("encrypt", uploaded_file.name, "success")
                            
                            st.success(f"✅ **Encryption Complete!** Generated `{out_filename}` ({len(encrypted_bytes):,} bytes).")
                            
                            st.download_button(
                                label=f"⬇️ Download Encrypted File ({out_filename})",
                                data=encrypted_bytes,
                                file_name=out_filename,
                                mime="application/octet-stream",
                                use_container_width=True,
                            )
                        except SDVSError as e:
                            log_activity("encrypt", uploaded_file.name, f"failed: {str(e)}")
                            st.error(str(e))
                        except Exception:
                            log_activity("encrypt", uploaded_file.name, "failed: internal error")
                            st.error("Couldn't open the file.")
                            
    # TAB: DECRYPT
    with dec_tab:
        st.markdown(
            """
            <div class="info-panel">
                <strong>Authentication Check:</strong> Decrypts <code>.sdvs</code> files by verifying the 33-byte AAD header and 16-byte Poly1305/GCM tag.
            </div>
            """,
            unsafe_allow_html=True,
        )
        
        sdvs_upload = st.file_uploader(
            "Upload Encrypted .sdvs File:",
            type=["sdvs"],
            key="dec_file_uploader",
        )
        
        dec_pwd = st.text_input("Decryption Password:", type="password", key="dec_password_input")
        
        if st.button("🔓 Authenticate & Decrypt", type="primary", use_container_width=True):
            if not sdvs_upload:
                st.error("Please upload an encrypted .sdvs file.")
            elif not dec_pwd:
                st.error("Please enter the decryption password.")
            else:
                with st.spinner("Verifying AAD header and Poly1305/GCM authentication tag..."):
                    with tempfile.TemporaryDirectory() as temp_dir:
                        temp_in = Path(temp_dir) / sdvs_upload.name
                        temp_in.write_bytes(sdvs_upload.get_buffer() if hasattr(sdvs_upload, "get_buffer") else sdvs_upload.read())
                        
                        src_name = sdvs_upload.name
                        if src_name.endswith(".sdvs"):
                            target_name = src_name[:-5]
                        else:
                            target_name = f"{src_name}.decrypted"
                            
                        temp_out = Path(temp_dir) / target_name
                        
                        try:
                            decrypt_file(temp_in, dest_path=temp_out, password=dec_pwd)
                            decrypted_bytes = temp_out.read_bytes()
                            log_activity("decrypt", sdvs_upload.name, "success")
                            
                            st.success(f"✅ **Decryption & Authentication Verified!** Restored `{target_name}` ({len(decrypted_bytes):,} bytes).")
                            
                            st.download_button(
                                label=f"⬇️ Download Restored File ({target_name})",
                                data=decrypted_bytes,
                                file_name=target_name,
                                mime="application/octet-stream",
                                use_container_width=True,
                            )
                        except AuthenticationError:
                            log_activity("decrypt", sdvs_upload.name, "failed: Wrong password or file was modified")
                            st.error("❌ Authentication Failed: Wrong password or file was modified.")
                        except InvalidSDVSFileError:
                            log_activity("decrypt", sdvs_upload.name, "failed: Not a valid SDVS file")
                            st.error("❌ Invalid Format: Not a valid SDVS file header.")
                        except SDVSError as e:
                            log_activity("decrypt", sdvs_upload.name, f"failed: {str(e)}")
                            st.error(str(e))
                        except Exception:
                            log_activity("decrypt", sdvs_upload.name, "failed: file error")
                            st.error("Couldn't open the file.")


# -----------------------------------------------------------------------------
# MODULE 3: HASH GENERATOR
# -----------------------------------------------------------------------------
elif st.session_state["nav_section"] == "Hash Generator":
    st.markdown(
        """
        <div class="app-header">
            <h1>⚡ Cryptographic Hash Generator</h1>
            <p>Generate collision-resistant SHA-256 & SHA-1 document fingerprints with streaming 64 KB chunk buffers.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    st.markdown("**Supported Document Formats:**")
    st.markdown(FORMAT_BADGES_HTML, unsafe_allow_html=True)
    
    hash_upload = st.file_uploader(
        "Upload Document to Fingerprint (PDF, DOCX, DOC, TXT, JPG, PNG, XLSX, ZIP, etc.):",
        type=SUPPORTED_EXTENSIONS,
        key="gen_hash_uploader",
    )
    
    col_alg, col_info = st.columns([1, 1])
    with col_alg:
        algo_choice = st.selectbox(
            "Select Hash Algorithm:",
            ["SHA-256 (NIST standard, recommended)", "SHA-1 (Legacy / Weak)"],
            index=0 if st.session_state["default_algo"] == "SHA-256" else 1,
        )
        selected_algo = "sha256" if "SHA-256" in algo_choice else "sha1"
        
    with col_info:
        if selected_algo == "sha1":
            st.warning("⚠️ **Cryptographic Warning:** SHA-1 is vulnerable to collision attacks (SHAttered). Recommended only for legacy hash validation.")
        else:
            st.info("ℹ️ **SHA-256:** 256-bit digest providing 128 bits of security against collision attacks.")
            
    if st.button("⚡ Generate Cryptographic Hash", type="primary", use_container_width=True):
        if not hash_upload:
            st.error("Please upload a file to hash.")
        else:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_file = Path(temp_dir) / hash_upload.name
                file_bytes = hash_upload.get_buffer() if hasattr(hash_upload, "get_buffer") else hash_upload.read()
                temp_file.write_bytes(file_bytes)
                
                try:
                    digest = hash_file(temp_file, algo=selected_algo)
                    st.session_state["latest_hash"] = {
                        "filename": hash_upload.name,
                        "algorithm": selected_algo,
                        "digest": digest,
                        "size_bytes": len(file_bytes),
                    }
                    log_activity("hash", hash_upload.name, selected_algo)
                except HashEngineError as e:
                    st.error(str(e))
                except Exception:
                    st.error("Couldn't open the file.")
                    
    # Display Hash Output
    if st.session_state.get("latest_hash"):
        res = st.session_state["latest_hash"]
        st.markdown("---")
        st.subheader("📋 Document Cryptographic Fingerprint")
        
        m1, m2, m3 = st.columns(3)
        with m1:
            st.metric("Filename", res["filename"])
        with m2:
            st.metric("File Size", f"{res['size_bytes']:,} bytes")
        with m3:
            st.metric("Algorithm", res["algorithm"].upper())
            
        st.markdown("**Hexadecimal Digest:**")
        st.code(res["digest"], language="text")
        
        # Download and Manifest options
        d_col1, d_col2 = st.columns(2)
        with d_col1:
            checksum_text = f"{res['digest']}  {res['filename']}\n"
            checksum_filename = f"{res['filename']}.{res['algorithm']}"
            st.download_button(
                label=f"⬇️ Download Checksum File ({checksum_filename})",
                data=checksum_text,
                file_name=checksum_filename,
                mime="text/plain",
                use_container_width=True,
            )
        with d_col2:
            if st.button("💾 Save to Verification Manifest", use_container_width=True):
                register_manifest_entry(
                    filename=res["filename"],
                    algorithm=res["algorithm"],
                    digest=res["digest"],
                    size_bytes=res["size_bytes"],
                )
                log_activity("manifest_save", res["filename"], f"saved {res['algorithm']}")
                st.success(f"✅ Registered **{res['filename']}** to local manifest!")


# -----------------------------------------------------------------------------
# MODULE 4: DOCUMENT VERIFICATION
# -----------------------------------------------------------------------------
elif st.session_state["nav_section"] == "Document Verification":
    st.markdown(
        """
        <div class="app-header">
            <h1>🔍 Document Verification & Tamper Detection</h1>
            <p>Compare original vs received files, verify against registered manifest entries, or test 1-bit tamper resilience.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    st.markdown("**Supported Document Formats:**")
    st.markdown(FORMAT_BADGES_HTML, unsafe_allow_html=True)
    
    v_tab_two, v_tab_manifest, v_tab_tamper = st.tabs([
        "⚖️ Direct Two-Document Comparison",
        "📑 Manifest / Hash Verification",
        "🧪 1-Bit Tamper Simulation Lab",
    ])
    
    # 1. DIRECT TWO-DOCUMENT COMPARISON
    with v_tab_two:
        st.markdown("Compare the original master file against a received file to verify integrity.")
        col_orig, col_test = st.columns(2)
        with col_orig:
            file_orig = st.file_uploader(
                "1. Upload Original / Baseline Document:",
                type=SUPPORTED_EXTENSIONS,
                key="v_file_orig",
            )
        with col_test:
            file_test = st.file_uploader(
                "2. Upload Received / Inspected Document:",
                type=SUPPORTED_EXTENSIONS,
                key="v_file_test",
            )
            
        v_algo = st.selectbox("Verification Algorithm:", ["SHA-256", "SHA-1"], key="two_doc_algo")
        v_algo_key = "sha256" if v_algo == "SHA-256" else "sha1"
        
        if st.button("🔍 Compare & Verify Documents", type="primary", use_container_width=True):
            if not file_orig or not file_test:
                st.error("Please upload both the original and inspected files.")
            else:
                with tempfile.TemporaryDirectory() as temp_dir:
                    orig_path = Path(temp_dir) / f"orig_{file_orig.name}"
                    test_path = Path(temp_dir) / f"test_{file_test.name}"
                    
                    orig_bytes = file_orig.get_buffer() if hasattr(file_orig, "get_buffer") else file_orig.read()
                    test_bytes = file_test.get_buffer() if hasattr(file_test, "get_buffer") else file_test.read()
                    
                    orig_path.write_bytes(orig_bytes)
                    test_path.write_bytes(test_bytes)
                    
                    hash_orig = hash_file(orig_path, algo=v_algo_key)
                    hash_test = hash_file(test_path, algo=v_algo_key)
                    
                    is_valid, status, message = compare_hashes(hash_test, hash_orig)
                    log_activity("verify", file_test.name, f"{status} (compared with {file_orig.name})")
                    
                    if is_valid:
                        st.markdown(
                            f"""
                            <div class="verified-box">
                                <h3 style="margin:0; color:#14532D;">✅ VERIFIED — FILE IS AUTHENTIC</h3>
                                <p style="margin:0.5rem 0 0 0;">Cryptographic digests match identically. No unauthorized modifications or corruption detected.</p>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                    else:
                        st.markdown(
                            f"""
                            <div class="modified-box">
                                <h3 style="margin:0; color:#7F1D1D;">❌ MODIFIED — INTEGRITY COMPROMISED</h3>
                                <p style="margin:0.5rem 0 0 0;">The inspected file's cryptographic hash does not match the original. The document was tampered with or corrupted.</p>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                        
                    st.markdown("#### Detailed Hash Inspection")
                    c_h1, c_h2 = st.columns(2)
                    with c_h1:
                        st.markdown(f"**Original ({file_orig.name}) [{len(orig_bytes):,} bytes]:**")
                        st.code(hash_orig, language="text")
                    with c_h2:
                        st.markdown(f"**Inspected ({file_test.name}) [{len(test_bytes):,} bytes]:**")
                        st.code(hash_test, language="text")
                        
    # 2. MANIFEST & HASH VERIFICATION
    with v_tab_manifest:
        verify_upload = st.file_uploader(
            "Upload File to Inspect:",
            type=SUPPORTED_EXTENSIONS,
            key="manifest_v_upload",
        )
        
        mode_choice = st.radio(
            "Verification Source:",
            ["Option A: Match with Registered Manifest Record", "Option B: Enter Expected Hash String"],
        )
        
        manifest_data = load_manifest()
        expected_hash = ""
        expected_algo = "sha256"
        
        if "Option A" in mode_choice:
            if not manifest_data:
                st.warning("Manifest is empty. Fingerprint a document in the Hash Generator and save it first.")
            else:
                options = list(manifest_data.keys())
                def_idx = 0
                if verify_upload and verify_upload.name in options:
                    def_idx = options.index(verify_upload.name)
                    
                selected_entry = st.selectbox("Select Manifest Record:", options, index=def_idx)
                rec = manifest_data[selected_entry]
                expected_hash = rec.get("digest", "")
                expected_algo = rec.get("algorithm", "sha256")
                
                st.caption(f"Registered on: `{rec.get('timestamp')}` | Size: `{rec.get('size_bytes', 0):,} bytes` | Algorithm: `{expected_algo.upper()}`")
                st.code(expected_hash, language="text")
        else:
            expected_hash = st.text_input("Expected Hash Digest:", placeholder="Paste expected 64-char SHA-256 or 40-char SHA-1 hex...")
            p_algo = st.selectbox("Expected Algorithm:", ["SHA-256", "SHA-1"])
            expected_algo = "sha256" if p_algo == "SHA-256" else "sha1"
            
        if st.button("🔍 Verify Integrity (Constant-Time)", type="primary", use_container_width=True):
            if not verify_upload:
                st.error("Please upload a file to verify.")
            elif not expected_hash.strip():
                st.error("Please select or paste an expected hash.")
            else:
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_file = Path(temp_dir) / verify_upload.name
                    temp_file.write_bytes(verify_upload.get_buffer() if hasattr(verify_upload, "get_buffer") else verify_upload.read())
                    
                    try:
                        actual_digest = hash_file(temp_file, algo=expected_algo)
                        is_valid, status, message = compare_hashes(actual_digest, expected_hash)
                        log_activity("verify", verify_upload.name, status)
                        
                        if is_valid:
                            st.markdown(
                                f"""
                                <div class="verified-box">
                                    <h3 style="margin:0; color:#14532D;">✅ VERIFIED</h3>
                                    <p style="margin:0.5rem 0 0 0;">{message}</p>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                        else:
                            st.markdown(
                                f"""
                                <div class="modified-box">
                                    <h3 style="margin:0; color:#7F1D1D;">❌ MODIFIED</h3>
                                    <p style="margin:0.5rem 0 0 0;">{message}</p>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                            
                        c_e, c_a = st.columns(2)
                        with c_e:
                            st.markdown("**Expected Hash:**")
                            st.code(expected_hash.strip().lower(), language="text")
                        with c_a:
                            st.markdown("**Computed Actual Hash:**")
                            st.code(actual_digest, language="text")
                    except Exception as e:
                        st.error(f"Verification error: {str(e)}")
                        
    # 3. TAMPER LAB
    with v_tab_tamper:
        st.markdown(
            """
            <div class="info-panel">
                <strong>Avalanche Effect Demonstration:</strong> Flips exactly <strong>1 single bit</strong> (XOR 1 of byte 0) in an isolated copy of your file to prove that even microscopic changes produce entirely disparate hashes. Original file is never touched.
            </div>
            """,
            unsafe_allow_html=True,
        )
        
        tamper_file = st.file_uploader(
            "Upload Sample Document for 1-Bit Tamper Test:",
            type=SUPPORTED_EXTENSIONS,
            key="tamper_demo_uploader",
        )
        if st.button("🧪 Execute 1-Bit Tamper Test", type="primary"):
            if not tamper_file:
                st.error("Please select a file first.")
            else:
                with tempfile.TemporaryDirectory() as temp_dir:
                    t_path = Path(temp_dir) / tamper_file.name
                    t_path.write_bytes(tamper_file.get_buffer() if hasattr(tamper_file, "get_buffer") else tamper_file.read())
                    
                    res = run_tamper_demo(t_path)
                    log_activity("tamper_demo", tamper_file.name, "MODIFIED")
                    
                    st.markdown(
                        f"""
                        <div class="modified-box">
                            <h4 style="margin:0; color:#7F1D1D;">⚠️ {res['status']} — Avalanche Effect Triggered</h4>
                            <p style="margin:0.3rem 0 0 0;">{res['message']}</p>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    
                    st.markdown("**Original SHA-256 Digest:**")
                    st.code(res["original_hash"], language="text")
                    st.markdown("**Tampered SHA-256 Digest (1 Bit Inverted):**")
                    st.code(res["tampered_hash"], language="text")


# -----------------------------------------------------------------------------
# MODULE 5: VERIFICATION HISTORY
# -----------------------------------------------------------------------------
elif st.session_state["nav_section"] == "Verification History":
    st.markdown(
        """
        <div class="app-header">
            <h1>📜 Verification History & Manifest</h1>
            <p>Inspect, search, and manage registered document checksums in the local verified manifest repository.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    manifest = load_manifest()
    
    if not manifest:
        st.info("No documents are currently registered in the verification history manifest.")
    else:
        search_query = st.text_input("🔍 Search Manifest by Filename:", placeholder="e.g. invoice.pdf")
        
        manifest_list = list(manifest.values())
        if search_query:
            manifest_list = [m for m in manifest_list if search_query.lower() in m.get("filename", "").lower()]
            
        st.markdown(f"**Showing {len(manifest_list)} of {len(manifest)} registered records:**")
        
        st.dataframe(
            manifest_list,
            column_config={
                "filename": "Filename",
                "algorithm": "Algorithm",
                "digest": "Cryptographic Digest",
                "size_bytes": "Size (Bytes)",
                "timestamp": "Registered (ISO)",
            },
            use_container_width=True,
            hide_index=True,
        )
        
        col_exp1, col_exp2, col_clear = st.columns([1, 1, 1])
        with col_exp1:
            json_data = json.dumps(manifest, indent=2)
            st.download_button(
                "⬇️ Export Manifest (JSON)",
                data=json_data,
                file_name="sdvs_manifest.json",
                mime="application/json",
                use_container_width=True,
            )
        with col_exp2:
            csv_buffer = io.StringIO()
            csv_buffer.write("filename,algorithm,digest,size_bytes,timestamp\n")
            for item in manifest.values():
                csv_buffer.write(f'"{item.get("filename")}","{item.get("algorithm")}","{item.get("digest")}",{item.get("size_bytes")},"{item.get("timestamp")}"\n')
            st.download_button(
                "⬇️ Export Manifest (CSV)",
                data=csv_buffer.getvalue(),
                file_name="sdvs_manifest.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with col_clear:
            if st.button("🗑️ Clear All Manifest History", type="secondary", use_container_width=True):
                clear_manifest()
                log_activity("manifest_clear", "all", "cleared")
                st.success("Manifest records cleared.")
                st.rerun()


# -----------------------------------------------------------------------------
# MODULE 6: SECURITY LOGS
# -----------------------------------------------------------------------------
elif st.session_state["nav_section"] == "Security Logs":
    st.markdown(
        """
        <div class="app-header">
            <h1>🛡️ Security & Audit Logs</h1>
            <p>Immutable local audit trail of all cryptographic operations. Passwords and secret keys are strictly never logged.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    logs = read_activity_logs()
    
    f_col1, f_col2, f_col3 = st.columns([2, 1, 1])
    with f_col1:
        log_search = st.text_input("Search Logs:", placeholder="Filter by filename or keyword...")
    with f_col2:
        op_filter = st.selectbox(
            "Filter by Operation:",
            ["All Operations", "encrypt", "decrypt", "hash", "verify", "manifest_save", "tamper_demo"],
        )
    with f_col3:
        log_limit = st.selectbox("Display Limit:", [50, 100, 250, "All"], index=0)
        
    filtered_logs = logs
    if log_search:
        filtered_logs = [l for l in filtered_logs if log_search.lower() in str(l).lower()]
    if op_filter != "All Operations":
        filtered_logs = [l for l in filtered_logs if l.get("operation") == op_filter]
        
    if log_limit != "All":
        filtered_logs = filtered_logs[:int(log_limit)]
        
    st.markdown(f"**Audit Trail ({len(filtered_logs)} events):**")
    
    if not filtered_logs:
        st.info("No security logs matching the selected filters.")
    else:
        st.dataframe(
            filtered_logs,
            column_config={
                "timestamp": "Timestamp",
                "operation": "Operation",
                "filename": "Filename",
                "result": "Result / Status",
            },
            use_container_width=True,
            hide_index=True,
        )
        
        col_l1, col_l2 = st.columns(2)
        with col_l1:
            csv_log_buffer = io.StringIO()
            csv_log_buffer.write("timestamp,operation,filename,result\n")
            for item in logs:
                csv_log_buffer.write(f'"{item.get("timestamp")}","{item.get("operation")}","{item.get("filename")}","{item.get("result")}"\n')
            st.download_button(
                "⬇️ Export Security Audit Log (CSV)",
                data=csv_log_buffer.getvalue(),
                file_name=f"sdvs_audit_log_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with col_l2:
            if st.button("🗑️ Clear Activity Logs", use_container_width=True):
                clear_activity_logs()
                st.success("Security logs cleared.")
                st.rerun()


# -----------------------------------------------------------------------------
# MODULE 7: SETTINGS
# -----------------------------------------------------------------------------
elif st.session_state["nav_section"] == "Settings":
    st.markdown(
        """
        <div class="app-header">
            <h1>⚙️ System Settings & Diagnostics</h1>
            <p>Cryptographic engine parameters, environment diagnostics, and local storage management.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    # Supported Types Card
    st.subheader("📄 Supported Document Formats")
    st.markdown(FORMAT_BADGES_HTML, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # 1. Cryptographic Parameters
    st.subheader("🔒 Cryptographic Engine Specifications")
    s1, s2 = st.columns(2)
    with s1:
        st.markdown(
            f"""
            * **Cipher Algorithm:** AES-256 in Galois/Counter Mode (GCM)
            * **Cipher Key Length:** 256 bits ({KEY_LENGTH} bytes)
            * **Nonce Size:** 96 bits (12 bytes, cryptographic PRNG)
            * **Authentication Tag:** 128 bits ({TAG_SIZE} bytes, Poly1305/GHASH)
            * **AAD Header Size:** {HEADER_SIZE} bytes (Magic + Version + Salt + Nonce)
            """
        )
    with s2:
        st.markdown(
            f"""
            * **KDF Function:** Scrypt (RFC 7914)
            * **KDF CPU/Memory Cost (N):** {SCRYPT_N:,} iterations
            * **KDF Block Size (r):** {SCRYPT_R}
            * **KDF Parallelization (p):** {SCRYPT_P}
            * **Salt Size:** 128 bits (16 bytes, cryptographic PRNG)
            """
        )
        
    st.markdown("---")
    
    # 2. Preferences
    st.subheader("⚙️ System Preferences")
    pref_col1, pref_col2 = st.columns(2)
    with pref_col1:
        default_algo_choice = st.selectbox(
            "Default Hash Algorithm:",
            ["SHA-256", "SHA-1"],
            index=0 if st.session_state["default_algo"] == "SHA-256" else 1,
        )
        st.session_state["default_algo"] = default_algo_choice
    with pref_col2:
        st.caption("Default algorithm is pre-selected across the Hash Generator and Verification tabs.")
        
    st.markdown("---")
    
    # 3. Environment Diagnostics
    st.subheader("💻 Environment Diagnostics")
    d1, d2 = st.columns(2)
    with d1:
        st.write(f"• **Operating System:** {platform.system()} {platform.release()} ({platform.machine()})")
        st.write(f"• **Python Runtime:** {platform.python_version()}")
    with d2:
        st.write("• **Local Manifest Path:** `data/manifest.json`")
        st.write("• **Local Audit Log Path:** `data/activity.log`")
