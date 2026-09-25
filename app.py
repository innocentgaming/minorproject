"""Secure Document Verification System (SDVS) - Streamlit Application.

A production-grade, local cryptographic document security suite providing:
1. AES-256-GCM encryption & decryption with Scrypt key derivation.
2. SHA-256 & SHA-1 cryptographic fingerprinting.
3. Manifest-based and manual tamper verification.
4. Safe 1-bit tamper demonstration.
5. Local audit activity logging.
"""

import os
import tempfile
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
)
from hash_engine import (
    hash_file,
    HashEngineError,
    UnsupportedAlgorithmError,
    FileAccessError,
)
from verifier import (
    load_manifest,
    register_manifest_entry,
    compare_hashes,
    run_tamper_demo,
)
from logger import log_activity, read_activity_logs

# Configure Streamlit Page
st.set_page_config(
    page_title="Secure Document Verification System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Custom Styling for Academic / Cybersecurity Theme
st.markdown(
    """
    <style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E293B;
        margin-bottom: 0.2rem;
    }
    .sub-caption {
        font-size: 1.05rem;
        color: #475569;
        margin-bottom: 1.5rem;
    }
    .verified-box {
        background-color: #ECFDF5;
        border: 2px solid #10B981;
        border-radius: 8px;
        padding: 1.2rem;
        color: #065F46;
        font-weight: 600;
        margin-top: 1rem;
    }
    .modified-box {
        background-color: #FEF2F2;
        border: 2px solid #EF4444;
        border-radius: 8px;
        padding: 1.2rem;
        color: #991B1B;
        font-weight: 600;
        margin-top: 1rem;
    }
    .metric-card {
        background-color: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 6px;
        padding: 0.75rem 1rem;
        margin-bottom: 0.5rem;
    }
    .hash-display {
        font-family: 'Courier New', Courier, monospace;
        background-color: #0F172A;
        color: #38BDF8;
        padding: 0.75rem;
        border-radius: 6px;
        word-break: break-all;
        font-size: 0.95rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Header Section
st.markdown('<div class="main-title">🛡️ Secure Document Verification System (SDVS)</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-caption">'
    'Encrypt documents with AES-256-GCM, fingerprint them with SHA-256 / SHA-1, '
    'and verify whether they were modified. Everything runs locally.'
    '</div>',
    unsafe_allow_html=True,
)

# Application Tabs
tab_crypto, tab_hash, tab_verify, tab_audit = st.tabs([
    "🔒 Encrypt / Decrypt",
    "⚡ Generate Hash",
    "🔍 Verify",
    "📊 Log & Tamper Demo",
])


# ==========================================
# TAB 1: ENCRYPT / DECRYPT
# ==========================================
with tab_crypto:
    st.subheader("Document Confidentiality & Decryption")
    mode = st.radio("Select Operation Mode:", ["Encrypt Document", "Decrypt Document"], horizontal=True)

    if mode == "Encrypt Document":
        st.info("ℹ️ AES-256-GCM authenticated encryption with Scrypt key derivation (32-byte key, random 16-byte salt, random 12-byte nonce).")
        uploaded_file = st.file_uploader("Choose a document to encrypt (any file type):", key="enc_uploader")

        col1, col2 = st.columns(2)
        with col1:
            enc_pwd = st.text_input("Encryption Password (min 8 chars):", type="password", key="enc_pwd")
        with col2:
            enc_confirm = st.text_input("Confirm Password:", type="password", key="enc_confirm")

        st.warning("⚠️ **Warning:** If you lose the password, the encrypted data cannot be recovered. This is by design.")

        if st.button("🔒 Encrypt Document", type="primary", use_container_width=True):
            if not uploaded_file:
                st.error("Please choose a file first.")
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

                            st.success(f"✅ Document successfully encrypted into **{out_filename}** ({len(encrypted_bytes):,} bytes)")
                            st.download_button(
                                label=f"⬇️ Download {out_filename}",
                                data=encrypted_bytes,
                                file_name=out_filename,
                                mime="application/octet-stream",
                                use_container_width=True,
                            )
                        except SDVSError as e:
                            log_activity("encrypt", uploaded_file.name, f"failed: {str(e)}")
                            st.error(str(e))
                        except Exception as e:
                            log_activity("encrypt", uploaded_file.name, "failed: internal error")
                            st.error("Couldn't open the file.")

    else:  # Decrypt Document
        st.info("ℹ️ Authenticates SDVS header AAD and 16-byte GCM tag. Rejects tampered files or incorrect passwords.")
        sdvs_file = st.file_uploader("Choose an encrypted .sdvs file:", key="dec_uploader")
        dec_pwd = st.text_input("Decryption Password:", type="password", key="dec_pwd")

        if st.button("🔓 Decrypt Document", type="primary", use_container_width=True):
            if not sdvs_file:
                st.error("Please choose a file first.")
            elif not dec_pwd:
                st.error("Please enter a password.")
            else:
                with st.spinner("Verifying AAD header, deriving key & verifying GCM tag..."):
                    with tempfile.TemporaryDirectory() as temp_dir:
                        temp_in = Path(temp_dir) / sdvs_file.name
                        temp_in.write_bytes(sdvs_file.get_buffer() if hasattr(sdvs_file, "get_buffer") else sdvs_file.read())

                        # Determine restored filename
                        src_name = sdvs_file.name
                        if src_name.endswith(".sdvs"):
                            target_name = src_name[:-5]
                        else:
                            target_name = f"{src_name}.decrypted"

                        temp_out = Path(temp_dir) / target_name

                        try:
                            decrypt_file(temp_in, dest_path=temp_out, password=dec_pwd)
                            decrypted_bytes = temp_out.read_bytes()
                            log_activity("decrypt", sdvs_file.name, "success")

                            st.success(f"✅ Authentication verified! Document decrypted to **{target_name}** ({len(decrypted_bytes):,} bytes)")
                            st.download_button(
                                label=f"⬇️ Download {target_name}",
                                data=decrypted_bytes,
                                file_name=target_name,
                                mime="application/octet-stream",
                                use_container_width=True,
                            )
                        except AuthenticationError:
                            log_activity("decrypt", sdvs_file.name, "failed: Wrong password or file was modified")
                            st.error("Wrong password or file was modified")
                        except InvalidSDVSFileError:
                            log_activity("decrypt", sdvs_file.name, "failed: Not a valid SDVS file")
                            st.error("Not a valid SDVS file")
                        except SDVSError as e:
                            log_activity("decrypt", sdvs_file.name, f"failed: {str(e)}")
                            st.error(str(e))
                        except Exception:
                            log_activity("decrypt", sdvs_file.name, "failed: file error")
                            st.error("Couldn't open the file.")


# ==========================================
# TAB 2: GENERATE HASH
# ==========================================
with tab_hash:
    st.subheader("Cryptographic Document Fingerprinting")
    hash_upload = st.file_uploader("Select document to fingerprint:", key="hash_uploader")

    algo_choice = st.selectbox(
        "Select Hash Algorithm:",
        ["SHA-256 (recommended)", "SHA-1 (legacy, weak)"],
        index=0,
    )

    algo_key = "sha256" if "SHA-256" in algo_choice else "sha1"

    if algo_key == "sha1":
        st.warning("⚠️ **Warning:** SHA-1 has practical collision attacks. Use it only for comparison.")

    if st.button("⚡ Generate Hash", type="primary", use_container_width=True):
        if not hash_upload:
            st.error("Please choose a file first.")
        else:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_file = Path(temp_dir) / hash_upload.name
                file_bytes = hash_upload.get_buffer() if hasattr(hash_upload, "get_buffer") else hash_upload.read()
                temp_file.write_bytes(file_bytes)

                try:
                    digest = hash_file(temp_file, algo=algo_key)
                    file_size = len(file_bytes)

                    # Store in session state for saving to manifest
                    st.session_state["latest_hash"] = {
                        "filename": hash_upload.name,
                        "algorithm": algo_key,
                        "digest": digest,
                        "size_bytes": file_size,
                    }
                    log_activity("hash", hash_upload.name, algo_key)
                except HashEngineError as e:
                    st.error(str(e))
                except Exception:
                    st.error("Couldn't open the file.")

    if "latest_hash" in st.session_state and st.session_state["latest_hash"]:
        res = st.session_state["latest_hash"]
        st.markdown("---")
        st.markdown("### Fingerprint Results")

        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Filename", res["filename"])
        with c2:
            st.metric("File Size", f"{res['size_bytes']:,} bytes")
        with c3:
            st.metric("Algorithm", res["algorithm"].upper())

        st.markdown("**Cryptographic Digest:**")
        st.code(res["digest"], language="text")

        if st.button("💾 Save to Manifest", use_container_width=True):
            entry = register_manifest_entry(
                filename=res["filename"],
                algorithm=res["algorithm"],
                digest=res["digest"],
                size_bytes=res["size_bytes"],
            )
            log_activity("manifest_save", res["filename"], f"saved {res['algorithm']}")
            st.success(f"✅ Successfully registered **{res['filename']}** in local manifest!")


# ==========================================
# TAB 3: VERIFY
# ==========================================
with tab_verify:
    st.subheader("Integrity & Tamper Verification")
    verify_upload = st.file_uploader("Upload file to inspect and verify:", key="verify_uploader")

    verify_option = st.radio(
        "Verification Method:",
        ["Option A: Compare against saved manifest entry", "Option B: Paste expected hash manually"],
    )

    manifest_data = load_manifest()
    expected_hash = ""
    expected_algo = "sha256"

    if "Option A" in verify_option:
        if not manifest_data:
            st.warning("The manifest is currently empty. Fingerprint a file in Tab 2 and save it to the manifest first.")
        else:
            options = list(manifest_data.keys())
            # Default to matching filename if uploaded file matches
            default_index = 0
            if verify_upload and verify_upload.name in options:
                default_index = options.index(verify_upload.name)

            selected_file = st.selectbox("Select registered manifest record:", options, index=default_index)
            record = manifest_data[selected_file]
            expected_hash = record.get("digest", "")
            expected_algo = record.get("algorithm", "sha256")

            st.markdown(
                f"**Registered Record:** `{record['filename']}` | Size: `{record['size_bytes']:,} bytes` | "
                f"Algo: `{expected_algo.upper()}` | Registered: `{record['timestamp']}`"
            )
            st.code(expected_hash, language="text")

    else:  # Option B: Paste Hash
        expected_hash = st.text_input("Paste Expected Hash Digest:", placeholder="e.g. ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        paste_algo = st.selectbox("Algorithm of Pasted Hash:", ["SHA-256", "SHA-1"], index=0)
        expected_algo = "sha256" if paste_algo == "SHA-256" else "sha1"

    if st.button("🔍 Verify Integrity", type="primary", use_container_width=True):
        if not verify_upload:
            st.error("Please choose a file first.")
        elif not expected_hash.strip():
            st.error("Please provide or select an expected hash to compare against.")
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
                                <h3 style="margin:0; color:#065F46;">✅ VERIFIED</h3>
                                <p style="margin:0.5rem 0 0 0;">{message}</p>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                    else:
                        st.markdown(
                            f"""
                            <div class="modified-box">
                                <h3 style="margin:0; color:#991B1B;">❌ MODIFIED</h3>
                                <p style="margin:0.5rem 0 0 0;">{message}</p>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                    st.markdown("---")
                    st.markdown("#### Hash Comparison (Constant-Time)")
                    col_exp, col_act = st.columns(2)
                    with col_exp:
                        st.markdown("**Expected Hash:**")
                        st.code(expected_hash.strip().lower(), language="text")
                    with col_act:
                        st.markdown("**Calculated Actual Hash:**")
                        st.code(actual_digest, language="text")

                except HashEngineError as e:
                    st.error(str(e))
                except Exception:
                    st.error("Couldn't open the file.")


# ==========================================
# TAB 4: LOG & TAMPER DEMO
# ==========================================
with tab_audit:
    st.subheader("Demonstrability: Safe 1-Bit Tamper Test")
    st.markdown(
        "Demonstrate how flipping **just one single bit** in a document's binary stream fundamentally changes "
        "its cryptographic fingerprint (Avalanche effect). **The original file is never touched or modified.**"
    )

    demo_upload = st.file_uploader("Select any document for Tamper Demonstration:", key="demo_uploader")
    if st.button("🧪 Run Tamper Demo", type="primary"):
        if not demo_upload:
            st.error("Please choose a file first.")
        else:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_file = Path(temp_dir) / demo_upload.name
                temp_file.write_bytes(demo_upload.get_buffer() if hasattr(demo_upload, "get_buffer") else demo_upload.read())

                res = run_tamper_demo(temp_file)
                log_activity("tamper_demo", demo_upload.name, "MODIFIED")

                st.markdown(
                    f"""
                    <div class="modified-box">
                        <h4 style="margin:0; color:#991B1B;">⚠️ {res['status']}</h4>
                        <p style="margin:0.3rem 0 0 0;">{res['message']}</p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                st.markdown("**Original SHA-256 Hash:**")
                st.code(res["original_hash"], language="text")

                st.markdown("**SHA-256 Hash After Flipping 1 Bit (Lowest bit of byte 0):**")
                st.code(res["tampered_hash"], language="text")

    st.markdown("---")
    st.subheader("Local Audit Activity Log")
    st.caption("Records operations in `data/activity.log`. Strictly sanitizes secrets (passwords and keys are never stored).")

    if st.button("🔄 Refresh Logs"):
        st.rerun()

    logs = read_activity_logs(limit=50)
    if not logs:
        st.info("No activity records logged yet.")
    else:
        st.dataframe(
            logs,
            column_config={
                "timestamp": "Timestamp (ISO)",
                "operation": "Operation",
                "filename": "Filename",
                "result": "Result / Status",
            },
            use_container_width=True,
            hide_index=True,
        )
