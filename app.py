import streamlit as st
import time
import os

from core.scanner import scan_data
from core.recommender import recommend_wipe
from processing.wipe import simulate_wipe
from processing.trust_score import calculate_trust_score
from processing.certificate import generate_certificate
from processing.pdf_certificate import generate_pdf_certificate
from security.verification import store_certificate, verify_certificate
from security.attack_simulation import simulate_attack

st.set_page_config(page_title="TrustSense", layout="wide")

st.title("🔐 TrustSense")

file_path = st.text_input("📁 Device Path", "C:\\TestFolder")
device_id = st.text_input("💻 Device ID", "TS-UNIT-01")

if st.button("🚀 Run Full Security Check"):

    # SCAN
    scan_result = scan_data(file_path)
    st.subheader("🔍 Scan Result")
    st.json(scan_result)

    # FILE NAMES CLEAN
    st.subheader("📂 Files Detected")
    if scan_result["files"]:
        for f in scan_result["files"]:
            st.write(os.path.basename(f))
    else:
        st.write("No files found")

    # RECOMMEND
    wipe_plan = recommend_wipe(scan_result)
    st.success(f"Recommended: {wipe_plan['wipe_level']}")

    # BEFORE SCORE
    before = calculate_trust_score(scan_result)
    st.metric("Before", before["trust_score"])

    # WIPE
    progress = st.progress(0)
    for i in range(100):
        time.sleep(0.01)
        progress.progress(i + 1)

    wipe_status = simulate_wipe(file_path, wipe_plan["wipe_level"])

    # AFTER SCAN
    new_scan = scan_data(file_path)
    st.subheader("After Scan")
    st.json(new_scan)

    # AFTER SCORE
    after = calculate_trust_score(new_scan)
    st.metric("After", after["trust_score"])

    # CERTIFICATE
    cert = generate_certificate(device_id, after["trust_score"], wipe_plan["wipe_level"])
    store_certificate(cert)
    verify_certificate(cert)

    # ATTACK SIMULATION
    attack = simulate_attack()
    st.text(attack["report"])

    status = "SAFE" if attack["is_secure"] else "UNSAFE"
    st.success(status)

    # CERT DATA FOR PDF
    cert_data = {
        "device_id": device_id,
        "trust_score": after["trust_score"],
        "risk_level": new_scan["risk_level"],
        "wipe_method": wipe_plan["wipe_level"],
        "files_wiped": wipe_status.get("deleted_count", 0),
        "hash": cert["hash"],
        "status": status
    }

    # GENERATE PDF
    pdf_file = generate_pdf_certificate(cert_data)

    if pdf_file:
        with open(pdf_file, "rb") as f:
            pdf_bytes = f.read()

        st.download_button(
            label="📄 Download Certificate",
            data=pdf_bytes,
            file_name=f"{device_id}_certificate.pdf",
            mime="application/pdf"
        )
    else:
        st.error("PDF generation failed")