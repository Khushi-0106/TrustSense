import streamlit as st
import time

# === IMPORT BACKEND ===
from core.scanner import scan_data
from core.recommender import recommend_wipe
from processing.wipe import simulate_wipe
from processing.trust_score import calculate_trust_score
from processing.certificate import generate_certificate
from security.verification import store_certificate, verify_certificate
from security.attack_simulation import simulate_attack

# === PAGE CONFIG ===
st.set_page_config(page_title="TrustSense", layout="wide")

# === STYLING ===
st.markdown("""
<style>
.big-title {
    font-size: 42px;
    font-weight: bold;
}
.safe {
    color: #00ff88;
    font-size: 28px;
    font-weight: bold;
}
.danger {
    color: #ff4b4b;
    font-size: 28px;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

# === HEADER ===
st.markdown('<p class="big-title">🔐 TrustSense</p>', unsafe_allow_html=True)
st.markdown("### Device Trust Certification Platform")

# === SIDEBAR ===
st.sidebar.title("🧭 Process Flow")
st.sidebar.info("""
1. 🔍 Scan System  
2. 🧠 AI Recommendation  
3. 🧹 Secure Wipe  
4. 📊 Trust Score  
5. 📄 Certificate  
6. ⚠️ Attack Simulation  
""")

# === INPUTS ===
file_path = st.text_input("📁 Enter Device Path", "C:\\TestFolder")
device_id = st.text_input("💻 Device ID", "TS-UNIT-01")

# === BUTTON ===
if st.button("🚀 Run Full Security Check"):

    # STEP 1: SCAN
    st.subheader("🔍 Scan Result")
    scan_result = scan_data(file_path)
    st.json(scan_result)

    # SHOW FILES
    st.subheader("📂 Files Detected")
    if scan_result["files"]:
        for f in scan_result["files"]:
            st.write(f)
    else:
        st.write("No files found.")

    # STEP 2: RECOMMEND
    st.subheader("🧠 AI Recommendation")
    wipe_plan = recommend_wipe(scan_result)
    st.success(f"Recommended Method: {wipe_plan['wipe_level']}")

    # STEP 3: TRUST SCORE BEFORE
    st.subheader("📊 Trust Score (Before)")
    before_score = calculate_trust_score(scan_result)
    st.metric("Before Wipe Score", f"{before_score['trust_score']}/100")

    # STEP 4: WIPE
    st.subheader("🧹 Executing Secure Wipe...")

    progress = st.progress(0)
    for i in range(100):
        time.sleep(0.01)
        progress.progress(i + 1)

    wipe_status = simulate_wipe(file_path, wipe_plan["wipe_level"])
    st.info(wipe_status["details"])

    # STEP 5: RE-SCAN
    st.subheader("🔁 After Wipe Scan")
    new_scan = scan_data(file_path)
    st.json(new_scan)

    # STEP 6: TRUST SCORE AFTER
    st.subheader("📊 Trust Score (After)")
    after_score = calculate_trust_score(new_scan)
    st.metric("After Wipe Score", f"{after_score['trust_score']}/100")

    # IMPROVEMENT
    improvement = after_score["trust_score"] - before_score["trust_score"]
    st.success(f"🔥 Trust Score Improved by +{improvement}")

    # STEP 7: CERTIFICATE
    st.subheader("📄 Trust Certificate")

    cert = generate_certificate(
        device_id,
        after_score["trust_score"],
        wipe_plan["wipe_level"]
    )

    store_certificate(cert)
    verified = verify_certificate(cert)

    st.markdown(f"""
    **Device ID:** {device_id}  
    **Trust Score:** {after_score['trust_score']}/100  
    **Wipe Method:** {wipe_plan['wipe_level']}  
    **Verification:** {"✅ Verified" if verified else "❌ Failed"}  
    """)

    # STEP 8: ATTACK SIMULATION
    st.subheader("⚠️ Attack Simulation")

    attack = simulate_attack()

    if "report" in attack:
        st.text(attack["report"])
    else:
        st.error("Attack simulation failed")

    # FINAL STATUS
    st.subheader("🏁 Final Status")

    if attack.get("is_secure", False):
        st.markdown('<p class="safe">🟢 SAFE FOR RESALE</p>', unsafe_allow_html=True)
    else:
        st.markdown('<p class="danger">🔴 DATA STILL RECOVERABLE</p>', unsafe_allow_html=True)

# FOOTER
st.markdown("---")
st.caption("TrustSense • Hackathon Project • AI + Cybersecurity 🚀")