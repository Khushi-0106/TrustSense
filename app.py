import streamlit as st

from core.scanner import scan_data
from core.recommender import recommend_wipe
from processing.wipe import simulate_wipe
from processing.trust_score import calculate_trust_score
from processing.certificate import generate_certificate
from security.verification import store_certificate, verify_certificate
from security.attack_simulation import simulate_attack

st.set_page_config(page_title="TrustSense", layout="centered")

st.title("🔐 TrustSense - Secure Data Wiping System")

st.markdown("### Turn device resale into a **trusted process**")

# Run button
if st.button("🚀 Run Full Security Check"):

    st.subheader("🔍 Step 1: Scanning System")
    scan_result = scan_data()
    st.json(scan_result)

    st.subheader("🧠 Step 2: AI Wipe Recommendation")
    wipe_plan = recommend_wipe(scan_result)
    st.success(f"Recommended: {wipe_plan['wipe_level']}")

    st.subheader("🧹 Step 3: Secure Wipe Simulation")
    wipe_status = simulate_wipe(wipe_plan["wipe_level"])
    st.info(wipe_status["details"])

    st.subheader("📊 Step 4: Trust Score")
    trust_score = calculate_trust_score(scan_result, wipe_plan)
    st.metric("Trust Score", f"{trust_score['trust_score']}/100")

    st.subheader("📄 Step 5: Certificate Generation")
    cert = generate_certificate(
        "Device123",
        trust_score["trust_score"],
        wipe_plan["wipe_level"]
    )
    st.json(cert)

    st.subheader("🔐 Step 6: Verification")
    store_certificate(cert)
    valid = verify_certificate(cert)
    st.success(f"Certificate Verified: {valid}")

    st.subheader("⚠️ Step 7: Attack Simulation")
    attack = simulate_attack()
    st.text(attack["report"])

    if attack["is_secure"]:
        st.success("✅ Device is SAFE for resale")
    else:
        st.error("❌ Data still recoverable")

st.markdown("---")
st.caption("Built for Hackathon Demo 🚀")