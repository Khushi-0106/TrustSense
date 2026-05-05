import streamlit as st
import time
import os
import pandas as pd
import platform

from core.scanner import scan_data
from core.recommender import recommend_wipe
from processing.wipe import simulate_wipe
from processing.trust_score import calculate_trust_score
from processing.certificate import generate_certificate
from processing.pdf_certificate import generate_pdf_certificate
from security.verification import store_certificate, verify_certificate
from security.attack_simulation import simulate_attack

st.set_page_config(page_title="TrustSense+ Platform", layout="wide", page_icon="🛡️")

# Initialize session state for persistent results
if "scan_data" not in st.session_state:
    st.session_state.scan_data = None
if "protocol_finished" not in st.session_state:
    st.session_state.protocol_finished = False

# Custom CSS for Neon Green/Teal Glassmorphism, Collapsible Cards, and Animations
st.markdown("""
    <style>
        #MainMenu {visibility: hidden;}
        header {visibility: hidden;}
        footer {visibility: hidden;}
        .stDeployButton {display:none;}
        
        .stApp {
            background-color: #0b1120; /* Very dark slate */
            color: #e2e8f0;
        }
        
        @keyframes glow {
            0% { text-shadow: 0 0 10px #06b6d4, 0 0 20px #06b6d4, 0 0 30px #10b981; }
            50% { text-shadow: 0 0 20px #06b6d4, 0 0 30px #06b6d4, 0 0 40px #10b981; }
            100% { text-shadow: 0 0 10px #06b6d4, 0 0 20px #06b6d4, 0 0 30px #10b981; }
        }
        
        .hero-header {
            text-align: center;
            padding: 40px 0;
            background: linear-gradient(135deg, rgba(11, 17, 32, 0.9) 0%, rgba(6, 182, 212, 0.1) 100%);
            border-bottom: 1px solid rgba(16, 185, 129, 0.4);
            margin-bottom: 30px;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);
            border-radius: 0 0 20px 20px;
        }
        
        .hero-title {
            font-size: 3rem;
            font-weight: 800;
            color: #ffffff;
            margin: 0;
            
        }
        
        .hero-subtitle {
            font-size: 1.2rem;
            color: #10b981; /* Neon green accent */
            letter-spacing: 2px;
            text-transform: uppercase;
        }

        /* Glassmorphism containers */
        .glass-container {
            background: rgba(255, 255, 255, 0.03);
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 20px;
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
        }
        
        /* Style Streamlit Expanders to look like Glass Cards */
        div[data-testid="stExpander"] {
            background: rgba(255, 255, 255, 0.03) !important;
            border-radius: 12px !important;
            border: 1px solid rgba(6, 182, 212, 0.3) !important;
            backdrop-filter: blur(10px);
            margin-bottom: 15px;
            transition: all 0.3s ease;
        }
        div[data-testid="stExpander"]:hover {
            border-color: rgba(16, 185, 129, 0.6) !important;
            box-shadow: 0 0 15px rgba(16, 185, 129, 0.2);
        }
        div[data-testid="stExpander"] > details > summary {
            color: #06b6d4;
            font-size: 1.2rem;
            font-weight: 600;
        }
        
        /* Circular Progress Ring */
        .circular-chart {
            display: block;
            margin: 0 auto;
            max-width: 150px;
            max-height: 150px;
        }
        .circle-bg {
            fill: none;
            stroke: rgba(255,255,255,0.05);
            stroke-width: 3.8;
        }
        .circle {
            fill: none;
            stroke-width: 2.8;
            stroke-linecap: round;
            animation: progress 1.5s ease-out forwards;
        }
        @keyframes progress {
            0% { stroke-dasharray: 0 100; }
        }
        .percentage {
            fill: #fff;
            font-family: sans-serif;
            font-size: 0.5em;
            text-anchor: middle;
            font-weight: bold;
        }
        .green .circle { stroke: #10b981; }
        .red .circle { stroke: #ef4444; }

        .badge-safe {
            background-color: rgba(16, 185, 129, 0.15);
            color: #10b981;
            padding: 12px 20px;
            border-radius: 8px;
            border: 1px solid #10b981;
            font-weight: bold;
            text-align: center;
            font-size: 1.2rem;
        }
        
        .badge-danger {
            background-color: rgba(239, 68, 68, 0.15);
            color: #ef4444;
            padding: 12px 20px;
            border-radius: 8px;
            border: 1px solid #ef4444;
            font-weight: bold;
            text-align: center;
            font-size: 1.2rem;
        }
    </style>
""", unsafe_allow_html=True)

# Hero Header
st.markdown("""
    <div class="hero-header">
        <h1 class="hero-title">TrustSense+ Digital Integrity Platform</h1>
        <p class="hero-subtitle">AI-Powered Device Sanitization & Certification</p>
    </div>
""", unsafe_allow_html=True)

# Input Section
with st.container():
    st.markdown('<div class="glass-container">', unsafe_allow_html=True)
    st.markdown("<h3 style='color:#06b6d4; margin-top:0;'>⚙️ Target Configuration</h3>", unsafe_allow_html=True)
    col1, col2 = st.columns(2)
    with col1:
        file_path = st.text_input("📁 Target Directory Path", "C:\\TestFolder")
    with col2:
        device_id = st.text_input("💻 Device ID", "TS-UNIT-01")
        device_name = platform.node()
        st.caption(f"Detected Hostname: {device_name}")
    st.markdown('</div>', unsafe_allow_html=True)

if st.button("🚀 INITIATE SANITIZATION PROTOCOL", use_container_width=True, type="primary"):
    st.session_state.protocol_finished = False
    
    st.markdown("<br/>", unsafe_allow_html=True)
    
    # Run logic and store in session state
    with st.spinner("Executing Deep Heuristic Scan..."):
        time.sleep(1)
        scan_result = scan_data(file_path)
        before_score = calculate_trust_score(scan_result)
        
    wipe_plan = recommend_wipe(scan_result)
    
    with st.expander("⚡ Eradication Progress", expanded=True):
        progress_bar = st.progress(0, text="Initializing override sequences...")
        for i in range(100):
            time.sleep(0.01)
            if i == 30:
                progress_bar.progress(i + 1, text="Overwriting file segments with cryptographic noise...")
            elif i == 70:
                progress_bar.progress(i + 1, text="Purging directory structures...")
            else:
                progress_bar.progress(i + 1)
                
        wipe_status = simulate_wipe(file_path, wipe_plan["wipe_level"])
        st.success(f"Protocol Complete: {wipe_status['details']}")

    with st.spinner("Verifying destruction and simulating forensic attacks..."):
        new_scan = scan_data(file_path)
        after_score = calculate_trust_score(new_scan)
        attack = simulate_attack()
        
    with st.spinner("Generating cryptographically signed PDF..."):
        cert = generate_certificate(device_id, after_score["trust_score"], wipe_plan["wipe_level"])
        store_certificate(cert)
        status = "SAFE" if attack["is_secure"] else "UNSAFE"
        
        cert_data = {
            "device_id": device_id,
            "device_name": device_name,
            "trust_score": after_score["trust_score"],
            "risk_level": new_scan["risk_level"],
            "wipe_method": wipe_plan["wipe_level"],
            "files_wiped": wipe_status.get("deleted_count", 0),
            "folders_wiped": wipe_status.get("deleted_folders_count", 0),
            "hash": cert["hash"],
            "status": status
        }
        pdf_file = generate_pdf_certificate(cert_data)
        
        pdf_bytes = None
        if pdf_file and os.path.exists(pdf_file):
            with open(pdf_file, "rb") as f:
                pdf_bytes = f.read()

    # Save to session state
    st.session_state.scan_result = scan_result
    st.session_state.before_score = before_score
    st.session_state.wipe_plan = wipe_plan
    st.session_state.wipe_status = wipe_status
    st.session_state.new_scan = new_scan
    st.session_state.after_score = after_score
    st.session_state.attack = attack
    st.session_state.cert = cert
    st.session_state.status = status
    st.session_state.pdf_bytes = pdf_bytes
    st.session_state.pdf_file = pdf_file
    st.session_state.protocol_finished = True

def render_svg_ring(score, color_class):
    return f'''
    <svg viewBox="0 0 36 36" class="circular-chart {color_class}">
      <path class="circle-bg"
        d="M18 2.0845
          a 15.9155 15.9155 0 0 1 0 31.831
          a 15.9155 15.9155 0 0 1 0 -31.831"
      />
      <path class="circle"
        stroke-dasharray="{score}, 100"
        d="M18 2.0845
          a 15.9155 15.9155 0 0 1 0 31.831
          a 15.9155 15.9155 0 0 1 0 -31.831"
      />
      <text x="18" y="20.35" class="percentage">{score}</text>
    </svg>
    '''

# Display UI from session state if protocol is finished
if st.session_state.protocol_finished:
    
    # 1. SCAN & DEVICE SUMMARY
    with st.expander("🔍 Stage 1: Device Summary & Forensic Analysis", expanded=True):
        st.markdown(f"**Host:** {platform.node()} | **ID:** {device_id}")
        
        sc1, sc2, sc3, sc4 = st.columns(4)
        sc1.metric("Total Files", st.session_state.scan_result["total_files"])
        sc2.metric("Total Folders", st.session_state.scan_result["total_folders"])
        sc3.metric("Sensitive Files", st.session_state.scan_result["sensitive_files"])
        sc4.metric("Initial Risk Level", st.session_state.scan_result["risk_level"])
        
        if st.session_state.scan_result["file_types"]:
            st.markdown("<br/>**File Type Distribution**", unsafe_allow_html=True)
            df = pd.DataFrame(list(st.session_state.scan_result["file_types"].items()), columns=['Extension', 'Count'])
            st.bar_chart(df.set_index('Extension'), color="#06b6d4")

    # 2. AI RECOMMENDATION
    with st.expander("🧠 Stage 2: AI Sanitization Strategy", expanded=True):
        st.info(f"**Protocol Chosen:** {st.session_state.wipe_plan['wipe_level']}")
        st.markdown(f"> **Why this wipe method was chosen:** Detected {st.session_state.scan_result['sensitive_files']} sensitive files and a directory depth of {st.session_state.scan_result['max_depth']}. Base risk level is {st.session_state.scan_result['risk_level']}. Executing **{st.session_state.wipe_plan['wipe_level']}** multi-pass patterns to ensure permanent data destruction.")

    # 3. VERIFICATION & TRUST SCORE
    with st.expander("📊 Stage 3: Verification & Smart Trust Score", expanded=True):
        
        c1, c2, c3 = st.columns([1, 1, 2])
        
        before_score_val = st.session_state.before_score['trust_score']
        after_score_val = st.session_state.after_score['trust_score']
        
        with c1:
            st.markdown("<h5 style='text-align: center; color: #94a3b8;'>PRE-WIPE SCORE</h5>", unsafe_allow_html=True)
            st.markdown(render_svg_ring(before_score_val, "red"), unsafe_allow_html=True)
            
        with c2:
            st.markdown("<h5 style='text-align: center; color: #94a3b8;'>POST-WIPE SCORE</h5>", unsafe_allow_html=True)
            st.markdown(render_svg_ring(after_score_val, "green"), unsafe_allow_html=True)
            
        with c3:
            st.markdown("<br/>**Attack Simulation / Forensic Recovery Attempt:**", unsafe_allow_html=True)
            if st.session_state.status == "SAFE":
                st.markdown('<div class="badge-safe">🟢 VERDICT: NO DATA RECOVERED</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="badge-danger">🔴 VERDICT: FRAGMENTS FOUND</div>', unsafe_allow_html=True)
                
            with st.expander("Show Forensic Log"):
                st.code(st.session_state.attack["report"], language="text")

        st.markdown("<br/>", unsafe_allow_html=True)
        if st.session_state.status == "SAFE":
            st.markdown('<div class="badge-safe" style="font-size: 1.5rem; padding: 20px;">✅ VERIFIED SAFE FOR RESALE</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="badge-danger" style="font-size: 1.5rem; padding: 20px;">❌ DEVICE NOT SAFE FOR RESALE</div>', unsafe_allow_html=True)

    # 4. CERTIFICATE GENERATION
    with st.expander("📜 Stage 4: Premium Certification Passport", expanded=True):
        st.markdown("Your Cryptographic Security Passport has been generated with a verifiable QR code.")
        
        if st.session_state.pdf_bytes:
            st.download_button(
                label="⬇️ DOWNLOAD OFFICIAL SECURITY PASSPORT (PDF)",
                data=st.session_state.pdf_bytes,
                file_name=f"{device_id}_Security_Passport.pdf",
                mime="application/pdf",
                use_container_width=True,
                type="primary"
            )
        else:
            st.error("PDF generation encountered a critical error.")
            
    # 5. EXECUTION LOG
    with st.expander("📋 Execution Trace Logs", expanded=False):
        st.text(f"[SCAN COMPLETE] Found {st.session_state.scan_result['total_files']} files, {st.session_state.scan_result['total_folders']} folders.")
        st.text(f"[ANALYSIS GENERATED] Risk: {st.session_state.scan_result['risk_level']} | AI Rec: {st.session_state.wipe_plan['wipe_level']}")
        st.text(f"[WIPE STARTED] Executing pattern overrides...")
        st.text(f"[FILES REMOVED] {st.session_state.wipe_status.get('deleted_count')} files completely eradicated.")
        st.text(f"[ATTACK SIMULATION] Status: {'Secure' if st.session_state.attack['is_secure'] else 'Vulnerable'}")
        st.text(f"[CERTIFICATE GENERATED] SHA256: {st.session_state.cert['hash']}")