import streamlit as st
import streamlit.components.v1 as components
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
from datetime import datetime
import streamlit.components.v1 as components
from ui_components import get_passport_html, get_verification_portal_html, get_qr_base64, get_local_ip
from processing.neo_pdf import generate_neo_pdf
from processing.backup import perform_backup

# Create dummy data if needed
if not os.path.exists("./test_data"):
    os.makedirs("./test_data", exist_ok=True)
    files = {
        "production.key": "PRIVATE_KEY_55882211",
        "sensitive_db.config": "DB_PASSWORD=admin_secret_123",
        "forensic_audit.log": "Access attempt from 192.168.1.50 denied",
        "backup_v1.bak": "Old system state backup",
        "passwords.csv": "site,username,password\ngithub,khushi,********",
        "intel_report.pdf": "%PDF-1.4 simulated forensic report",
        "asset_image.jpg": "FFD8FFE0 simulated image data",
        "README.txt": "This is a safe file."
    }
    for name, content in files.items():
        with open(os.path.join("./test_data", name), "w") as f:
            f.write(content)
    os.makedirs("./test_data/hidden_vault", exist_ok=True)
    with open("./test_data/hidden_vault/.vault_token", "w") as f:
        f.write("H-TOKEN-XYZ-998")

st.set_page_config(page_title="TrustSense+ Platform", layout="wide", page_icon="🛡️")

# Initialize session state for persistent results
if "scan_data" not in st.session_state:
    st.session_state.scan_data = None
if "protocol_finished" not in st.session_state:
    st.session_state.protocol_finished = False
if "stage" not in st.session_state:
    st.session_state.stage = "IDLE"

# --- NEW: ROUTING LOGIC FOR QR SCANS ---
query_params = st.query_params
if "verify" in query_params:
    st.markdown("""
        <style>
            .stApp { background-color: #000000 !important; }
            header { visibility: hidden; }
            footer { visibility: hidden; }
        </style>
    """, unsafe_allow_html=True)
    
    verify_data = {
        "device_id": query_params.get("id", "UNKNOWN"),
        "hash": query_params.get("hash", "UNKNOWN")
    }
    
    # Render the Live Verification Portal as a full-screen component
    portal_html = get_verification_portal_html(verify_data, tamper_detected=False)
    components.html(portal_html, height=1000, scrolling=True)
    st.stop() # Stop execution here to only show the portal
# ---------------------------------------

# Custom CSS for Neon Green/Teal Glassmorphism, Collapsible Cards, and Animations
st.markdown("""
    <style>
        #MainMenu {visibility: hidden;}
        header {visibility: hidden;}
        footer {visibility: hidden;}
        .stDeployButton {display:none;}
        
        .stApp {
            background-color: #0b1120; /* Very dark slate */
            color: #ffffff; /* Bright white text */
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
            color: #ffffff; /* Bright white accent */
            letter-spacing: 2px;
            text-transform: uppercase;
            text-shadow: 0 0 10px rgba(6, 182, 212, 0.5);
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
            color: #00f3ff; /* Bright Cyan */
            font-size: 1.2rem;
            font-weight: 700;
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
        .green .circle { stroke: #B2F2BB; }
        .red .circle { stroke: #FFC9C9; }

        .badge-safe {
            background-color: rgba(178, 242, 187, 0.15);
            color: #B2F2BB;
            padding: 12px 20px;
            border-radius: 8px;
            border: 1px solid #B2F2BB;
            font-weight: bold;
            text-align: center;
            font-size: 1.2rem;
        }
        
        .badge-danger {
            background-color: rgba(255, 201, 201, 0.15);
            color: #FFC9C9;
            padding: 12px 20px;
            border-radius: 8px;
            border: 1px solid #FFC9C9;
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

# Detect if running in cloud
is_cloud = platform.system() != "Windows" or os.environ.get("VERCEL") or "streamlit.app" in st.get_option("browser.serverAddress")
if is_cloud:
    st.error("🛑 **CLOUD DEMO MODE**: This web version can ONLY wipe the internal `/demo_files` folder. To wipe folders on YOUR physical laptop, you must run the app locally via your terminal.")

# Input Section
with st.container():
    st.markdown('<div class="glass-container">', unsafe_allow_html=True)
    st.markdown("<h3 style='color:#00f3ff; margin-top:0;'>⚙️ Target Configuration</h3>", unsafe_allow_html=True)
    col1, col2 = st.columns(2)
    with col1:
        default_path = "C:\\TestFolder" if platform.system() == "Windows" else "./test_data"
        raw_path = st.text_input("📁 Target Directory Path", default_path)
        # Normalize path for Windows/Linux compatibility
        file_path = os.path.abspath(os.path.expanduser(raw_path.strip().replace('"', '')))
        
        if not os.path.exists(file_path):
            if is_cloud:
                st.warning("🌐 **VIRTUAL SANITIZATION ENABLED**: Local path not found. Switching to Cloud Demo Assets for the judges.")
                file_path = "./test_data" # Use the cloud-synced test data
            else:
                st.warning(f"⚠️ Path not found: {file_path}")
        else:
            st.success(f"📂 Target Locked: {file_path}")
    with col2:
        device_id = st.text_input("💻 Device ID", "TS-UNIT-01")
        device_name = platform.node()
        st.caption(f"Detected Hostname: {device_name}")
    st.markdown('</div>', unsafe_allow_html=True)

if st.button("🚀 INITIATE SANITIZATION PROTOCOL", use_container_width=True, type="primary"):
    st.session_state.stage = "OPTIONS"
    st.session_state.protocol_finished = False
    if "initial_scan" in st.session_state:
        del st.session_state.initial_scan # Reset scan on new initiate

if st.session_state.get("stage") == "OPTIONS":
    st.markdown("<br/>", unsafe_allow_html=True)
    
    # Run initial scan if not already cached
    if "initial_scan" not in st.session_state:
        with st.spinner("Executing Deep Heuristic Scan..."):
            time.sleep(1)
            scan_result = scan_data(file_path)
            before_score = calculate_trust_score(scan_result)
            wipe_plan = recommend_wipe(scan_result)
            st.session_state.initial_scan = {
                "scan_result": scan_result,
                "before_score": before_score,
                "wipe_plan": wipe_plan
            }
    
    scan_result = st.session_state.initial_scan["scan_result"]
    wipe_plan = st.session_state.initial_scan["wipe_plan"]
    
    # --- PRE-WIPE ACTION CENTER ---
    st.markdown("### 🛡️ Pre-Wipe Action Center")
    st.info(f"Recommended Protocol: **{wipe_plan['wipe_level']}**")
    
    col_b1, col_b2 = st.columns(2)
    with col_b1:
        if st.button("🚀 Proceed with Secure Wipe"):
            st.session_state.do_backup = False
            st.session_state.stage = "WIPING"
            st.rerun()
    with col_b2:
        if st.button("📂 Backup Sensitive Files then Wipe"):
            st.session_state.do_backup = True
            st.session_state.stage = "WIPING"
            st.rerun()

if st.session_state.get("stage") == "WIPING":
    scan_result = st.session_state.initial_scan["scan_result"]
    before_score = st.session_state.initial_scan["before_score"]
    wipe_plan = st.session_state.initial_scan["wipe_plan"]
    
    if st.session_state.get("do_backup", False):
        with st.spinner("Backing up sensitive forensic assets..."):
            moved_count, backup_path = perform_backup(scan_result, device_id, file_path)
            if moved_count > 0:
                st.success(f"✔ Backup completed successfully")
                st.info(f"✔ {moved_count} sensitive files stored at: {backup_path}")
            else:
                st.warning("No sensitive files found. Proceeding with wipe.")
    
    # Automatically continue with wipe logic
    with st.expander("⚡ Eradication Progress", expanded=True):
        progress_bar = st.progress(0, text="Initializing override sequences...")
        
        # Call the actual wipe with error capturing
        try:
            print(f"DEBUG: Starting wipe for {file_path}")
            wipe_status = simulate_wipe(file_path, wipe_plan["wipe_level"])
            
            for i in range(100):
                time.sleep(0.005)
                progress_bar.progress(i + 1)
                
            st.success(f"Protocol Complete: {wipe_status['details']}")
            
            if wipe_status.get("deleted_files"):
                st.info(f"✅ Successfully eradicated {len(wipe_status['deleted_files'])} items.")
            else:
                st.warning("⚠️ No files were deleted. Check if the folder is empty or if the path is correct.")
                
        except Exception as e:
            st.error(f"❌ CRITICAL ERROR DURING WIPE: {str(e)}")
            st.stop()
        if wipe_status.get("deleted_files"):
            with st.expander("🗑️ View Deleted Files List"):
                for df in wipe_status["deleted_files"]:
                    st.write(f"• {df}")

    with st.spinner("Verifying destruction and simulating forensic attacks..."):
        new_scan = scan_data(file_path)
        after_score = calculate_trust_score(new_scan)
        attack = simulate_attack()
        
    with st.spinner("Generating cryptographically signed PDF..."):
        cert = generate_certificate(device_id, after_score["trust_score"], wipe_plan["wipe_level"])
        st.session_state.cert = cert
        store_certificate(cert)
        status = "SAFE" if attack["is_secure"] else "UNSAFE"
        st.session_state.status = status
        st.session_state.after_score = after_score
        st.session_state.attack = attack
        st.session_state.scan_result = new_scan
        
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

        # Generate Neo-Brutalist PDF
        pdf_data = {
            "device_id": device_id,
            "hash": cert["hash"],
            "trust_score": after_score["trust_score"],
            "files_sensitive": scan_result["sensitive_files"],
            "files_safe": scan_result["total_files"] - scan_result["sensitive_files"]
        }
        neo_pdf_bytes = generate_neo_pdf(pdf_data)
        
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
    st.session_state.pdf_bytes = pdf_bytes # Old PDF
    st.session_state.neo_pdf_bytes = neo_pdf_bytes # New Neo-Brutalist PDF
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
            st.markdown("<h5 style='text-align: center; color: #ffffff;'>PRE-WIPE SCORE</h5>", unsafe_allow_html=True)
            st.markdown(render_svg_ring(before_score_val, "red"), unsafe_allow_html=True)
            
        with c2:
            st.markdown("<h5 style='text-align: center; color: #ffffff;'>POST-WIPE SCORE</h5>", unsafe_allow_html=True)
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
        
        # Prepare data for the Neo-Brutalist Passport
        local_ip = get_local_ip()
        verify_url = f"http://{local_ip}:8501/?verify=true&id={device_id}&hash={st.session_state.cert['hash']}"
        qr_base64 = get_qr_base64(verify_url)
        
        passport_data = {
            "trust_score": st.session_state.after_score["trust_score"],
            "device_id": device_id,
            "date": datetime.now().strftime("%Y-%m-%d"),
            "files_sensitive": st.session_state.scan_result["sensitive_files"],
            "files_safe": st.session_state.scan_result["total_files"] - st.session_state.scan_result["sensitive_files"],
            "hash": st.session_state.cert["hash"],
            "qr_base64": qr_base64
        }
        
        passport_html = get_passport_html(passport_data)
        components.html(passport_html, height=400, scrolling=True)
        
        if st.session_state.neo_pdf_bytes:
            st.download_button(
                label="⬇️ DOWNLOAD OFFICIAL SECURITY PASSPORT (NEO-BRUTALIST PDF)",
                data=st.session_state.neo_pdf_bytes,
                file_name=f"{device_id}_Security_Passport.pdf",
                mime="application/pdf",
                use_container_width=True,
                type="primary"
            )
        elif st.session_state.pdf_bytes:
            st.download_button(
                label="⬇️ DOWNLOAD OFFICIAL SECURITY PASSPORT (STANDARD PDF)",
                data=st.session_state.pdf_bytes,
                file_name=f"{device_id}_Security_Passport.pdf",
                mime="application/pdf",
                use_container_width=True,
                type="primary"
            )
        else:
            st.error("❌ PDF generation encountered a critical error. Please check your terminal for the 'PDF Error' log.")
            if st.button("Retry PDF Generation"):
                st.session_state.protocol_finished = False
                st.rerun()

    # 5. LIVE VERIFICATION SIMULATION
    with st.expander("🌐 Stage 5: Live Verification Portal Simulation", expanded=False):
        st.write("This is what a buyer or auditor sees when they scan the QR code on your passport.")
        
        tamper_sim = st.toggle("Simulate Tamper Detection (Hash Mismatch)")
        
        if st.button("🔗 OPEN LIVE VERIFICATION PORTAL"):
            portal_html = get_verification_portal_html(passport_data, tamper_detected=tamper_sim)
            components.html(portal_html, height=800, scrolling=True)
            
    # 6. EXECUTION LOG
    with st.expander("📋 Execution Trace Logs", expanded=False):
        st.text(f"[SCAN COMPLETE] Found {st.session_state.scan_result['total_files']} files, {st.session_state.scan_result['total_folders']} folders.")
        st.text(f"[ANALYSIS GENERATED] Risk: {st.session_state.scan_result['risk_level']} | AI Rec: {st.session_state.wipe_plan['wipe_level']}")
        st.text(f"[WIPE STARTED] Executing pattern overrides...")
        st.text(f"[FILES REMOVED] {st.session_state.wipe_status.get('deleted_count')} files completely eradicated.")
        st.text(f"[ATTACK SIMULATION] Status: {'Secure' if st.session_state.attack['is_secure'] else 'Vulnerable'}")
        st.text(f"[CERTIFICATE GENERATED] SHA256: {st.session_state.cert['hash']}")