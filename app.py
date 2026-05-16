import streamlit as st
import streamlit.components.v1 as components
import time
import os
import shutil
import pandas as pd
import platform
import hashlib
from datetime import datetime

from core.scanner import scan_data
from core.recommender import recommend_wipe
from processing.wipe import simulate_wipe
from processing.trust_score import calculate_trust_score
from processing.certificate import generate_certificate
from processing.pdf_certificate import generate_pdf_certificate
from security.verification import store_certificate, verify_certificate
from security.attack_simulation import simulate_attack
from ui_components import get_passport_html, get_verification_portal_html, get_qr_base64, get_local_ip
from processing.neo_pdf import generate_neo_pdf
from processing.backup import perform_backup

st.set_page_config(page_title="TrustSense+ Forensic Platform", layout="wide", page_icon="🛡️")

# Initialize session state for additive flow
if "workflow_stage" not in st.session_state:
    st.session_state.workflow_stage = 1 # 1:Setup, 2:Scanned, 3:Wiping, 4:Finished
if "scan_results" not in st.session_state:
    st.session_state.scan_results = None
if "wipe_rec" not in st.session_state:
    st.session_state.wipe_rec = None
if "selected_paths" not in st.session_state:
    st.session_state.selected_paths = []
if "backup_done" not in st.session_state:
    st.session_state.backup_done = False

# Custom CSS for Premium Forensic Look
st.markdown("""
    <style>
        .stApp { background-color: #0b1120; color: #ffffff; }
        .forensic-card {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(6, 182, 212, 0.2);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            backdrop-filter: blur(12px);
        }
        .risk-high { color: #ef4444; font-weight: bold; }
        .risk-medium { color: #f97316; font-weight: bold; }
        .risk-low { color: #10b981; font-weight: bold; }
        .risk-hidden { color: #06b6d4; font-weight: bold; }
        
        .hero-header {
            text-align: center;
            padding: 40px 0;
            background: linear-gradient(135deg, rgba(11, 17, 32, 0.9) 0%, rgba(6, 182, 212, 0.1) 100%);
            border-bottom: 1px solid rgba(16, 185, 129, 0.4);
            margin-bottom: 30px;
            border-radius: 0 0 20px 20px;
        }
    </style>
""", unsafe_allow_html=True)

def render_svg_ring(score, color_class):
    # score color based on value
    col = "#ef4444" if score < 40 else "#f97316" if score < 80 else "#10b981"
    return f'''
    <svg viewBox="0 0 36 36" style="max-width: 150px; display: block; margin: auto;">
      <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="3"/>
      <path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="{col}" stroke-width="3" stroke-dasharray="{score}, 100" stroke-linecap="round"/>
      <text x="18" y="20.35" fill="white" font-family="sans-serif" font-size="8" text-anchor="middle" font-weight="bold">{score}%</text>
    </svg>
    '''

# Hero Header
st.markdown("""
    <div class="hero-header">
        <h1 style='font-size: 3rem; font-weight: 800; margin: 0;'>TrustSense+ Elite</h1>
        <p style='font-size: 1.2rem; color: #06b6d4; letter-spacing: 2px; text-transform: uppercase;'>AI Forensic Sanitization & Verification</p>
    </div>
""", unsafe_allow_html=True)

# ── STAGE 1: TARGET CONFIGURATION ──────────────────────────────────────────
st.markdown("### ⚙️ STAGE 1: TARGET CONFIGURATION")
with st.container():
    col1, col2 = st.columns(2)
    with col1:
        raw_path = st.text_input("📁 Target Directory Path", "C:\\TestFolder" if platform.system() == "Windows" else "./test_data")
        file_path = os.path.abspath(os.path.expanduser(raw_path.strip().replace('"', '')))
    with col2:
        device_id = st.text_input("💻 Device ID", "TS-UNIT-01")
    
    if st.session_state.workflow_stage == 1:
        if st.button("🔍 INITIATE FORENSIC SCAN", use_container_width=True, type="primary"):
            with st.spinner("Analyzing filesystem metadata..."):
                time.sleep(1)
                st.session_state.scan_results = scan_data(file_path)
                st.session_state.wipe_rec = recommend_wipe(st.session_state.scan_results)
                st.session_state.workflow_stage = 2
                st.rerun()

# ── STAGE 2: FORENSIC ANALYSIS & CATEGORIZATION ────────────────────────────
if st.session_state.workflow_stage >= 2:
    res = st.session_state.scan_results
    rec = st.session_state.wipe_rec
    
    st.markdown("---")
    st.markdown("### 📊 STAGE 2: FORENSIC ANALYSIS & CATEGORIZATION")
    
    c1, c2 = st.columns([1.5, 1])
    with c1:
        st.markdown("#### Risk Distribution (Dynamic)")
        rc = res["risk_counts"]
        chart_data = pd.DataFrame({
            "Category": ["High Risk", "Medium Risk", "Low Risk", "Hidden Assets"],
            "Count": [rc["High"], rc["Medium"], rc["Low"], rc["Hidden"]]
        })
        st.bar_chart(chart_data.set_index("Category"), color="#06b6d4", horizontal=True)
        
    with c2:
        st.markdown("#### AI Recommendation Engine")
        st.info(f"**Suggested Protocol:** {rec['wipe_level']}")
        st.write(f"**Reasoning:** {rec['reason']}")
        st.caption("AI reasoning based on entropy and forensic signature detection.")

    # Asset Selection for Backup
    st.markdown("#### 📁 Asset Preservation (Backup)")
    st.write("Select specific files to preserve in the secure vault before destruction.")
    
    all_files = res["file_details"]
    
    # Table-like UI for selection
    with st.expander("📋 FORENSIC ASSET MANIFEST", expanded=(st.session_state.workflow_stage == 2)):
        # Header
        hcol1, hcol2, hcol3 = st.columns([0.1, 0.7, 0.2])
        hcol1.write("**Sel**")
        hcol2.write("**Path**")
        hcol3.write("**Forensic Risk**")
        
        current_selection = []
        for i, f in enumerate(all_files[:40]): # Limit to 40 for UI speed
            cc1, cc2, cc3 = st.columns([0.1, 0.7, 0.2])
            is_sel = cc1.checkbox("", key=f"file_{i}", value=(f['risk'] == "High"))
            if is_sel:
                current_selection.append(f['path'])
            cc2.code(f['path'], language="text")
            risk_class = f"risk-{f['risk'].lower()}"
            cc3.markdown(f"<span class='{risk_class}'>{f['risk']} {'(HIDDEN)' if f['hidden'] else ''}</span>", unsafe_allow_html=True)
        
        st.session_state.selected_paths = current_selection

    if st.session_state.workflow_stage == 2:
        col_b1, col_b2 = st.columns(2)
        with col_b1:
            if st.button("📁 BACKUP SELECTED & CONTINUE", use_container_width=True):
                if st.session_state.selected_paths:
                    moved, b_path = perform_backup(st.session_state.selected_paths, device_id, file_path)
                    st.session_state.backup_msg = f"✔ {moved} files securely archived to {b_path}"
                    st.session_state.backup_done = True
                st.session_state.workflow_stage = 3
                st.rerun()
        with col_b2:
            if st.button("🚀 DIRECT WIPE (NO BACKUP)", use_container_width=True, type="primary"):
                st.session_state.workflow_stage = 3
                st.rerun()

# ── STAGE 3: ERADICATION PROGRESS ──────────────────────────────────────────
if st.session_state.workflow_stage >= 3:
    if st.session_state.get("backup_done"):
        st.success(st.session_state.backup_msg)
        
    st.markdown("---")
    st.markdown("### ⚡ STAGE 3: SANITIZATION PROTOCOL")
    
    if "wipe_results" not in st.session_state:
        with st.spinner(f"Executing {rec['wipe_level']} override patterns..."):
            wipe_status = simulate_wipe(file_path, rec["wipe_level"])
            time.sleep(2)
            st.session_state.wipe_results = wipe_status
            st.session_state.workflow_stage = 4
            st.rerun()
    
    st.success(f"Sanitization Success: {st.session_state.wipe_results['details']}")
    with st.expander("🗑️ ERADICATION LOG"):
        for df in st.session_state.wipe_results.get("deleted_files", []):
            st.text(f"[DELETED] {df}")

# ── STAGE 4: POST-WIPE & ATTACK SIMULATION ─────────────────────────────────
if st.session_state.workflow_stage >= 4:
    st.markdown("---")
    st.markdown("### 🛡️ STAGE 4: POST-WIPE VERIFICATION & CERTIFICATION")
    
    if "final_report" not in st.session_state:
        with st.spinner("Conducting automated forensic recovery attempt..."):
            new_scan = scan_data(file_path)
            attack = simulate_attack()
            after_score = calculate_trust_score(new_scan)
            
            # PDF Generation
            pdf_data = {
                "device_id": device_id,
                "hash": hashlib.sha256(str(time.time()).encode()).hexdigest(),
                "trust_score": after_score["trust_score"],
                "files_sensitive": st.session_state.scan_results["sensitive_files"],
                "files_safe": st.session_state.scan_results["total_files"] - st.session_state.scan_results["sensitive_files"],
                "risk_counts": st.session_state.scan_results["risk_counts"],
                "protocol": rec["wipe_level"],
                "date": datetime.now().strftime("%d/%m/%Y")
            }
            neo_pdf_bytes = generate_neo_pdf(pdf_data)
            
            st.session_state.final_report = {
                "scan": new_scan,
                "attack": attack,
                "score": after_score,
                "pdf_bytes": neo_pdf_bytes,
                "pdf_data": pdf_data
            }
            st.rerun()
    
    report = st.session_state.final_report
    
    rcol1, rcol2 = st.columns([1, 2])
    with rcol1:
        st.markdown("#### Device Trust Score")
        st.markdown(render_svg_ring(report["score"]["trust_score"], ""), unsafe_allow_html=True)
        
    with rcol2:
        st.markdown("#### Forensic Attack Simulation")
        if report["attack"]["is_secure"]:
            st.markdown("<div style='background: rgba(16, 185, 129, 0.1); border: 1px solid #10b981; padding: 15px; border-radius: 8px; color: #10b981; font-weight: bold;'>VERDICT: ZERO DATA RECOVERY POSSIBLE</div>", unsafe_allow_html=True)
        else:
            st.error("VERDICT: DATA REMNANTS DETECTED")
        st.code(report["attack"]["report"], language="text")

    # ── PASSPORT ──
    st.markdown("#### 📜 TrustSense+ Cryptographic Security Passport")
    
    p_data = report["pdf_data"]
    local_ip = get_local_ip()
    verify_url = f"http://{local_ip}:8501/?verify=true&id={device_id}&hash={p_data['hash']}"
    p_data['qr_base64'] = get_qr_base64(verify_url)
    
    passport_html = get_passport_html(p_data)
    components.html(passport_html, height=500, scrolling=True)
    
    st.download_button(
        label="⬇️ DOWNLOAD OFFICIAL SECURITY PASSPORT (PDF)",
        data=report["pdf_bytes"],
        file_name=f"{device_id}_Passport.pdf",
        mime="application/pdf",
        use_container_width=True,
        type="primary"
    )

    if st.button("🔄 RESTART NEW FORENSIC SESSION"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()