from core.scanner import scan_data
from core.recommender import recommend_wipe
from processing.wipe import simulate_wipe, setup_live_sandbox
from processing.trust_score import calculate_trust_score
from processing.certificate import generate_certificate
from security.verification import store_certificate, verify_certificate
from security.attack_simulation import simulate_attack

def run_demo():
    print("=== TrustSense+ Backend Initialized ===")
    
    # 1. Setup Sandbox (Live Interaction)
    print(f"\n[Step 1] Creating Live Sandbox...")
    sandbox_path = setup_live_sandbox()
    
    # 2. Scan
    scan = scan_data(sandbox_path)
    print(f"[Step 2] Scan Result: Found {scan['total_files']} files, {scan['sensitive_files']} sensitive.")
    
    # 3. Recommend & Wipe
    rec = recommend_wipe(scan)
    wipe_res = simulate_wipe(sandbox_path, rec["wipe_level"])
    print(f"[Step 3] Wipe Status: {wipe_res['details']}")
    
    # 4. Trust Score
    # Re-scan after wipe
    scan_after = scan_data(sandbox_path)
    trust = calculate_trust_score(scan_after)
    print(f"[Step 4] Verified Trust Score: {trust['trust_score']}%")
    
    # 5. Certificate
    cert = generate_certificate("DEV-001", trust['trust_score'], rec["wipe_level"])
    print(f"[Step 5] Certificate Generated. Hash: {cert['hash'][:16]}...")
    
    # 6. Store & Verify (Tamper Demo)
    store_certificate(cert)
    print(f"[Step 6] Initial Verification: {verify_certificate(cert)}")
    
    # Simulate Tamper
    print("\n[!] SIMULATING SABOTAGE: Altering Trust Score in Memory...")
    tampered_cert = cert.copy()
    tampered_cert['trust_score'] = 0 # Change from 100
    print(f"[Step 7] Re-Verification: {verify_certificate(tampered_cert)}")
    
    # 7. Attack Simulation (Forensic Entropy)
    attack = simulate_attack()
    print(f"[Step 8] Forensic Result: {attack['result'] if 'result' in attack else attack['report']}")

if __name__ == "__main__":
    run_demo()