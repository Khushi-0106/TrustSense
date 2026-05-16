def recommend_wipe(scan_result):
    risk = scan_result["risk_level"]
    risk_counts = scan_result.get("risk_counts", {})
    
    if risk in ["High", "Critical"]:
        level = "Advanced Multi-pass"
        reason = f"Detected {risk_counts.get('High', 0)} High-Risk assets and {risk_counts.get('Hidden', 0)} hidden forensic artifacts. This requires a deep NIST 800-88 purge to ensure zero-bit recovery."
    elif risk == "Medium":
        level = "DoD 3-pass"
        reason = f"Medium risk profile with {risk_counts.get('Medium', 0)} active vulnerabilities. Standard DoD 5220.22-M overwrite is sufficient for enterprise-grade sanitization."
    else:
        level = "Basic"
        reason = "No critical forensic signatures found. Basic single-pass sanitization is verified for low-risk data profiles."
    
    return {"wipe_level": level, "reason": reason}