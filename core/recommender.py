def recommend_wipe(scan_result):
    risk = scan_result.get("risk_level", "Low")
    sensitive = scan_result.get("sensitive_files", 0)
    total = scan_result.get("total_files", 1)
    
    if risk in ["High", "Critical"]:
        level = "DoD 5220.22-M (7-Pass)"
        reason = f"Forensic analysis detected {sensitive} high-risk artifacts out of {total} total objects. Due to the presence of sensitive data structures, a rigorous Department of Defense (DoD) 5220.22-M standard 7-pass cryptographic wipe is mandated to ensure zero-bit recovery against advanced forensic reconstruction."
    elif risk == "Medium":
        level = "DoD 5220.22-M (3-Pass)"
        reason = f"Forensic analysis identified moderate risk vectors among {total} objects. A DoD 5220.22-M standard 3-pass cryptographic wipe is recommended to neutralize residual metadata and prevent unauthorized data extraction."
    else:
        level = "Secure Erase (1-Pass)"
        reason = f"Routine data footprint detected across {total} objects. A standard cryptographic Secure Erase (1-pass) is sufficient to permanently sanitize the target directory while minimizing hardware degradation."
    
    return {
        "wipe_level": level,
        "ai_reason": reason
    }