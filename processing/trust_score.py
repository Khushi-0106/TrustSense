def calculate_trust_score(scan_result, after_wipe=False):
    """
    Calculates trust score based on scan results and whether a wipe was performed.
    """
    hidden = scan_result.get("hidden_files", 0)
    temp = scan_result.get("temp_files", 0)
    sensitive = scan_result.get("sensitive_files", 0)
    
    # Calculate base score
    reduction = (hidden * 5) + (temp * 2) + (sensitive * 10)
    trust = 100 - reduction
    
    if after_wipe:
        # Boost trust after remediation, capped at 95
        trust = min(95, trust + 50)
    
    # Ensure score doesn't drop below 0
    trust = max(0, trust)
    
    return {
        "trust_score": int(trust)
    }