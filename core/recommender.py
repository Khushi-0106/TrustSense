def recommend_wipe(scan_result):
    risk = scan_result["risk_level"]
    if risk == "High":
        level = "Advanced Multi-pass"
    elif risk == "Medium":
        level = "DoD 3-pass"
    else:
        level = "Basic"
    
    return {"wipe_level": level}