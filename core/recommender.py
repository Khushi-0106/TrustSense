def recommend_wipe(scan_result):
    """
    Determines the appropriate data destruction protocol based on risk level.
    """
    risk = scan_result.get("risk_level")

    if risk == "High":
        wipe_type = "Advanced Multi-pass"
    elif risk == "Medium":
        wipe_type = "DoD 3-pass"
    else:
        wipe_type = "Basic"

    return {
        "wipe_level": wipe_type
    }
