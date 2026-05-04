def calculate_trust_score(scan_result):
    hidden = scan_result["hidden_files"]
    temp = scan_result["temp_files"]
    sensitive = scan_result["sensitive_files"]

    score = 100

    # Penalty system
    score -= hidden * 2
    score -= temp * 3
    score -= sensitive * 10

    if score < 0:
        score = 0

    return {
        "trust_score": score
    }