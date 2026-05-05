def calculate_trust_score(scan_result):
    total_files = scan_result.get("total_files", 0)
    total_folders = scan_result.get("total_folders", 0)
    hidden = scan_result.get("hidden_files", 0)
    temp = scan_result.get("temp_files", 0)
    sensitive = scan_result.get("sensitive_files", 0)
    file_types = scan_result.get("file_types", {})
    max_depth = scan_result.get("max_depth", 0)

    score = 100

    if total_files == 0 and total_folders == 0:
        return {"trust_score": 100} # Perfectly clean

    # Penalty system
    score -= hidden * 2
    score -= temp * 1.5
    score -= sensitive * 5

    # High-risk file penalties
    exe_count = file_types.get('.exe', 0)
    script_count = file_types.get('.sh', 0) + file_types.get('.bat', 0) + file_types.get('.ps1', 0)
    score -= exe_count * 15
    score -= script_count * 10

    # Complexity penalty
    if total_files > 1000:
        score -= 5
    if max_depth > 10:
        score -= 5

    # Ensure score bounds
    if score < 0:
        score = 0
    if score > 100:
        score = 100

    return {
        "trust_score": int(score)
    }