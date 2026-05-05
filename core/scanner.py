import os
from collections import defaultdict

def scan_data(path):
    hidden = 0
    temp = 0
    sensitive = 0
    total_files = 0
    total_folders = 0
    max_depth = 0
    file_types = defaultdict(int)
    files_list = []

    if not os.path.exists(path):
        return {
            "total_files": 0, "total_folders": 0, "hidden_files": 0, "temp_files": 0,
            "sensitive_files": 0, "max_depth": 0, "file_types": {},
            "risk_level": "Low", "files": []
        }

    base_depth = path.rstrip(os.path.sep).count(os.path.sep)

    for root, dirs, files in os.walk(path):
        total_folders += len(dirs)
        current_depth = root.count(os.path.sep) - base_depth
        if current_depth > max_depth:
            max_depth = current_depth

        for file in files:
            total_files += 1
            full_path = os.path.join(root, file)
            clean_name = file
            files_list.append(clean_name)

            ext = os.path.splitext(file)[1].lower()
            if ext:
                file_types[ext] += 1
            else:
                file_types["No Extension"] += 1

            if file.startswith('.') or any(part.startswith('.') for part in root.split(os.path.sep)):
                hidden += 1

            if ext in ['.tmp', '.log', '.bak', '.swp']:
                temp += 1

            if ext in ['.txt', '.pdf', '.docx', '.csv', '.xlsx', '.json', '.yaml', '.key', '.pem']:
                sensitive += 1
                
            # High risk executable/script types
            if ext in ['.exe', '.sh', '.bat', '.ps1', '.py', '.js']:
                sensitive += 2 # weighted higher for risk

    if sensitive > 10 or file_types.get('.exe', 0) > 0:
        risk = "Critical"
    elif sensitive > 5:
        risk = "High"
    elif sensitive > 1:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "total_files": total_files,
        "total_folders": total_folders,
        "hidden_files": hidden,
        "temp_files": temp,
        "sensitive_files": sensitive,
        "max_depth": max_depth,
        "file_types": dict(file_types),
        "risk_level": risk,
        "files": files_list[:50] # Top 50 clean names
    }