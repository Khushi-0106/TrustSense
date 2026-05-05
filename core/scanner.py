import os
import re
from collections import defaultdict

SENSITIVE_KEYWORDS = [
    'password', 'secret', 'api_key', 'access_token', 'credentials',
    'confidential', 'private_key', 'ssn', 'social security',
    'bank account', 'credit card', 'internal only', 'proprietary'
]

def is_content_sensitive(file_path):
    """
    Checks if the file content contains sensitive keywords.
    Only scans the first 8KB to keep it fast.
    """
    try:
        # Avoid scanning very large binary files if possible, but check if it's text-like
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(8192).lower()
            for keyword in SENSITIVE_KEYWORDS:
                if keyword in content:
                    return True
    except:
        pass
    return False

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

            # NEW: Content-based sensitivity detection
            is_sensitive = False
            
            # Check by extension first (legacy but still useful for speed)
            if ext in ['.key', '.pem', '.env', '.config']:
                is_sensitive = True
            
            # Deep content scan for text/code files
            if not is_sensitive and ext in ['.txt', '.pdf', '.docx', '.csv', '.xlsx', '.json', '.yaml', '.py', '.js', '.sh', '.bat']:
                if is_content_sensitive(full_path):
                    is_sensitive = True
            
            if is_sensitive:
                sensitive += 1
                
            # High risk executable/script types (still flagged by type as well)
            if ext in ['.exe', '.sh', '.bat', '.ps1']:
                sensitive += 1 # extra weight

    if sensitive > 10:
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
        "files": files_list[:50]
    }