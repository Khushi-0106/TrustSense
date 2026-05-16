import os
import re
from collections import defaultdict
import ctypes

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
    file_details = []

    if not os.path.exists(path):
        return {
            "total_files": 0, "total_folders": 0, "hidden_files": 0, "temp_files": 0,
            "sensitive_files": 0, "max_depth": 0, "file_types": {},
            "risk_level": "Low", "files": [], "file_details": [],
            "risk_counts": {"High": 0, "Medium": 0, "Low": 0, "Hidden": 0}
        }

    base_depth = path.rstrip(os.path.sep).count(os.path.sep)
    risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Hidden": 0}

    for root, dirs, files in os.walk(path):
        total_folders += len(dirs)
        current_depth = root.count(os.path.sep) - base_depth
        if current_depth > max_depth:
            max_depth = current_depth

        for file in files:
            total_files += 1
            full_path = os.path.join(root, file)
            ext = os.path.splitext(file)[1].lower()
            
            if ext: file_types[ext] += 1
            else: file_types["No Extension"] += 1

            # ── Hidden Detection ──
            is_hidden = file.startswith('.')
            if not is_hidden and os.name == 'nt':
                try:
                    attrs = ctypes.windll.kernel32.GetFileAttributesW(full_path)
                    is_hidden = bool(attrs & 2)
                except: pass
            
            if is_hidden: 
                hidden += 1
                risk_counts["Hidden"] += 1

            # ── Sensitivity Detection ──
            risk_score = 0 # 0=Low, 1=Medium, 2+=High
            
            # Extension matches
            if ext in ['.key', '.pem', '.env', '.config', '.bak', '.old']:
                risk_score += 2
            elif ext in ['.txt', '.pdf', '.docx', '.json', '.yaml', '.sh', '.bat', '.ps1']:
                risk_score += 1
            
            # Content match
            if ext in ['.txt', '.json', '.py', '.js', '.sh', '.bat', '.ps1']:
                if is_content_sensitive(full_path):
                    risk_score += 2

            # Categorization
            if risk_score >= 2:
                risk_label = "High"
                sensitive += 1
                risk_counts["High"] += 1
            elif risk_score == 1:
                risk_label = "Medium"
                risk_counts["Medium"] += 1
            else:
                risk_label = "Low"
                risk_counts["Low"] += 1
            
            file_details.append({
                "name": file,
                "path": full_path,
                "risk": risk_label,
                "hidden": is_hidden,
                "size": os.path.getsize(full_path)
            })

    if risk_counts["High"] > 5: risk = "Critical"
    elif risk_counts["High"] > 0: risk = "High"
    elif risk_counts["Medium"] > 5: risk = "Medium"
    else: risk = "Low"

    return {
        "total_files": total_files,
        "total_folders": total_folders,
        "hidden_files": hidden,
        "sensitive_files": sensitive,
        "max_depth": max_depth,
        "file_types": dict(file_types),
        "risk_level": risk,
        "file_details": file_details,
        "risk_counts": risk_counts
    }