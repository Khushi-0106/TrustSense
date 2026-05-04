import os

def scan_data(path):
    hidden = 0
    temp = 0
    sensitive = 0
    files_list = []

    for root, dirs, files in os.walk(path):
        for file in files:
            full_path = os.path.join(root, file)
            files_list.append(full_path)

            if file.startswith('.'):
                hidden += 1

            if file.endswith(('.tmp', '.log')):
                temp += 1

            if file.endswith(('.txt', '.pdf', '.docx')):
                sensitive += 1

    if sensitive > 3:
        risk = "High"
    elif sensitive > 1:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "hidden_files": hidden,
        "temp_files": temp,
        "sensitive_files": sensitive,
        "risk_level": risk,
        "files": files_list[:10]
    }