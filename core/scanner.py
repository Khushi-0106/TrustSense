import random

def scan_data():
    """
    Simulates a file system scan and returns a formatted result dictionary.
    """
    hidden = random.randint(0, 10)
    temp = random.randint(0, 10)
    sensitive = random.randint(0, 5)

    # Risk Assessment Logic
    if sensitive > 3:
        risk = "High"
    elif temp > 3:
        risk = "Medium"
    else:
        risk = "Low"

    scan_result = {
        "hidden_files": hidden,
        "temp_files": temp,
        "sensitive_files": sensitive,
        "risk_level": risk
    }

    return scan_result
