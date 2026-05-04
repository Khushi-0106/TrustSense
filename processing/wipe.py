import time

def simulate_wipe(wipe_level):
    time.sleep(1.5)

    # Normalize input
    level = wipe_level.lower()

    if "dod" in level:
        details = "Multi-pass DoD 5220.22-M wipe completed. Data overwritten 3 times."
    elif "advanced" in level or "gutmann" in level:
        details = "Advanced deep wipe completed. Gutmann-style passes applied."
    else:
        details = "Quick wipe completed. Temporary files cleared."

    return {
        "status": "completed",
        "wipe_level": wipe_level,
        "details": details
    }