import time

def simulate_wipe(wipe_level):
    """
    Simulates different levels of data wiping with a slight processing delay.
    """
    time.sleep(1.5)  # Slight delay to simulate disk I/O
    
    wipe_configs = {
        "Basic": "Quick wipe completed. Temporary files cleared and pointers removed.",
        "DoD": "Multi-pass DoD 5220.22-M wipe completed. Data overwritten 3 times.",
        "Advanced": "Advanced deep wipe completed. Gutmann-style passes applied to sensitive sectors."
    }
    
    # Default to Basic if level is unrecognized
    details = wipe_configs.get(wipe_level, "Standard wipe completed.")
    
    return {
        "status": "completed",
        "details": details
    }