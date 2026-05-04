import hashlib
from datetime import datetime

def generate_certificate(device_id, trust_score, wipe_level):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # FEATURE 2: Create a unique hash for the tamper-proof demo
    raw_payload = f"{device_id}{timestamp}{trust_score}{wipe_level}"
    cert_hash = hashlib.sha256(raw_payload.encode()).hexdigest()
    
    return {
        "device_id": device_id,
        "timestamp": timestamp,
        "trust_score": trust_score,
        "wipe_level": wipe_level,
        "hash": cert_hash
    }