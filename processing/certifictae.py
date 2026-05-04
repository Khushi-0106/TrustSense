import hashlib
from datetime import datetime

def generate_certificate(device_id, trust_score, wipe_level):
    """
    Generates a secure JSON certificate for device verification.
    """
    timestamp = datetime.now().isoformat()
    
    # Prepare data for hashing
    # Format: device_id + timestamp + trust_score + wipe_level
    raw_string = f"{device_id}{timestamp}{trust_score}{wipe_level}"
    cert_hash = hashlib.sha256(raw_string.encode()).hexdigest()
    
    return {
        "device_id": str(device_id),
        "timestamp": timestamp,
        "trust_score": int(trust_score),
        "wipe_level": str(wipe_level),
        "hash": cert_hash
    }