import hashlib
from datetime import datetime

def generate_certificate(device_id, trust_score, wipe_level):
    raw_data = f"{device_id}{trust_score}{wipe_level}{datetime.utcnow()}"
    cert_hash = hashlib.sha256(raw_data.encode()).hexdigest()

    return {
        "device_id": device_id,
        "timestamp": str(datetime.utcnow()),
        "trust_score": trust_score,
        "wipe_level": wipe_level,
        "hash": cert_hash
    }