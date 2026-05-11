import hashlib
from datetime import datetime

def generate_certificate(device_id, trust_score, wipe_level):
    now = str(datetime.utcnow())
    raw_data = f"{device_id}{now}{trust_score}{wipe_level}"
    cert_hash = hashlib.sha256(raw_data.encode()).hexdigest()

    return {
        "device_id": device_id,
        "timestamp": now,
        "trust_score": trust_score,
        "wipe_level": wipe_level,
        "hash": cert_hash
    }