import json
import hashlib
import os

LEDGER_FILE = "security/ledger.json"

def store_certificate(cert):
    ledger = []
    if os.path.exists(LEDGER_FILE):
        with open(LEDGER_FILE, 'r') as f:
            ledger = json.load(f)
    
    ledger.append(cert)
    with open(LEDGER_FILE, 'w') as f:
        json.dump(ledger, f, indent=4)

def verify_certificate(cert_to_check):
    """
    Re-calculates the hash of the provided certificate.
    If any character has changed, the verification will fail.
    """
    raw_payload = f"{cert_to_check['device_id']}{cert_to_check['timestamp']}{cert_to_check['trust_score']}{cert_to_check['wipe_level']}"
    calculated_hash = hashlib.sha256(raw_payload.encode()).hexdigest()
    
    if calculated_hash == cert_to_check['hash']:
        return "Valid"
    else:
        return "INTEGRITY BREACH: UNAUTHORIZED MODIFICATION DETECTED"