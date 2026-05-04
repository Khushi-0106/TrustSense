import json
import os

LEDGER_FILE = "security/ledger.json"

def store_certificate(cert):
    # Load existing data
    if os.path.exists(LEDGER_FILE):
        with open(LEDGER_FILE, "r") as f:
            try:
                data = json.load(f)
            except:
                data = []
    else:
        data = []

    # Add certificate
    data.append(cert)

    # Save back
    with open(LEDGER_FILE, "w") as f:
        json.dump(data, f, indent=4)


def verify_certificate(cert):
    if not os.path.exists(LEDGER_FILE):
        return False

    with open(LEDGER_FILE, "r") as f:
        data = json.load(f)

    for entry in data:
        if entry.get("hash") == cert.get("hash"):
            return True

    return False