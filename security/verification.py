import hashlib
import json
import os
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

class TrustVerifier:
    def __init__(self, ledger_path='security/ledger.json'):
        self.ledger_path = ledger_path
        self.private_key_path = 'security/private_key.pem'
        self.public_key_path = 'security/public_key.pem'
        self._ensure_keys()

    def _ensure_keys(self):
        """Generates RSA keys if missing to fulfill digital signature requirement."""
        if not os.path.exists(self.private_key_path):
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open(self.private_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            public_key = private_key.public_key()
            with open(self.public_key_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

    def sign_certificate(self, certificate_data):
        """Signs data with private key to create a tamper-proof digital signature."""
        with open(self.private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        
        cert_bytes = json.dumps(certificate_data, sort_keys=True).encode()
        signature = private_key.sign(
            cert_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature.hex()

    def export_trust_certificate(self, device_id, wipe_method):
        """Generates a verifiable, digitally signed JSON certificate for the user."""
        cert_data = {
            "issuing_authority": "TrustSense Security Protocol",
            "device_id": device_id,
            "wipe_method": wipe_method,
            "timestamp": datetime.now().isoformat(),
            "status": "SUCCESS - VERIFIED"
        }
        cert_data["digital_signature"] = self.sign_certificate(cert_data)
        
        cert_filename = f"certificate_{device_id}.json"
        with open(cert_filename, 'w') as f:
            json.dump(cert_data, f, indent=4)
        return cert_data

    def update_ledger(self, new_entry):
        """Appends a new record to the hash-linked ledger.json."""
        if not os.path.exists(self.ledger_path):
            ledger = []
        else:
            with open(self.ledger_path, 'r') as f:
                ledger = json.load(f)

        prev_hash = ledger[-1]['current_hash'] if ledger else "0" * 64
        new_entry['previous_hash'] = prev_hash
        new_entry['timestamp'] = datetime.now().isoformat()
        
        # Hash current data + previous hash to create the chain
        hash_input = json.dumps(new_entry, sort_keys=True).encode()
        new_entry['current_hash'] = hashlib.sha256(hash_input).hexdigest()
        
        ledger.append(new_entry)
        with open(self.ledger_path, 'w') as f:
            json.dump(ledger, f, indent=4)
        return new_entry['current_hash']

    def verify_external_certificate(self, cert_data, signature_hex):
        """Enables third-party verification of the certificate using the public key."""
        with open(self.public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        
        data_to_verify = cert_data.copy()
        data_to_verify.pop("digital_signature", None)
        cert_bytes = json.dumps(data_to_verify, sort_keys=True).encode()
        
        try:
            public_key.verify(
                bytes.fromhex(signature_hex),
                cert_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except:
            return False