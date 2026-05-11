import os
import sys
from flask import Flask, request, jsonify
from flask_cors import CORS
import tempfile

# Add parent directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.scanner import scan_data
from processing.trust_score import calculate_trust_score
from processing.certificate import generate_certificate
from processing.wipe import simulate_wipe

app = Flask(__name__)
CORS(app)

DEMO_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'demo_files'))

@app.route('/')
def home():
    return jsonify({
        "status": "online",
        "platform": "TrustSense+ Cloud Demo",
        "version": "Anti-Gravity 2.0"
    })

@app.route('/api/scan', methods=['POST', 'GET'])
def scan():
    target_path = DEMO_PATH
    if request.is_json:
        target_path = request.json.get('path', DEMO_PATH)
    
    scan_result = scan_data(target_path)
    trust_score = calculate_trust_score(scan_result)
    
    return jsonify({
        "scan_result": scan_result,
        "trust_score": trust_score
    })

@app.route('/api/wipe', methods=['POST'])
def wipe():
    data = request.json
    target_path = data.get('path', DEMO_PATH)
    wipe_level = data.get('level', 'Secure Wipe')
    device_id = data.get('device_id', 'TS-CLOUD-DEMO')

    wipe_status = simulate_wipe(target_path, wipe_level)
    new_scan = scan_data(target_path)
    after_score = calculate_trust_score(new_scan)
    cert = generate_certificate(device_id, after_score["trust_score"], wipe_level)
    
    return jsonify({
        "wipe_status": wipe_status,
        "after_score": after_score,
        "certificate": cert
    })
