import os
import sys
from flask import Flask, request, jsonify
from flask_cors import CORS

# Add parent directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.scanner import scan_data
from core.recommender import recommend_wipe
from processing.trust_score import calculate_trust_score
from processing.neo_pdf import generate_neo_pdf
from processing.certificate import generate_certificate

app = Flask(__name__)
CORS(app)

DEMO_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'demo_files'))

@app.route('/')
def home():
    return jsonify({"status": "online", "platform": "TrustSense+ REST API"})

@app.route('/api/scan', methods=['POST', 'GET'])
def scan():
    target_path = DEMO_PATH
    if request.is_json:
        target_path = request.json.get('path', DEMO_PATH)
    
    # If the user tries to scan a random C:\ drive path, it won't exist on Vercel.
    # Fallback to demo path if the path doesn't exist to prevent crashes.
    if not os.path.exists(target_path):
        target_path = DEMO_PATH

    results = scan_data(target_path)
    score_data = calculate_trust_score(results)
    recommendation_data = recommend_wipe(results)
    
    return jsonify({
        "results": results,
        "score": score_data["trust_score"],
        "recommendation": recommendation_data["wipe_level"],
        "ai_reason": recommendation_data["ai_reason"]
    })

@app.route('/api/certify', methods=['POST'])
def certify():
    data = request.json
    device_id = data.get('device_id', 'TS-UNIT-01')
    trust_score = data.get('trust_score', 100)
    wipe_level = data.get('wipe_level', 'Secure Wipe')
    
    cert = generate_certificate(device_id, trust_score, wipe_level)
    
    return jsonify({
        "cert": cert
    })

@app.route('/api/certificate', methods=['POST'])
def certificate():
    data = request.json
    try:
        pdf_bytes = generate_neo_pdf(data)
        import base64
        pdf_base64 = base64.b64encode(pdf_bytes).decode()
        return jsonify({"pdf_base64": pdf_base64})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
