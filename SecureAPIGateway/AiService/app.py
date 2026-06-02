from flask import Flask, request, jsonify
import numpy as np
import joblib
import re

app = Flask(__name__)

model = joblib.load("model/anomaly_model.pkl")
scaler = joblib.load("model/scaler.pkl")
features = joblib.load("model/features.pkl")

def has_suspicious_chars(text):
    if not text:
        return 0

    pattern = r"('|--|;|<script|>|union|select|drop|insert|delete)"
    return 1 if re.search(pattern, text, re.IGNORECASE) else 0

def extract_features(data):
    return np.array([[
        float(data.get("flowDuration", 0)),
        float(data.get("totalFwdPackets", 1)),
        float(data.get("totalBackwardPackets", 0)),
        float(data.get("totalLengthFwdPackets", data.get("bodyLength", 0))),
        float(data.get("totalLengthBwdPackets", 0)),
        float(data.get("flowBytesPerSecond", 0)),
        float(data.get("flowPacketsPerSecond", data.get("requestRate", 0)))
    ]])

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json() or {}

    combined_text = (
        data.get("queryString", "") + " " +
        data.get("path", "") + " " +
        data.get("body", "")
    )

    if has_suspicious_chars(combined_text):
        return jsonify({
            "isMalicious": True,
            "confidenceScore": 0.95,
            "threatType": "SQL Injection / Suspicious Payload"
        })

    request_features = extract_features(data)
    scaled_features = scaler.transform(request_features)

    prediction = model.predict(scaled_features)[0]
    anomaly_score = model.decision_function(scaled_features)[0]

    is_malicious = prediction == -1
    confidence = min(1.0, max(0.0, abs(anomaly_score)))

    threat_type = "Normal"

    if is_malicious:
        if float(data.get("flowPacketsPerSecond", data.get("requestRate", 0))) > 80:
            threat_type = "API Abuse / DDoS"
        elif float(data.get("totalLengthFwdPackets", data.get("bodyLength", 0))) > 5000:
            threat_type = "Large Payload Anomaly"
        else:
            threat_type = "General Network/API Anomaly"

    return jsonify({
        "isMalicious": bool(is_malicious),
        "confidenceScore": round(float(confidence), 3),
        "threatType": threat_type
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "AI service running"})

if __name__ == "__main__":
    print("Starting AI service...")
    app.run(host="0.0.0.0", port=5001, debug=True)