from flask import request, jsonify
from functools import wraps
from config import API_KEYS

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-KEY')
        if api_key not in API_KEYS:
            return jsonify({"error": "Unauthorized access"}), 401
        return f(*args, **kwargs)
    return decorated_function

def is_valid_ethereum_address(address):
    import re
    # Check if the address starts with '0x' and is 42 characters long
    if not address.startswith('0x') or len(address) != 42:
        return False
    
    # Check if all characters after '0x' are valid hexadecimal characters
    return bool(re.match(r'^0x[a-fA-F0-9]{40}$', address))

def calculate_risk_score(probability):
    return probability[1]  # Probability of the address being fraudulent

def determine_risk_band(risk_score):
    if risk_score >= 0.8:
        return 1, "Very High Risk"
    elif risk_score >= 0.6:
        return 2, "High Risk"
    elif risk_score >= 0.4:
        return 3, "Medium Risk"
    elif risk_score >= 0.2:
        return 4, "Low Risk"
    else:
        return 5, "Very Low Risk"

def generate_risk_reason(features, risk_band, risk_text):
    reasons = []

    # Define thresholds
    HIGH_OUTGOING_THRESHOLD = 0.01
    HIGH_TX_INTERVAL_THRESHOLD = 3600  # 1 hour in seconds
    
    if risk_band in [1, 2]:  # High Risk
        if features.get('interacted_with_malicious', 0):
            reasons.append("Address has interactions with known malicious addresses.")
        if features['value_out'] > features['value_in']:
            reasons.append("High outgoing transaction volume compared to incoming volume.")
        if features['degree_out'] > features['degree_in']:
            reasons.append("High number of outgoing transactions compared to incoming transactions.")
        if features.get('malicious_interactions_count', 0) > 0:
            reasons.append(f"Number of interactions with malicious addresses: {features['malicious_interactions_count']}.")
        if features['min_value_out'] < HIGH_OUTGOING_THRESHOLD:
            reasons.append("Minimum Ether amount sent is very low.")
        if features['avg_in_tx_interval'] > HIGH_TX_INTERVAL_THRESHOLD:
            reasons.append("Average time between inward transactions is high.")
        if not reasons:
            reasons.append("High risk score detected by the model despite no specific indicators.")
    elif risk_band in [4, 5]:  # Low Risk
        if not features.get('interacted_with_malicious', 0):
            reasons.append("No interactions with known malicious addresses.")
        if features['value_in'] > features['value_out']:
            reasons.append("High incoming transaction volume compared to outgoing volume.")
        if features['degree_in'] > features['degree_out']:
            reasons.append("High number of incoming transactions compared to outgoing transactions.")
        if not reasons:
            reasons.append("Low risk score detected by the model despite no specific indicators.")

    return " | ".join(reasons)

def generate_assessment_summary(address, features, risk_band, risk_text, risk_score, risk_reason, is_phishing, malicious_info):
    summary = {
        "address": address,
        "overall_assessment": risk_text,
        "risk_score": risk_score,
        "blacklist_search_result": "Found in Etherscan Blacklist" if features.get('interacted_with_malicious', 0) else "Not found in blacklist",
        "blacklist_category": malicious_info.get(address.lower(), {}).get('category', "N/A"),
        "phishing_dataset_check": "Found in phishing dataset" if is_phishing else "Not found in phishing dataset",
        "transaction_tracing_result": "No evidence of links to known blacklisted wallets",
        "whitelist_search_result": "Not found in our whitelist of known entities",
        "total_transactions": features['degree'],
        "total_received": features['value_in'],
        "total_sent": features['value_out'],
        "current_balance": features['balance'],
        "ml_analysis_result": f"High-risk score of {risk_score} indicates potential fraud or scam",
        "top_features_influencing_ml_analysis": risk_reason
    }
    return summary
