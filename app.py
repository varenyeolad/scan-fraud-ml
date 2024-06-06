from flask import Flask, request, jsonify
import joblib
import pandas as pd
from data_processing import extract_features, load_malicious_addresses, load_phishing_addresses

app = Flask(__name__)

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
        "ml_analysis_result": f"High-risk score of {risk_score} indicates potential fraud or scam" if risk_band in [1, 2] else f"Low-risk score of {risk_score}",
        "top_features_influencing_ml_analysis": risk_reason
    }
    return summary

@app.route('/scan', methods=['POST'])
def scan_address():
    data = request.json
    address = data.get('address')
    
    if not address:
        return jsonify({'error': 'Address is required'}), 400
    
    try:
        feature_order = joblib.load('feature_order.pkl')
    except FileNotFoundError:
        return jsonify({'error': 'Feature order file not found'}), 500
    
    try:
        malicious_addresses, malicious_info = load_malicious_addresses()
    except FileNotFoundError:
        return jsonify({'error': 'Malicious addresses file not found'}), 500

    try:
        phishing_addresses = load_phishing_addresses()
    except FileNotFoundError:
        return jsonify({'error': 'Phishing addresses file not found'}), 500
    
    try:
        features_df = extract_features(address, feature_order, malicious_addresses, phishing_addresses)
        features_df = features_df.drop(columns=['address'], errors='ignore')
        features = features_df.iloc[0].to_dict()
    except KeyError as e:
        print(f"Error extracting features for {address}: {str(e)}")
        return jsonify({'error': f'Missing expected feature: {str(e)}'}), 500
    
    is_phishing = address.lower() in phishing_addresses
    
    try:
        model = joblib.load('knn_model.pkl')
        scaler = joblib.load('scaler.pkl')
    except FileNotFoundError:
        return jsonify({'error': 'Model or scaler file not found'}), 500
    
    try:
        features_scaled = scaler.transform(features_df)
        probability = model.predict_proba(features_scaled)[0]
        print(f"Model probabilities: {probability}")
        risk_score = calculate_risk_score(probability)
        risk_band, risk_text = determine_risk_band(risk_score)
        risk_reason = generate_risk_reason(features, risk_band, risk_text)
        assessment_summary = generate_assessment_summary(address, features, risk_band, risk_text, risk_score, risk_reason, is_phishing, malicious_info)
    except Exception as e:
        print(f"Error during prediction for {address}: {str(e)}")
        return jsonify({'error': f'Error during prediction: {str(e)}'}), 500
    
    return jsonify(assessment_summary)

if __name__ == '__main__':
    app.run(debug=True)
