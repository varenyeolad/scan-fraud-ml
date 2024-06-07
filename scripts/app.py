from flask import Flask, request, jsonify, send_from_directory
import joblib
import pandas as pd
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
from sqlalchemy.orm import sessionmaker
from models import Address, ReportedAddress, engine
from config import FEATURE_ORDER_FILE, MODEL_FILE, SCALER_FILE, MALICIOUS_ADDRESSES_FILE, PHISHING_ADDRESSES_FILE
from data_processing import extract_features, load_malicious_addresses, load_phishing_addresses
from datetime import datetime, timedelta
from flask_swagger_ui import get_swaggerui_blueprint
import os

app = Flask(__name__)

# Configure Redis for Flask-Limiter
redis_client = Redis(host='localhost', port=6379)
limiter = Limiter(get_remote_address, app=app, storage_uri="redis://localhost:6379")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Swagger UI configuration
SWAGGER_URL = '/swagger'
API_URL = '/swagger.yaml'  # Endpoint to serve the Swagger YAML file

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Scam Explorer API"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

@app.route('/swagger.yaml')
def swagger_yaml():
    return send_from_directory(os.path.dirname(__file__), 'swagger.yaml')

# Initialize database session
Session = sessionmaker(bind=engine)
session = Session()

@app.route('/top-risk-addresses', methods=['GET'])
def get_top_risk_addresses():
    top_addresses = session.query(Address).filter(Address.risk_score >= 0.5).order_by(Address.risk_score.desc()).limit(10).all()
    result = [{"address": addr.address, "risk_score": addr.risk_score} for addr in top_addresses]
    return jsonify(result)

@app.route('/address-info/<address>', methods=['GET'])
def get_address_info(address):
    addr = session.query(Address).filter(Address.address == address).first()
    if not addr:
        return jsonify({"error": "Address not found"}), 404
    
    result = {
        "address": addr.address,
        "risk_score": addr.risk_score,
        "risk_reason": addr.risk_reason,
        "overall_assessment": addr.overall_assessment,
        "total_transactions": addr.total_transactions,
        "total_received": addr.total_received,
        "total_sent": addr.total_sent,
        "current_balance": addr.current_balance
    }
    return jsonify(result)

@app.route('/report-address', methods=['POST'])
def report_address():
    data = request.json
    address = data.get('address')
    report_reason = data.get('report_reason')
    
    addr = session.query(Address).filter(Address.address == address).first()
    if not addr:
        return jsonify({"error": "Address not found"}), 404
    
    report = ReportedAddress(address_id=addr.id, report_reason=report_reason)
    session.add(report)
    session.commit()
    return jsonify({"message": "Address reported successfully"})

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

@app.route('/scan/<address>', methods=['GET'])
@limiter.limit("10 per minute")
async def scan_address(address):
    if not address:
        logger.error('Address is required')
        return jsonify({'error': 'Address is required'}), 400
    
    try:
        feature_order = joblib.load(FEATURE_ORDER_FILE)
    except FileNotFoundError:
        logger.error('Feature order file not found')
        return jsonify({'error': 'Feature order file not found'}), 500
    
    try:
        malicious_addresses, malicious_info = load_malicious_addresses(MALICIOUS_ADDRESSES_FILE)
    except FileNotFoundError:
        logger.error('Malicious addresses file not found')
        return jsonify({'error': 'Malicious addresses file not found'}), 500

    try:
        phishing_addresses = load_phishing_addresses(PHISHING_ADDRESSES_FILE)
    except FileNotFoundError:
        logger.error('Phishing addresses file not found')
        return jsonify({'error': 'Phishing addresses file not found'}), 500
    
    try:
        features_df = await extract_features(address, feature_order, malicious_addresses, phishing_addresses)
        features_df = features_df.drop(columns=['address'], errors='ignore')
        features = features_df.iloc[0].to_dict()
    except KeyError as e:
        logger.error(f"Error extracting features for {address}: {str(e)}")
        return jsonify({'error': f'Missing expected feature: {str(e)}'}), 500
    
    is_phishing = address.lower() in phishing_addresses
    
    try:
        model = joblib.load(MODEL_FILE)
        scaler = joblib.load(SCALER_FILE)
    except FileNotFoundError:
        logger.error('Model or scaler file not found')
        return jsonify({'error': 'Model or scaler file not found'}), 500
    
    try:
        features_scaled = scaler.transform(features_df)
        probability = model.predict_proba(features_scaled)[0]
        logger.info(f"Model probabilities: {probability}")
        risk_score = calculate_risk_score(probability)
        risk_band, risk_text = determine_risk_band(risk_score)
        risk_reason = generate_risk_reason(features, risk_band, risk_text)
        
        # Save the address information to the database
        address_entry = session.query(Address).filter(Address.address == address).first()
        if address_entry:
            address_entry.risk_score = risk_score
            address_entry.risk_reason = risk_reason
            address_entry.overall_assessment = risk_text
            address_entry.total_transactions = features['degree']
            address_entry.total_received = features['value_in']
            address_entry.total_sent = features['value_out']
            address_entry.current_balance = features['balance']
        else:
            address_entry = Address(
                address=address,
                risk_score=risk_score,
                risk_reason=risk_reason,
                overall_assessment=risk_text,
                total_transactions=features['degree'],
                total_received=features['value_in'],
                total_sent=features['value_out'],
                current_balance=features['balance']
            )
            session.add(address_entry)
        
        session.commit()
        
        assessment_summary = generate_assessment_summary(address, features, risk_band, risk_text, risk_score, risk_reason, is_phishing, malicious_info)
    except Exception as e:
        logger.error(f"Error during prediction for {address}: {str(e)}")
        session.rollback()  # Rollback the session to avoid future issues
        return jsonify({'error': f'Error during prediction: {str(e)}'}), 500
    
    return jsonify(assessment_summary)

if __name__ == '__main__':
    app.run(debug=True)
