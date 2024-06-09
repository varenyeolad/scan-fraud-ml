from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from models import Address, Base
from config import FEATURE_ORDER_FILE, MODEL_FILE, SCALER_FILE, MALICIOUS_ADDRESSES_FILE, PHISHING_ADDRESSES_FILE
from data_processing import extract_features, load_malicious_addresses, load_phishing_addresses
from datetime import datetime, timezone
import joblib

# Database connection URL
DATABASE_URL = "postgresql://user:password@localhost:5432/scamexplorer"

# Create engine and session
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# Load the model and scaler
scaler = joblib.load(SCALER_FILE)
model = joblib.load(MODEL_FILE)

# Load feature order and address data
feature_order = joblib.load(FEATURE_ORDER_FILE)
malicious_addresses, malicious_info = load_malicious_addresses(MALICIOUS_ADDRESSES_FILE)
phishing_addresses = load_phishing_addresses(PHISHING_ADDRESSES_FILE)

# Load all addresses
addresses = session.query(Address).all()

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

# Update each address
for address_entry in addresses:
    try:
        features_df = extract_features(address_entry.address, feature_order, malicious_addresses, phishing_addresses)
        features_df = features_df.drop(columns=['address'], errors='ignore')
        features = features_df.iloc[0].to_dict()

        features_scaled = scaler.transform(features_df)
        probability = model.predict_proba(features_scaled)[0]
        risk_score = calculate_risk_score(probability)
        risk_band, risk_text = determine_risk_band(risk_score)
        risk_reason = generate_risk_reason(features, risk_band, risk_text)

        # Update the address information
        address_entry.risk_score = risk_score
        address_entry.risk_reason = risk_reason
        address_entry.overall_assessment = risk_text
        address_entry.total_transactions = features['degree']
        address_entry.total_received = features['value_in']
        address_entry.total_sent = features['value_out']
        address_entry.current_balance = features['balance']
        address_entry.last_scanned = datetime.now(timezone.utc)
        address_entry.blacklist_category = malicious_info.get(address_entry.address.lower(), {}).get('category', "N/A")
        address_entry.blacklist_search_result = "Found in Etherscan Blacklist" if features.get('interacted_with_malicious', 0) else "Not found in blacklist"
        address_entry.phishing_dataset_check = "Found in phishing dataset" if address_entry.address.lower() in phishing_addresses else "Not found in phishing dataset"
        address_entry.transaction_tracing_result = "No evidence of links to known blacklisted wallets"
        address_entry.whitelist_search_result = "Not found in our whitelist of known entities"

    except Exception as e:
        print(f"Error updating address {address_entry.address}: {str(e)}")
        session.rollback()  # Rollback the session to avoid future issues
        continue

# Commit the session to save changes
session.commit()
session.close()

print("Database updated successfully")
