import joblib
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta, timezone
import logging

from models import Address, ReportedAddress, engine
from config import FEATURE_ORDER_FILE, MODEL_FILE, SCALER_FILE, MALICIOUS_ADDRESSES_FILE, PHISHING_ADDRESSES_FILE
from data_processing import extract_features, load_malicious_addresses, load_phishing_addresses
from utils import calculate_risk_score, determine_risk_band, generate_risk_reason, generate_assessment_summary

logger = logging.getLogger(__name__)

# Initialize database session
Session = sessionmaker(bind=engine)
session = Session()

# Load the model and scaler once at the start
scaler = joblib.load(SCALER_FILE)
model = joblib.load(MODEL_FILE)

def get_top_risk_addresses():
    top_addresses = session.query(Address).filter(Address.risk_score >= 0.6).order_by(Address.risk_score.desc()).limit(10).all()
    result = [{"address": addr.address, "risk_score": addr.risk_score} for addr in top_addresses]
    return result

def get_address_info(address):
    addr = session.query(Address).filter(Address.address == address).first()
    if not addr:
        return {"error": "Address not found"}, 404

    if datetime.now(timezone.utc) - addr.last_scanned > timedelta(hours=24):
        try:
            feature_order = joblib.load(FEATURE_ORDER_FILE)
            malicious_addresses, malicious_info = load_malicious_addresses(MALICIOUS_ADDRESSES_FILE)
            phishing_addresses = load_phishing_addresses(PHISHING_ADDRESSES_FILE)
            features_df = extract_features(addr.address, feature_order, malicious_addresses, phishing_addresses)
            features_df = features_df.drop(columns=['address'], errors='ignore')
            features = features_df.iloc[0].to_dict()
            features_scaled = scaler.transform(features_df)
            probability = model.predict_proba(features_scaled)[0]
            risk_score = calculate_risk_score(probability)
            risk_band, risk_text = determine_risk_band(risk_score)
            risk_reason = generate_risk_reason(features, risk_band, risk_text)

            addr.risk_score = risk_score
            addr.risk_reason = risk_reason
            addr.overall_assessment = risk_text
            addr.total_transactions = features['degree']
            addr.total_received = features['value_in']
            addr.total_sent = features['value_out']
            addr.current_balance = features['balance']
            addr.last_scanned = datetime.now(timezone.utc)
            session.commit()
        except Exception as e:
            logger.error(f"Error updating address {addr.address}: {str(e)}")
            session.rollback()  # Rollback the session to avoid future issues

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
    return result

def report_address(address, report_reason):
    addr = session.query(Address).filter(Address.address == address).first()
    if not addr:
        return {"error": "Address not found"}, 404

    report = ReportedAddress(address_id=addr.id, report_reason=report_reason)
    session.add(report)
    session.commit()
    return {"message": "Address reported successfully"}

async def scan_address(address):
    address_entry = session.query(Address).filter(Address.address == address).first()
    if address_entry and datetime.now(timezone.utc) - address_entry.last_scanned < timedelta(hours=24):
        result = {
            "address": address_entry.address,
            "risk_score": address_entry.risk_score,
            "ml_analysis_result": address_entry.risk_reason,
            "overall_assessment": address_entry.overall_assessment,
            "total_transactions": address_entry.total_transactions,
            "total_received": address_entry.total_received,
            "total_sent": address_entry.total_sent,
            "current_balance": address_entry.current_balance,
            "blacklist_category": address_entry.blacklist_category,
            "blacklist_search_result": address_entry.blacklist_search_result,
            "phishing_dataset_check": address_entry.phishing_dataset_check,
            "transaction_tracing_result": address_entry.transaction_tracing_result,
            "whitelist_search_result": address_entry.whitelist_search_result
        }
        return result

    try:
        feature_order = joblib.load(FEATURE_ORDER_FILE)
        malicious_addresses, malicious_info = load_malicious_addresses(MALICIOUS_ADDRESSES_FILE)
        phishing_addresses = load_phishing_addresses(PHISHING_ADDRESSES_FILE)
        features_df = await extract_features(address, feature_order, malicious_addresses, phishing_addresses)
        features_df = features_df.drop(columns=['address'], errors='ignore')
        features = features_df.iloc[0].to_dict()
    except KeyError as e:
        logger.error(f"Error extracting features for {address}: {str(e)}")
        return {'error': f'Missing expected feature: {str(e)}'}, 500

    is_phishing = address.lower() in phishing_addresses

    try:
        features_scaled = scaler.transform(features_df)
        probability = model.predict_proba(features_scaled)[0]
        logger.info(f"Model probabilities: {probability}")
        risk_score = calculate_risk_score(probability)
        risk_band, risk_text = determine_risk_band(risk_score)
        risk_reason = generate_risk_reason(features, risk_band, risk_text)

        if address_entry:
            address_entry.risk_score = risk_score
            address_entry.risk_reason = risk_reason
            address_entry.overall_assessment = risk_text
            address_entry.total_transactions = features['degree']
            address_entry.total_received = features['value_in']
            address_entry.total_sent = features['value_out']
            address_entry.current_balance = features['balance']
            address_entry.blacklist_category = malicious_info.get(address.lower(), {}).get('category', "N/A")
            address_entry.blacklist_search_result = "Found in Etherscan Blacklist" if features.get('interacted_with_malicious', 0) else "Not found in blacklist"
            address_entry.phishing_dataset_check = "Found in phishing dataset" if is_phishing else "Not found in phishing dataset"
            address_entry.transaction_tracing_result = "No evidence of links to known blacklisted wallets"
            address_entry.whitelist_search_result = "Not found in our whitelist of known entities"
            address_entry.last_scanned = datetime.now(timezone.utc)
        else:
            address_entry = Address(
                address=address,
                risk_score=risk_score,
                risk_reason=risk_reason,
                overall_assessment=risk_text,
                total_transactions=features['degree'],
                total_received=features['value_in'],
                total_sent=features['value_out'],
                current_balance=features['balance'],
                blacklist_category=malicious_info.get(address.lower(), {}).get('category', "N/A"),
                blacklist_search_result="Found in Etherscan Blacklist" if features.get('interacted_with_malicious', 0) else "Not found in blacklist",
                phishing_dataset_check="Found in phishing dataset" if is_phishing else "Not found in phishing dataset",
                transaction_tracing_result="No evidence of links to known blacklisted wallets",
                whitelist_search_result="Not found in our whitelist of known entities",
                last_scanned=datetime.now(timezone.utc)
            )
            session.add(address_entry)

        session.commit()

        assessment_summary = generate_assessment_summary(address, features, risk_band, risk_text, risk_score, risk_reason, is_phishing, malicious_info)
    except Exception as e:
        logger.error(f"Error during prediction for {address}: {str(e)}")
        session.rollback()  # Rollback the session to avoid future issues
        return {'error': f'Error during prediction: {str(e)}'}, 500

    return assessment_summary

def trigger_update():
    update_addresses()

def update_addresses():
    addresses = session.query(Address).all()
    for addr in addresses:
        try:
            logger.info(f"Updating address: {addr.address}")
            feature_order = joblib.load(FEATURE_ORDER_FILE)
            malicious_addresses, malicious_info = load_malicious_addresses(MALICIOUS_ADDRESSES_FILE)
            phishing_addresses = load_phishing_addresses(PHISHING_ADDRESSES_FILE)
            features_df = extract_features(addr.address, feature_order, malicious_addresses, phishing_addresses)
            features_df = features_df.drop(columns=['address'], errors='ignore')
            features = features_df.iloc[0].to_dict()
            features_scaled = scaler.transform(features_df)
            probability = model.predict_proba(features_scaled)[0]
            risk_score = calculate_risk_score(probability)
            risk_band, risk_text = determine_risk_band(risk_score)
            risk_reason = generate_risk_reason(features, risk_band, risk_text)

            addr.risk_score = risk_score
            addr.risk_reason = risk_reason
            addr.overall_assessment = risk_text
            addr.total_transactions = features['degree']
            addr.total_received = features['value_in']
            addr.total_sent = features['value_out']
            addr.current_balance = features['balance']
            addr.last_scanned = datetime.now(timezone.utc)
            addr.blacklist_category = malicious_info.get(addr.address.lower(), {}).get('category', "N/A")
            addr.blacklist_search_result = "Found in Etherscan Blacklist" if features.get('interacted_with_malicious', 0) else "Not found in blacklist"
            addr.phishing_dataset_check = "Found in phishing dataset" if addr.address.lower() in phishing_addresses else "Not found in phishing dataset"
            addr.transaction_tracing_result = "No evidence of links to known blacklisted wallets"
            addr.whitelist_search_result = "Not found in our whitelist of known entities"
            session.commit()
            logger.info(f"Successfully updated address: {addr.address}")
        except Exception as e:
            logger.error(f"Error updating address {addr.address}: {str(e)}")
            session.rollback()  # Rollback the session to avoid future issues

       
