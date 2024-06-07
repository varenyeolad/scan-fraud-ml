import os
from dotenv import load_dotenv

load_dotenv()

ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY')
ETHERSCAN_API_URL = 'https://api.etherscan.io/api'
MALICIOUS_ADDRESSES_FILE = './data/etherscan_malicious_labels.csv'
PHISHING_ADDRESSES_FILE = './data/phishing_node_features.csv'
FEATURE_ORDER_FILE = 'feature_order.pkl'
MODEL_FILE = 'knn_model.pkl'
SCALER_FILE = 'scaler.pkl'
