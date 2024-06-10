import os
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis

load_dotenv()

ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY')
ETHERSCAN_API_URL = 'https://api.etherscan.io/api'
MALICIOUS_ADDRESSES_FILE = '../data/etherscan_malicious_labels.csv'
PHISHING_ADDRESSES_FILE = '../data/phishing_node_features_corrected.csv'
FEATURE_ORDER_FILE = '../feature_order.pkl'
MODEL_FILE = '../knn_model.pkl'
SCALER_FILE = '../scaler.pkl'

# Database Configuration
DATABASE_URL = os.getenv('DATABASE_URL')

# Redis Configuration
REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = int(os.getenv('REDIS_PORT'))

# Swagger Configuration
SWAGGER_URL = '/swagger'
API_URL = '/swagger.yaml'

# API Keys
API_KEYS = {
    os.getenv('API_KEY_1'): "user_1",
    os.getenv('API_KEY_2'): "user_2",
    # Add more keys as needed
}

redis_client = Redis(host=REDIS_HOST, port=REDIS_PORT)
# Initialize Limiter
limiter = Limiter(key_func=get_remote_address, storage_uri=f"redis://{REDIS_HOST}:{REDIS_PORT}")
