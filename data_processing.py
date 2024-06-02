import requests
import pandas as pd
from statistics import mean, stdev, median

# Замените 'YOUR_ETHERSCAN_API_KEY' на ваш реальный ключ API
ETHERSCAN_API_KEY = 'RPYDH8ZMBZZ41345SXCQ8D54JUQBUMI3JA'
ETHERSCAN_API_URL = 'https://api.etherscan.io/api'

def get_address_transactions(address):
    url = f"{ETHERSCAN_API_URL}?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=asc&apikey={ETHERSCAN_API_KEY}"
    response = requests.get(url)
    data = response.json()
    if data['status'] == '1':
        return data['result']
    else:
        return []

def get_address_balance(address):
    url = f"{ETHERSCAN_API_URL}?module=account&action=balance&address={address}&tag=latest&apikey={ETHERSCAN_API_KEY}"
    response = requests.get(url)
    data = response.json()
    if data['status'] == '1':
        return int(data['result']) / 10**18  # Преобразуем баланс из Wei в Ether
    else:
        return 0

def process_data(normal_node_features_path, phishing_node_features_path):
    normal_node_features_df = pd.read_csv(normal_node_features_path)
    phishing_node_features_df = pd.read_csv(phishing_node_features_path)
    
    # Объединение данных
    all_node_features_df = pd.concat([normal_node_features_df, phishing_node_features_df])
    
    # Удаление ненужных столбцов
    X = all_node_features_df.drop(columns=['address', 'label'])
    y = all_node_features_df['label']
    
    return X, y

def extract_features(address, feature_order):
    transactions = get_address_transactions(address)
    balance = get_address_balance(address)
    
    if not transactions:
        # Вернем фиктивные данные, если нет транзакций
        features = {col: 0 for col in feature_order}
        return pd.DataFrame([features])

    values = [int(tx['value']) / 10**18 for tx in transactions]
    in_degree = sum(1 for tx in transactions if tx['to'].lower() == address.lower())
    out_degree = sum(1 for tx in transactions if tx['from'].lower() == address.lower())

    features = {
        'value_out': sum(value for tx, value in zip(transactions, values) if tx['from'].lower() == address.lower()),
        'value_in': sum(value for tx, value in zip(transactions, values) if tx['to'].lower() == address.lower()),
        'balance': balance,
        'degree': in_degree + out_degree,
        'degree_in': in_degree,
        'degree_out': out_degree,
        'max_value': max(values),
        'min_value': min(values),
        'mean_value': mean(values),
        'std_value': stdev(values) if len(values) > 1 else 0,
        'median_value': median(values),
        # Добавьте другие признаки по аналогии
    }
    
    features_df = pd.DataFrame([features])
    features_df = features_df[feature_order]
    return features_df
