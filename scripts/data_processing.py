import aiohttp
import asyncio
import pandas as pd
from statistics import mean, stdev, median
from config import ETHERSCAN_API_KEY, ETHERSCAN_API_URL

async def fetch(session, url):
    async with session.get(url) as response:
        return await response.json()

async def get_address_transactions(address):
    url = f"{ETHERSCAN_API_URL}?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=asc&apikey={ETHERSCAN_API_KEY}"
    async with aiohttp.ClientSession() as session:
        data = await fetch(session, url)
        if data['status'] == '1':
            return data['result']
        else:
            return []

async def get_address_balance(address):
    url = f"{ETHERSCAN_API_URL}?module=account&action=balance&address={address}&tag=latest&apikey={ETHERSCAN_API_KEY}"
    async with aiohttp.ClientSession() as session:
        data = await fetch(session, url)
        if data['status'] == '1':
            return int(data['result']) / 10**18
        else:
            return 0

def load_malicious_addresses(file_path):
    df = pd.read_csv(file_path)
    return set(df['banned_address'].str.lower()), df.set_index('banned_address').to_dict(orient='index')

def load_phishing_addresses(file_path):
    df = pd.read_csv(file_path)
    if 'address' not in df.columns:
        raise KeyError("The CSV file does not contain an 'address' column")
    return set(df['address'].str.lower())

def check_malicious_interactions(address, transactions, malicious_addresses):
    interactions = {
        'interacted_with_malicious': False,
        'malicious_interactions_count': 0
    }
    address = address.lower()
    for tx in transactions:
        if tx['to'].lower() in malicious_addresses or tx['from'].lower() in malicious_addresses:
            interactions['interacted_with_malicious'] = True
            interactions['malicious_interactions_count'] += 1
    return interactions

async def extract_features(address, feature_order, malicious_addresses, phishing_addresses):
    transactions = await get_address_transactions(address)
    balance = await get_address_balance(address)
    
    if not transactions:
        features = {col: 0 for col in feature_order}
        return pd.DataFrame([features])

    values = [int(tx['value']) / 10**18 for tx in transactions]
    in_values = [int(tx['value']) / 10**18 for tx in transactions if tx['to'].lower() == address.lower()]
    out_values = [int(tx['value']) / 10**18 for tx in transactions if tx['from'].lower() == address.lower()]
    in_times = [int(tx['timeStamp']) for tx in transactions if tx['to'].lower() == address.lower()]

    in_degree = len(in_values)
    out_degree = len(out_values)
    degree = in_degree + out_degree
    
    if len(in_times) > 1:
        avg_in_tx_interval = mean([in_times[i] - in_times[i - 1] for i in range(1, len(in_times))])
    else:
        avg_in_tx_interval = 0
    
    malicious_interactions = check_malicious_interactions(address, transactions, malicious_addresses)
    
    features = {
        'value_out': sum(out_values),
        'value_in': sum(in_values),
        'balance': balance,
        'degree': degree,
        'degree_in': in_degree,
        'degree_out': out_degree,
        'max_value': max(values) if values else 0,
        'min_value': min(values) if values else 0,
        'mean_value': mean(values) if values else 0,
        'std_value': stdev(values) if len(values) > 1 else 0,
        'median_value': median(values) if values else 0,
        'avg_in_tx_interval': avg_in_tx_interval,
        'min_value_out': min(out_values) if out_values else 0,
        'interacted_with_malicious': int(malicious_interactions['interacted_with_malicious']),
        'malicious_interactions_count': malicious_interactions['malicious_interactions_count'],
        'is_malicious_address': int(address in malicious_addresses),
        'is_phishing_address': int(address in phishing_addresses)
    }

    for feature in feature_order:
        if feature not in features:
            features[feature] = 0

    features_df = pd.DataFrame([features])
    features_df = features_df[feature_order]

    return features_df
