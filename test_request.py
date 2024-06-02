import requests

url = 'http://127.0.0.1:5000/scan'
data = {
    "address": "0x2e6b74a732e95b507c3875dc0642af977314d959"
}

response = requests.post(url, json=data)
try:
    response_json = response.json()
    print(response_json)
except requests.exceptions.JSONDecodeError:
    print("Failed to decode JSON response")
    print("Response content:", response.text)
