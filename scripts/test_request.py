import requests

url = 'http://127.0.0.1:5000/scan'
data = {
    "address": "0x21fe6fcaba63f797517157ae7c1ff44439d6c148", #low risk
     "address": "0x3Ae29DB71EeD060CF1C970f5FaB553bcE71f67bE" #high risk
}

response = requests.post(url, json=data)
try:
    response_json = response.json()
    print(response_json)
except requests.exceptions.JSONDecodeError:
    print("Failed to decode JSON response")
    print("Response content:", response.text)
  