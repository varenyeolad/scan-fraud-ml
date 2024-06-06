import requests

url = 'http://127.0.0.1:5000/scan'
data = {
    "address": "0x0105a3bb58793a8514de8aa6bfdff33cad219186", # low risk
     "address": "0xff3d2b561029845b84fb42f6fb646e1c3a0d6caa" # high risk
}

response = requests.post(url, json=data)
try:
    response_json = response.json()
    print(response_json)
except requests.exceptions.JSONDecodeError:
    print("Failed to decode JSON response")
    print("Response content:", response.text)
