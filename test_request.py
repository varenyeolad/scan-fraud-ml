import requests

url = 'http://127.0.0.1:5000/scan'
data = {
    "address": "0x0e7d64eb09abb60594594f2f506557a638e76afb",
    # "address": "0x003eb9c77b5b896fcc27adead606d23def34510e",
    #  "address": "0xff3d2b561029845b84fb42f6fb646e1c3a0d6caa"
}

response = requests.post(url, json=data)
try:
    response_json = response.json()
    print(response_json)
except requests.exceptions.JSONDecodeError:
    print("Failed to decode JSON response")
    print("Response content:", response.text)
