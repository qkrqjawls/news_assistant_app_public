import requests

url = "https://news-assistant-app-public-1052035590147.us-central1.run.app"
# data = {
#     "my_message": "Hello from Python test client!"
# }

response = requests.get(url+"/api/issues")

print("Status Code:", response.status_code)
print("Response:", response.json())
