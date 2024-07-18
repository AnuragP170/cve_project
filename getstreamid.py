import requests

# Replace with your developer token
developer_token = 'fe_3o8diUvBPd543aLwFaN6AsjPxoPvCyLyQbTUqx3m'

headers = {
    'Authorization': f'OAuth {developer_token}'
}

response = requests.get('https://cloud.feedly.com/v3/profile', headers=headers)

if response.status_code == 200:
    profile = response.json()
    print("Profile Information:")
    print(profile)
else:
    print(f"Failed to fetch profile information. Status code: {response.status_code}")
    print(response.text)
