import requests
import os
# This program is used to find the team name (value of 'enterpriseName')

# Replace with your developer token
# developer_token = 'fe_*****************************'

developer_token = os.getenv('FEEDLY_API_KEY')

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
