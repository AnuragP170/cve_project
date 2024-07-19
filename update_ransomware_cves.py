import requests
import pandas as pd
import openpyxl
import os
import logging
import re
from datetime import datetime
import json

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

FEEDLY_API_KEY = 'fe_3o8diUvBPd543aLwFaN6AsjPxoPvCyLyQbTUqx3m'  # Replace with your Feedly API key
TEAM_ID = 'team-rk0k'  # Your team ID

UPDATE_LOG_FILE = 'update_log.json'

# Function to fetch ransomware CVEs from Feedly using streams
def fetch_ransomware_cves_from_feedly(feedly_api_key, stream_id):
    headers = {
        'Authorization': f'OAuth {feedly_api_key}',
        'Content-Type': 'application/json'
    }
    url = 'https://cloud.feedly.com/v3/search/contents'
    params = {
        'streamId': stream_id,
        'count': 100,
        'ranked': 'newest',  # Get the most recent articles
        'q': 'ransomware CVE'
    }
    response = requests.get(url, headers=headers, params=params)
    
    # Log the response status and content
    logging.info(f"Feedly API response status: {response.status_code}")
    logging.info(f"Feedly API response content: {response.text}")
    
    if response.status_code != 200:
        raise Exception(f"Error fetching data from Feedly: {response.status_code} - {response.text}")
    
    data = response.json()
    
    cve_ids = set()
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')  # Pattern to match valid CVE IDs
    for item in data.get('items', []):
        title = item.get('title', '')
        found_cves = cve_pattern.findall(title)
        for cve in found_cves:
            cve_ids.add(cve.strip())
    
    return list(cve_ids)

# Function to append CVE IDs to cves_from_cisa.txt and log the update
def append_cve_ids_to_file(cve_ids, file_name, log_file):
    existing_cves = set()
    
    # Read existing CVEs from the file
    if os.path.exists(file_name):
        with open(file_name, 'r') as file:
            for line in file:
                existing_cves.add(line.strip())
    
    # Find new CVEs
    new_cves = set(cve_ids) - existing_cves
    
    if not new_cves:
        logging.info("No new CVE IDs found.")
        return [], False
    
    # Append new CVEs to the set
    existing_cves.update(new_cves)
    
    # Write the updated set of CVEs back to the file
    with open(file_name, 'w') as file:
        for cve_id in sorted(existing_cves):
            file.write(f"{cve_id}\n")
    
    # Log the update
    update_log = {
        'latest_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'new_cves': sorted(new_cves)
    }
    
    with open(log_file, 'w') as log:
        json.dump(update_log, log, indent=4)
    
    logging.info(f"CVE IDs appended to {file_name}")
    return sorted(new_cves), True

# Ensure datasets directory exists
if not os.path.exists('datasets'):
    os.makedirs('datasets')

# Main execution
if __name__ == "__main__":
    cve_ids = fetch_ransomware_cves_from_feedly(FEEDLY_API_KEY, f"enterprise/{TEAM_ID}/category/global.all")
    new_cves, updated = append_cve_ids_to_file(cve_ids, "cves_from_cisa.txt", UPDATE_LOG_FILE)
    if updated:
        print("Ransomware CVE update process completed.")
        print(f"New CVEs added: {new_cves}")
    else:
        print("No new ransomware CVEs found. No update needed.")
