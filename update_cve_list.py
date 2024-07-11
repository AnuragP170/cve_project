
import traceback
import requests
import pandas as pd
import time
from datetime import datetime
import openpyxl
import re

API_KEY = '54ede83a-15f3-4b24-93b0-e6251f3bc2f2'
FILENAME = 'processed_cve_data.xlsx'
OUTPUT_FILENAME = 'processed_cve_data.xlsx'

def fetch_cve_data(start_date, end_date):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {
        'apiKey': API_KEY
    }
    params = {
        'pubStartDate': start_date,
        'pubEndDate': end_date
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        return data.get('vulnerabilities', [])
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.RequestException as err:
        print(f"Error occurred: {err}")
    except ValueError as json_err:
        print(f"JSON decode error occurred: {json_err}")
    return []

def setBaseSeverity(base_score, base_severity):
    if base_score != 'N/A' and base_severity == 'N/A':
        base_score = float(base_score)
        if 0.1 <= base_score <= 3.9:
            base_severity = 'Low'
        elif 4.0 <= base_score <= 6.9:
            base_severity = 'Medium'
        elif 7.0 <= base_score <= 8.9:
            base_severity = 'High'
        elif 9.0 <= base_score <= 10:
            base_severity = 'Critical'

    return base_severity

def process_vulnerability(vulnerability):
    cve_id = vulnerability['cve']['id']
    published_date = vulnerability['cve']['published']
    last_modified_date = vulnerability['cve']["lastModified"]
    references = vulnerability['cve']['references']
    reference_list = [f"{ref['url']} ({ref['source']})" for ref in references]
    references_str = "; ".join(reference_list)
    description = vulnerability['cve']['descriptions'][0]['value']
    weaknesses = vulnerability['cve'].get('weaknesses', [])
    configurations = vulnerability.get('configurations', [])

    cvss_metrics = vulnerability['cve']['metrics'].get('cvssMetricV31', [None])[0] or \
                   vulnerability['cve']['metrics'].get('cvssMetricV30', [None])[0] or \
                   vulnerability['cve']['metrics'].get('cvssMetricV2', [None])[0]
    cwe = 'N/A'

    for weakness in weaknesses:
        weakness_descriptions = weakness.get('description', [])
        for w_description in weakness_descriptions:
            if w_description.get('lang') == 'en':
                cwe = w_description.get('value', 'N/A')
                break

    affected_platform = []
    for config in configurations:
        nodes = config.get('nodes', [])
        for node in nodes:
            cpe_matches = node.get('cpeMatch', [])
            for cpe in cpe_matches:
                criteria = cpe.get('criteria', 'N/A')
                if criteria != 'N/A':
                    match = re.match(r'cpe:2\.3:[aho]:([^:]+):([^:]+):([^:]+)', criteria)
                    if match:
                        platform, product, version = match.groups()
                        affected_platform.append(f"{platform}:{product}:{version}")

    affected_platform_str = ', '.join(affected_platform) if affected_platform else 'N/A'

    if cvss_metrics:
        cvss_data = cvss_metrics['cvssData']
        version = cvss_data['version']
        vector_string = cvss_data['vectorString']
        base_score = cvss_data.get('baseScore', 'N/A')
        base_severity = cvss_metrics.get('baseSeverity', 'N/A')
        assigner = cvss_metrics.get('source', 'N/A')
    else:
        version = 'N/A'
        vector_string = 'N/A'
        base_score = 'N/A'
        base_severity = 'N/A'
        assigner = 'N/A'

    base_severity = setBaseSeverity(base_score, base_severity)

    return [cve_id, description, published_date, last_modified_date, affected_platform_str, version, vector_string, base_score, base_severity, references_str, cwe, assigner]

def extract_cve_details(cve_items, seen_cve_ids):
    cve_list = []
    for item in cve_items:
        cve_id = item['cve']['id']
        if cve_id not in seen_cve_ids:
            seen_cve_ids.add(cve_id)
            cve_list.append(process_vulnerability(item))
    return cve_list

def save_to_excel(cve_list, filename):
    df = pd.DataFrame(cve_list, columns=[
        'CVE ID', 'Description', 'Published Date', 'Last Modified Date', 'Affected Platform', 'CVSS Version', 'CVSS vector string', 'Base Score', 'Base Severity', 'References', 'CWE', 'Assigner'])
    with pd.ExcelWriter(filename, engine='openpyxl', mode='a', if_sheet_exists='overlay') as writer:
        df.to_excel(writer, index=False, header=False, startrow=writer.sheets['Sheet1'].max_row)

def read_latest_published_date(filename):
    try:
        df = pd.read_excel(filename)
        if not df.empty:
            latest_published_date_str = df.iloc[-1]['Published Date']
            latest_published_date = datetime.strptime(latest_published_date_str, '%Y-%m-%dT%H:%M:%S.%f')
            return latest_published_date
    except Exception as e:
        print(f"Error reading file {filename}: {e}")
    return None

def remove_duplicates(cve_list):
    seen = set()
    unique_list = []
    for cve in cve_list:
        if cve[0] not in seen:
            unique_list.append(cve)
            seen.add(cve[0])
    return unique_list

def initial_fetch_and_save(filename):
    latest_published_date = read_latest_published_date(filename)
    if latest_published_date:
        print(f"Latest published date in the existing file: {latest_published_date}")
        start_date = latest_published_date.strftime('%Y-%m-%dT%H:%M:%S.%f')
        print("Start date: ", start_date)
    else:
        print("No existing CVE data found. Starting from scratch.")
        start_date = '2000-01-01T00:00:00.000'  # Arbitrary start date for initial run

    end_date = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')
    print("End date: ", end_date)
    all_cve_list = []
    seen_cve_ids = set()

    try:
        while True:
            cve_items = fetch_cve_data(start_date, end_date)
            if not cve_items:
                break
            cve_list = extract_cve_details(cve_items, seen_cve_ids)
            all_cve_list.extend(cve_list)
            if not cve_list:
                break  # Exit the loop if no CVE items were fetched
            print(f"Fetched {len(cve_items)} CVEs")
            time.sleep(6)
    except KeyboardInterrupt:
        print("Keyboard interrupt received. Saving collected data to Excel.")
        raise
    except Exception as e:
        print(f"Error occurred: {e}")
        raise
    finally:
        if all_cve_list:
            unique_cve_list = remove_duplicates(all_cve_list)
            save_to_excel(unique_cve_list, filename)
            print(f"Data saved to {filename}")
        else:
            print("No new CVEs to save.")
    return all_cve_list

def main():
    try:
        print("Updating CVE data...")
        initial_fetch_and_save(FILENAME)
        print("CVE data update completed!")
    except Exception as e:
        print(f"An error occurred during the update process: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    main()


""" Create CVE update service (cve_update.service)

Create systemd service file - /etc/systemd/system/update_cve.service

    [Unit]
    Description=Update CVE Entries Script
    
    [Service]
    ExecStart=/usr/bin/python3 /home/username/scripts/update_cve_list.py
    
Create systemd timer file - etc/systemd/system/update_cve.timer

    [Unit]
    Description=Run update_cve.service every 4 hours
    
    [Timer]
    OnCalendar=0/4:00:00
    Persistent=true
    
    [Install]
    WantedBy=timers.target

in linux terminal,
    sudo systemctl enable update_cve_entries.timer
    sudo systemctl start update_cve_entries.timer


"""