import os
import subprocess
import re
import requests
from django.shortcuts import redirect
from .models import CVEEntry
import json

UPDATE_LOG_FILE = 'update_log.json'


def fetch_cve_data(start_date, end_date, API_KEY):
    # Fetch CVE data from the NVD API within the specified date range
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {'apiKey': API_KEY}
    params = {'pubStartDate': start_date, 'pubEndDate': end_date}

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
    # Determine the severity level based on the base score if the severity is not provided
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


# Extract each attribute (ID, published date, last modified date, references,
# description, CWE, affected platform) through NVD API
def process_vulnerability(vulnerability):
    processed_data = {}
    try:
        processed_data['cve_id'] = vulnerability['cve']['id']
        processed_data['published_date'] = vulnerability['cve']['published']
        processed_data['last_modified_date'] = vulnerability['cve']["lastModified"]

        references = vulnerability['cve']['references']
        reference_list = [f"{ref['url']} ({ref['source']})" for ref in references]
        processed_data['references'] = "; ".join(reference_list)

        processed_data['description'] = vulnerability['cve']['descriptions'][0]['value']

        weaknesses = vulnerability['cve'].get('weaknesses', [])
        configurations = vulnerability.get('configurations', [])

        cvss_metrics = vulnerability['cve']['metrics'].get('cvssMetricV31', [None])[0] or \
                       vulnerability['cve']['metrics'].get('cvssMetricV30', [None])[0] or \
                       vulnerability['cve']['metrics'].get('cvssMetricV2', [None])[0]

        processed_data['cwe'] = 'N/A'
        for weakness in weaknesses:
            weakness_descriptions = weakness.get('description', [])
            for w_description in weakness_descriptions:
                if w_description.get('lang') == 'en':
                    processed_data['cwe'] = w_description.get('value', 'N/A')
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

        processed_data['affected_platform'] = ', '.join(affected_platform) if affected_platform else 'N/A'

        if cvss_metrics:
            cvss_data = cvss_metrics['cvssData']
            processed_data['cvss_version'] = cvss_data['version']
            processed_data['base_score'] = cvss_data.get('baseScore', 'N/A')
            processed_data['base_severity'] = cvss_metrics.get('baseSeverity', 'N/A')
            processed_data['assigner'] = cvss_metrics.get('source', 'N/A')
        else:
            processed_data['cvss_version'] = 'N/A'
            processed_data['base_score'] = 0
            processed_data['base_severity'] = 'N/A'
            processed_data['assigner'] = 'N/A'

        processed_data['base_severity'] = setBaseSeverity(processed_data['base_score'],
                                                          processed_data['base_severity'])
    except KeyError as e:
        print(f"KeyError: {e} - Data: {vulnerability}")

    return processed_data


def extract_cve_details(cve_items, seen_cve_ids):
    # Extract details from the CVE items and avoid duplicates
    cve_list = []
    for item in cve_items:
        cve_id = item['cve']['id']
        if cve_id not in seen_cve_ids:
            seen_cve_ids.add(cve_id)
            processed_data = process_vulnerability(item)
            if processed_data:
                cve_list.append(processed_data)
    return cve_list


def remove_duplicates(cve_list):
    # Remove duplicates from the list of CVEs
    seen = set()
    unique_list = []
    for cve in cve_list:
        if cve['cve_id'] not in seen:
            unique_list.append(cve)
            seen.add(cve['cve_id'])
    return unique_list


def read_latest_published_date():
    # Read the latest published date of CVEs from the database
    try:
        latest_published_date = CVEEntry.objects.latest('published_date').published_date
        return latest_published_date
    except CVEEntry.DoesNotExist:
        return None
    except Exception as e:
        print(f"Error reading latest published date from database: {e}")
    return None


def get_next_entry_id():
    # Get the next entry ID for inserting new CVE data
    try:
        latest_entry = CVEEntry.objects.latest('entry_id')
        return latest_entry.entry_id + 1
    except CVEEntry.DoesNotExist:
        return 1
    except Exception as e:
        print(f"Error getting the next entry ID: {e}")
        return None


def fetch_existing_cve_ids():
    # Fetch existing CVE IDs from the database to avoid duplicates
    return set(CVEEntry.objects.values_list('cve_id', flat=True))


def get_latest_update_info():
    # Get the latest update information from the update log file
    if os.path.exists(UPDATE_LOG_FILE):
        with open(UPDATE_LOG_FILE, 'r') as log_file:
            update_info = json.load(log_file)
        return update_info
    else:
        return {'latest_update': 'N/A', 'new_cves': []}

def get_latest_update_date():
    # Get the latest update information from the update log file
    if os.path.exists(UPDATE_LOG_FILE):
        with open(UPDATE_LOG_FILE, 'r') as log_file:
            update_info = json.load(log_file)
        return update_info.get('latest_update', 'N/A')
    else:
        return 'N/A'