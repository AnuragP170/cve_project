import warnings

from django.shortcuts import render, redirect
from django.core.cache import cache
import openpyxl
from django.http import JsonResponse
from django.core.paginator import Paginator
import pandas as pd
from datetime import datetime, timedelta, timezone
import time
import requests
import re
import traceback
import subprocess
from .models import CVEEntry, RansomwareCVEEntry
from dateutil import parser
import pytz
import json
import os
API_KEY = '54ede83a-15f3-4b24-93b0-e6251f3bc2f2'
FILENAME = 'processed_cve_data.xlsx'
RANSOMWARE_CVE_FILE = 'ransomware_merged.xlsx'

def load_cve_data(request):
    query = request.GET.get('q')  # Get the search query from request
    filter_ransomware = 'filter_ransomware' in request.GET  # Check if the filter button is pressed
    cve_entries = cache.get('cve_entries')
    if not cve_entries:
        # Load data from database
        cve_entries = list(CVEEntry.objects.all().values())
        cache.set('cve_entries', cve_entries, timeout=60*15)  # Cache for 15 minutes

    cve_entries.reverse()
    # Filter entries based on search query if it exists
    if filter_ransomware:
        # Filter CVEs based on the contents of RansomwareEntry
        ransomware_cves = set(RansomwareCVEEntry.objects.values_list('cve_id', flat=True))
        filtered_entries = [entry for entry in cve_entries if entry['cve_id'] in ransomware_cves]
    else:
        filtered_entries = cve_entries

    # Further filter entries based on search query if it exists
    if query:
        query_parts = query.lower().split()
        filtered_entries = [
            entry for entry in filtered_entries
            if all(
                any(part in (str(value).lower() or '') for value in entry.values())
                for part in query_parts
            )
        ]

    # Paginate the filtered entries
    paginator = Paginator(filtered_entries, 50)  # Show 50 entries per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'cve_app/cve_list.html', {'page_obj': page_obj})

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
    cve_list = []
    for item in cve_items:
        cve_id = item['cve']['id']
        if cve_id not in seen_cve_ids:
            seen_cve_ids.add(cve_id)
            processed_data = process_vulnerability(item)
            if processed_data:
                cve_list.append(processed_data)
    return cve_list

def read_latest_published_date():
    try:
        latest_published_date = CVEEntry.objects.latest('published_date').published_date
        return latest_published_date
    except CVEEntry.DoesNotExist:
        return None
    except Exception as e:
        print(f"Error reading latest published date from database: {e}")
    return None

def remove_duplicates(cve_list):
    seen = set()
    unique_list = []
    for cve in cve_list:
        if cve['cve_id'] not in seen:
            unique_list.append(cve)
            seen.add(cve['cve_id'])
    return unique_list

def get_next_entry_id():
    try:
        latest_entry = CVEEntry.objects.latest('entry_id')
        return latest_entry.entry_id + 1
    except CVEEntry.DoesNotExist:
        return 1
    except Exception as e:
        print(f"Error getting the next entry ID: {e}")
        return None


def fetch_existing_cve_ids():
    return set(CVEEntry.objects.values_list('cve_id', flat=True))


def insert_data_to_database(cve_list):
    try:
        existing_cve_ids = fetch_existing_cve_ids()
        next_entry_id = get_next_entry_id()
        if next_entry_id is None:
            print("Failed to get the next entry ID.")
            return

        for cve in cve_list:
            if cve['cve_id'] in existing_cve_ids:
                print(f"CVE {cve['cve_id']} already exists in the database.")
                continue

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=RuntimeWarning)
                # Parse datetime strings to datetime objects
                if isinstance(cve['published_date'], str):
                    cve['published_date'] = parser.parse(cve['published_date']).replace(tzinfo=pytz.UTC)
                if isinstance(cve['last_modified_date'], str):
                    cve['last_modified_date'] = parser.parse(cve['last_modified_date']).replace(tzinfo=pytz.UTC)

                cve['entry_id'] = next_entry_id  # Manually set entry_id
                # Insert data into the database using Django ORM
                CVEEntry.objects.create(**cve)

                next_entry_id += 1
        print("Data has been successfully inserted into the database.")
    except Exception as e:
        print(f"An error occurred while inserting data into the database: {e}")

def initial_fetch_and_save():
    latest_published_date = read_latest_published_date()
    if latest_published_date:
        try:
            latest_published_date = str(latest_published_date)
            # Attempt to parse with timezone information
            latest_published_date = datetime.fromisoformat(latest_published_date)
        except ValueError:
            latest_published_date = str(latest_published_date)
            latest_published_date = datetime.strptime(latest_published_date, '%Y-%m-%d %H:%M:%S')

        latest_published_date = latest_published_date.replace(tzinfo=pytz.UTC)
        start_date = latest_published_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'  # Format correctly for the API
    else:
        print("No existing CVE data found. Starting from scratch.")
        start_date = '2000-01-01T00:00:00.000Z'  # Arbitrary start date for initial run

    end_date_utc = datetime.utcnow().replace(tzinfo=pytz.UTC)
    end_date_singapore = end_date_utc.astimezone(pytz.timezone('Asia/Singapore'))

    print(f"Time now in UTC:  {end_date_utc.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z")
    print(f"Time now in Singapore: {end_date_singapore.strftime('%Y-%m-%d %H:%M:%S')}")

    end_date = end_date_utc.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    print(f"Fetching CVE data from {start_date} to {end_date}")

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
        print("Keyboard interrupt received. Saving collected data to database.")
        raise
    except Exception as e:
        print(f"Error occurred: {e}")
        raise
    finally:
        if all_cve_list:
            unique_cve_list = remove_duplicates(all_cve_list)
            insert_data_to_database(unique_cve_list)
        else:
            print("No new CVEs to save.")
    return all_cve_list

def update_cves(request):
    try:
        new_entries = initial_fetch_and_save()
        latest_date = read_latest_published_date()
        message = "Data updated!"
        latest_date_str = latest_date.strftime('%Y-%m-%d')
        new_cve_ids = [entry['cve_id'] for entry in new_entries] if new_entries else []
    except Exception as e:
        message = f"An error occurred: {e}"
        traceback.print_exc()
        latest_date_str = "Unknown"
        new_cve_ids = []

    return JsonResponse({"message": message, "latest_date": latest_date_str, "new_entries": new_cve_ids})
def update_page(request):
    latest_date = read_latest_published_date()
    context = {'latest_date': latest_date.strftime('%Y-%m-%d') if latest_date else 'Unknown'}
    return render(request, 'cve_app/update.html', context)


def run_cisa_script(request):
    subprocess.run(['python', 'CISA_ransomware.py'], check=True)
    return redirect('cve_list')


def load_ransomware_data(request):
    query = request.GET.get('q')  # Get the search query from the request
    ransomware_entries = cache.get('ransomware_entries')
    if not ransomware_entries:
        # Load data from the database
        ransomware_entries = list(RansomwareCVEEntry.objects.all().values())

        # Cache the data for 15 minutes
        cache.set('ransomware_entries', ransomware_entries, timeout=60*15)

    # Further filter entries based on the search query if it exists
    if query:
        query_parts = query.lower().split()
        filtered_entries = []
        for entry in ransomware_entries:
            if all(
                any(part in (str(value).lower() or '') for value in entry.values())
                for part in query_parts
            ):
                filtered_entries.append(entry)
        ransomware_entries = filtered_entries

    # Paginate the filtered entries
    paginator = Paginator(ransomware_entries, 50)  # Show 50 entries per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'cve_app/ransomware.html', {'page_obj': page_obj})
def get_latest_update_info():
    if os.path.exists(UPDATE_LOG_FILE):
        with open(UPDATE_LOG_FILE, 'r') as log_file:
            update_info = json.load(log_file)
        return update_info
    else:
        return {'latest_update': 'N/A', 'new_cves': []}

def update_ransomware_cves_view(request):
    if request.method == 'POST':
        try:
            # Run the update ransomware CVEs script
            subprocess.run(['python', 'update_ransomware_cves.py'], capture_output=True, text=True, check=True)
            # Get the latest update info
            update_info = get_latest_update_info()
            return JsonResponse({'message': 'Ransomware CVEs updated successfully!', **update_info}, status=200)
        except subprocess.CalledProcessError as e:
            return JsonResponse({'message': f'An error occurred: {e}', 'latest_update': 'N/A', 'new_cves': []}, status=500)
    return JsonResponse({'message': 'Invalid request method.'}, status=405)

def update_ransomware_page(request):
    update_info = get_latest_update_info()
    return render(request, 'cve_app/update_ransomware_page.html', update_info)