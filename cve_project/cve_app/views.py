from django.shortcuts import render, redirect
from django.core.cache import cache
import openpyxl
from django.http import JsonResponse
from django.core.paginator import Paginator
import pandas as pd
from datetime import datetime, timedelta
import time
import requests
import traceback
import subprocess
import cve_app.security_detection

API_KEY = '54ede83a-15f3-4b24-93b0-e6251f3bc2f2'
FILENAME = 'merged_done.xlsx'

def load_cve_data(request):
    query = request.GET.get('q')  # Get the search query from request
    filter_ransomware = 'filter_ransomware' in request.GET  # Check if the filter button is pressed
    cve_entries = cache.get('cve_entries')
    if not cve_entries:
        # Load data from Excel file

       

        wb = openpyxl.load_workbook(FILENAME)
        sheet = wb.active
        
        cve_entries = []
        for row in sheet.iter_rows(min_row=11, values_only=True):
            cve_entry = {
                'cve_id': row[0],
                'description': row[1] if row[1] else "",
                'published_date': row[2] if row[2] else "",
                'modified_date': row[3] if row[3] else "",
                'affected_platform': row[4] if row[4] else "",
                'version': row[5] if row[5] else "",
                'vector_string': row[6] if row[6] else "",
                'base_score': row[7] if row[7] else "",
                'base_severity': row[8] if row[8] else "",
                'references': row[9] if row[9] else "",
                'cwe': row[10] if row[10] else "",
                'assigner': row[11] if row[11] else ""
            }
            cve_entries.append(cve_entry)
        
        cache.set('cve_entries', cve_entries, timeout=60*15)  # Cache for 15 minutes

    cve_entries.reverse()
    # Filter entries based on search query if it exists
    if filter_ransomware:
        # Filter CVEs based on the contents of cves_from_cisa.txt
        try:
            # with open('cves_from_cisa.txt', 'r') as file:
            #     cisa_cves = set(line.strip() for line in file)
            # filtered_entries = [entry for entry in cve_entries if entry['cve_id'] in cisa_cves]
            ransomware_wb = openpyxl.load_workbook('ransomware_merged.xlsx')
            ransomware_sheet = ransomware_wb.active
            ransomware_cves = set(cell.value for cell in ransomware_sheet['A'] if cell.value)
            filtered_entries = [entry for entry in cve_entries if entry['cve_id'] in ransomware_cves]
        except FileNotFoundError:
            filtered_entries = cve_entries  # If the file is not found, do not filter
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

    affected_platform = 'N/A'
    for config in configurations:
        nodes = config.get('nodes', [])
        for node in nodes:
            cpe_matches = node.get('cpeMatch', [])
            for cpe in cpe_matches:
                affected_platform = cpe.get('criteria', 'N/A')
                break


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

    return [cve_id, description, published_date, last_modified_date, affected_platform, version, vector_string, base_score, base_severity, references_str, cwe, assigner]

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
        'CVE ID', 'Description', 'Published Date', 'Last Modified Date', 'Affected Platform', 'CVSS Version', 'CVSS vector string', 'Base Score', 'Base Severity', 'References', 'CWE', 'assigner'])
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
       
        print("start date: ", start_date)
    else:
        print("No existing CVE data found. Starting from scratch.")
        start_date = '2000-01-01T00:00:00.000'  # Arbitrary start date for initial run

    start_date_dt = datetime.strptime(start_date, '%Y-%m-%dT%H:%M:%S.%f')
    # uncomment this to make end date as current date and time
    end_date_dt = datetime.utcnow()  # Use the current date and time as the end date
    end_date = end_date_dt.strftime('%Y-%m-%dT%H:%M:%S.%f')
    
    print("End date: ", end_date)
    start_index = 0
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
            #start_index += 2000
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

def update_cves(request):
    try:
        new_entries = initial_fetch_and_save(FILENAME)
        latest_date = read_latest_published_date(FILENAME)
        message = "Data updated!"
        latest_date_str = latest_date.strftime('%Y-%m-%d')
        new_cve_ids = [entry[0] for entry in new_entries]
    except Exception as e:
        message = f"An error occurred: {e}"
        traceback.print_exc()
        latest_date_str = "Unknown"
        new_cve_ids = []
    
    return JsonResponse({"message": message, "latest_date": latest_date_str, "new_entries": new_cve_ids})


def update_page(request):
    latest_date = read_latest_published_date(FILENAME)
    context = {'latest_date': latest_date.strftime('%Y-%m-%d') if latest_date else 'Unknown'}
    return render(request, 'cve_app/update.html', context)
def run_cisa_script(request):
    subprocess.run(['python', 'CISA_ransomware.py'], check=True)
    return redirect('cve_list')

def check_programs_view(request):
    status = cve_app.security_detection.get_security_status()
    print(status)
    return render(request, 'cve_app/status.html', {'status': status})

def load_ransomware_data(request):
    query = request.GET.get('q')  # Get the search query from request
    ransomware_entries = cache.get('ransomware_entries')
    if not ransomware_entries:
        # Load data from Excel file

        wb = openpyxl.load_workbook("ransomware_merged.xlsx")
        sheet = wb.active
        
        ransomware_entries = []
        for row in sheet.iter_rows(min_row=9, values_only=True):
            if row[0] is None:  # Skip rows where cve_id is None
                continue
            ransomware_entry = {
                'cve_id': row[0],
                'description': row[1] if row[1] else "",
                'mitigation': row[2] if row[2] else "",
                'ransomware': row[3] if row[3] else "",
                'school': row[4] if row[4] else "",
                'CISA': row[5] if row[5] else "",
                'NVD': row[6] if row[6] else "",
                'references': row[7] if row[7] else "",
                'ransomware_url': row[8] if row[8] else ""
            }
            ransomware_entries.append(ransomware_entry)
        
        cache.set('ransomware_entries', ransomware_entries, timeout=60*15)  # Cache for 15 minutes

    # Further filter entries based on search query if it exists
    if query:
        query_parts = query.lower().split()
        ransomware_entries = [
            entry for entry in ransomware_entries 
            if all(
                any(part in (str(value).lower() or '') for value in entry.values())
                for part in query_parts
            )
        ]

    # # Paginate the filtered entries
    paginator = Paginator(ransomware_entries, 50)  # Show 50 entries per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'cve_app/ransomware.html', {'page_obj': page_obj})


