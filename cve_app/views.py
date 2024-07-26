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

# import local methods (helpers.py)
from .helpers import fetch_cve_data, extract_cve_details, remove_duplicates
from .helpers import get_next_entry_id, fetch_existing_cve_ids, read_latest_published_date
from .helpers import get_latest_update_info

API_KEY = '54ede83a-15f3-4b24-93b0-e6251f3bc2f2'
UPDATE_LOG_FILE = 'update_log.json'


def load_cve_data(request):
    query = request.GET.get('q')  # Get the search query from request
    filter_ransomware = 'filter_ransomware' in request.GET  # Check if the filter button is pressed
    cve_entries = cache.get('cve_entries')
    if not cve_entries:
        # Load data from database
        cve_entries = list(CVEEntry.objects.all().values())
        cache.set('cve_entries', cve_entries, timeout=60 * 15)  # Cache for 15 minutes

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


def insert_data_to_database(cve_list):
    try:
        existing_cve_ids = fetch_existing_cve_ids()  # Fetch existing CVE IDs from the database
        next_entry_id = get_next_entry_id()  # Get the next entry ID for the new data
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
    latest_published_date = read_latest_published_date()  # Read the latest published date from the database
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
            cve_items = fetch_cve_data(start_date, end_date, API_KEY)  # Fetch CVE data from the API
            if not cve_items:
                break
            cve_list = extract_cve_details(cve_items, seen_cve_ids)  # Extract relevant details from the fetched data
            all_cve_list.extend(cve_list)
            if not cve_list:
                break  # Exit the loop if no CVE items were fetched
            print(f"Fetched {len(cve_items)} CVEs")
            time.sleep(6)  # Wait to avoid hitting the API rate limit
    except KeyboardInterrupt:
        print("Keyboard interrupt received. Saving collected data to database.")
        raise
    except Exception as e:
        print(f"Error occurred: {e}")
        raise
    finally:
        if all_cve_list:
            unique_cve_list = remove_duplicates(all_cve_list)  # Remove duplicates from the fetched data
            insert_data_to_database(unique_cve_list)  # Insert the data into the database
        else:
            print("No new CVEs to save.")
    return all_cve_list


def update_cves(request):
    try:
        new_entries = initial_fetch_and_save()  # Fetch new CVEs and save to the database
        latest_date = read_latest_published_date()  # Read the latest published date from the database
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
    latest_date = read_latest_published_date()  # Read the latest published date from the database
    context = {'latest_date': latest_date.strftime('%Y-%m-%d') if latest_date else 'Unknown'}
    return render(request, 'cve_app/update.html', context)  # Render the update page with the latest date


def load_ransomware_data(request):
    query = request.GET.get('q')  # Get the search query from the request
    ransomware_entries = cache.get('ransomware_entries')  # Try to fetch cached ransomware data
    if not ransomware_entries:
        # Load data from the database
        ransomware_entries = list(RansomwareCVEEntry.objects.all().values())

        # Cache the data for 15 minutes
        cache.set('ransomware_entries', ransomware_entries, timeout=60 * 15)

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
    return render(request, 'cve_app/ransomware.html', {'page_obj': page_obj})  # Render the ransomware data page


def run_cisa_script(request):
    # Run the CISA ransomware script and redirect to the CVE list page
    subprocess.run(['python', 'CISA_ransomware.py'], check=True)
    return redirect('cve_list')


def update_ransomware_cves_view(request):
    if request.method == 'POST':
        try:
            # Run the update ransomware CVEs script
            subprocess.run(['python', 'update_ransomware_cves.py'], capture_output=True, text=True, check=True)
            # Get the latest update info
            update_info = get_latest_update_info()
            return JsonResponse({'message': 'Ransomware CVEs updated successfully!', **update_info}, status=200)
        except subprocess.CalledProcessError as e:
            return JsonResponse({'message': f'An error occurred: {e}', 'latest_update': 'N/A', 'new_cves': []},
                                status=500)
    return JsonResponse({'message': 'Invalid request method.'}, status=405)


def update_ransomware_page(request):
    update_info = get_latest_update_info()  # Get the latest update information
    return render(request, 'cve_app/update_ransomware_page.html', update_info)  # Render the ransomware update page
