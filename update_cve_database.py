import traceback
import requests
import pandas as pd
import time
from datetime import datetime
import re
from sqlalchemy import create_engine
from sqlalchemy import text
import logging
import urllib.parse

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

API_KEY = '54ede83a-15f3-4b24-93b0-e6251f3bc2f2'

# Database configuration
db_user = 'team27'
db_password = 'T3@m27!'
db_host = '13.237.28.154'
db_port = '3306'
db_name = 'Mitigation'
db_table = 'entire_cve_list'

db_password_encoded = urllib.parse.quote_plus(db_password)

# Create a connection to the database
engine = create_engine(f'mysql+pymysql://{db_user}:{db_password_encoded}@{db_host}:{db_port}/{db_name}')

logging.info("Database connection established.")


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
        logging.error(f"HTTP error occurred: {http_err} for url: {response.url}")
    except requests.exceptions.RequestException as err:
        logging.error(f"Error occurred: {err}")
    except ValueError as json_err:
        logging.error(f"JSON decode error occurred: {json_err}")
    return []


def set_base_severity(base_score, base_severity):
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
        processed_data['CVE_ID'] = vulnerability['cve']['id']
        processed_data['Published_Date'] = vulnerability['cve']['published']
        processed_data['Last_Modified_Date'] = vulnerability['cve']["lastModified"]

        references = vulnerability['cve']['references']
        reference_list = [f"{ref['url']} ({ref['source']})" for ref in references]
        processed_data['References'] = "; ".join(reference_list)

        processed_data['Description'] = vulnerability['cve']['descriptions'][0]['value']

        weaknesses = vulnerability['cve'].get('weaknesses', [])
        configurations = vulnerability.get('configurations', [])

        cvss_metrics = vulnerability['cve']['metrics'].get('cvssMetricV31', [None])[0] or \
                       vulnerability['cve']['metrics'].get('cvssMetricV30', [None])[0] or \
                       vulnerability['cve']['metrics'].get('cvssMetricV2', [None])[0]

        processed_data['CWE'] = 'N/A'
        for weakness in weaknesses:
            weakness_descriptions = weakness.get('description', [])
            for w_description in weakness_descriptions:
                if w_description.get('lang') == 'en':
                    processed_data['CWE'] = w_description.get('value', 'N/A')
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

        processed_data['Affected_Platform'] = ', '.join(affected_platform) if affected_platform else 'N/A'

        if cvss_metrics:
            cvss_data = cvss_metrics['cvssData']
            processed_data['CVSS_Version'] = cvss_data['version']
            processed_data['Base_Score'] = cvss_data.get('baseScore', 'N/A')
            processed_data['Base_Severity'] = cvss_metrics.get('baseSeverity', 'N/A')
            processed_data['assigner'] = cvss_metrics.get('source', 'N/A')
        else:
            processed_data['CVSS_Version'] = 'N/A'
            processed_data['Base_Score'] = 0
            processed_data['Base_Severity'] = 'N/A'
            processed_data['assigner'] = 'N/A'

        processed_data['Base_Severity'] = set_base_severity(processed_data['Base_Score'],
                                                            processed_data['Base_Severity'])
    except KeyError as e:
        logging.error(f"KeyError: {e} - Data: {vulnerability}")

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
        with engine.connect() as conn:
            result = conn.execute(text(f"SELECT MAX(Published_Date) FROM {db_table}"))
            latest_published_date = result.scalar()
            if latest_published_date:
                return latest_published_date
    except Exception as e:
        logging.error(f"Error reading latest published date from database: {e}")
    return None


def remove_duplicates(cve_list):
    seen = set()
    unique_list = []
    for cve in cve_list:
        if cve['CVE_ID'] not in seen:
            unique_list.append(cve)
            seen.add(cve['CVE_ID'])
    return unique_list


def insert_data_to_database(cve_list):
    try:
        # Create a DataFrame from the list of dictionaries
        df = pd.DataFrame(cve_list)
        logging.info(f"DataFrame columns: {df.columns.tolist()}")

        # Ensure date columns are in datetime format if they exist
        if 'Published_Date' in df.columns:
            df['Published_Date'] = pd.to_datetime(df['Published_Date'], errors='coerce')
        if 'Last_Modified_Date' in df.columns:
            df['Last_Modified_Date'] = pd.to_datetime(df['Last_Modified_Date'], errors='coerce')

        # Insert data into the database
        df.to_sql(db_table, con=engine, if_exists='append', index=False)
        logging.info("Data has been successfully inserted into the database.")
    except Exception as e:
        logging.error(f"An error occurred while inserting data into the database: {e}")


def initial_fetch_and_save():
    latest_published_date = read_latest_published_date()
    if latest_published_date:
        logging.info(f"Latest published date in the existing database: {latest_published_date}")
        try:
            latest_published_date = str(latest_published_date)
            latest_published_date = datetime.strptime(latest_published_date, '%Y-%m-%d %H:%M:%S.%f')
        except ValueError:
            latest_published_date = str(latest_published_date)
            latest_published_date = datetime.strptime(latest_published_date, '%Y-%m-%d %H:%M:%S')
        start_date = latest_published_date.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'  # Format correctly for the API
    else:
        logging.info("No existing CVE data found. Starting from scratch.")
        start_date = '2000-01-01T00:00:00.000Z'  # Arbitrary start date for initial run

    end_date = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    logging.info(f"Fetching CVE data from {start_date} to {end_date}")

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
            logging.info(f"Fetched {len(cve_items)} CVEs")
            time.sleep(6)
    except KeyboardInterrupt:
        logging.warning("Keyboard interrupt received. Saving collected data to database.")
        raise
    except Exception as e:
        logging.error(f"Error occurred: {e}")
        raise
    finally:
        if all_cve_list:
            unique_cve_list = remove_duplicates(all_cve_list)
            insert_data_to_database(unique_cve_list)
        else:
            logging.info("No new CVEs to save.")


def main():
    try:
        logging.info("Updating CVE data...")
        initial_fetch_and_save()
        logging.info("CVE data update completed!")
    except Exception as e:
        logging.error(f"An error occurred during the update process: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()