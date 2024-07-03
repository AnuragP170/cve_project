import requests

def fetch_cisa_ransomware_cves():
    url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'  # Replace with the actual API endpoint
    response = requests.get(url)
    data = response.json()
    return data

def filter_cves_by_ransomware_campaign(data):
    ransomware_cves = []
    for vulnerability in data['vulnerabilities']:
        if vulnerability.get('knownRansomwareCampaignUse') == 'Known':
            ransomware_cves.append(vulnerability['cveID'])
    return ransomware_cves

# Fetch CISA ransomware-related CVEs
cisa_data = fetch_cisa_ransomware_cves()

# Filter CVEs by ransomware campaign
filtered_cves = filter_cves_by_ransomware_campaign(cisa_data)

output_file = 'cves_from_cisa.txt'
# Output the filtered CVEs
print("CVEs with known ransomware campaigns:")
with open(output_file, 'w') as f:
    for cve_id in filtered_cves:
        f.write(cve_id + '\n')
print(f"CVE IDs saved to {output_file}")