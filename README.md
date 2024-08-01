# The CVE Project

This DJANGO web app renders cve entries from an SQL database and displays in table format.

SQL database contains all CVE entries compiled from:  NVD, CVE Details, MITRE CVE, CIRCL + SENTNL

Features 
1. List of all CVE entries to date (http://127.0.0.1:8000/cve-list/)
2. Search CVE entries by CVE-ID or any keyword
3. Option to filter ransomware related CVEs
4. List of all ransomware related CVEs and their Recommended Mitigations (http://127.0.0.1:8000/ransomware/)
6. Update the local CVE database manually for latest CVE entries (http://127.0.0.1:8000/update)
   Click 'View Update' button in update.html to see latest entries

## INSTALLATION OF PRE-REQUISITES

1. pip3 install -r requirements

## connect Database 
1. Edit cve_project/settings.py and add database information (user, password, DB name, port, host address)

## Instructions to add Feedly API key

1. Go to Feedly website -> Create account (Select Threat Intelligence field)
2. Go to https://feedly.com/i/team/api
3. Create New API Token
4. To retrieve team name -> Enter the API token in getstreamid.py and run it
5. the value of key 'enterpriseName' is the team name (eg  'entepriseName' : 'team-75ig')
6. Add the newly generated API token and team name to the update_ransomware_cves.py

## add NVD API Key
1. Go to NVD website, obtain api key
2. Edit cve_project/cve_app/views.py to add API key

### Set System variables (Environment variables)
FEEDLY_API_KEY "api key"
TEAM_ID "team id"
NVD_API_KEY "nvd api key"

### Run the web application

To Run web app, in terminal/CMD
python3 manage.py runserver

### STANDALONE CVE database update script
update_cve_database.py can be run standalone to update the database
Before running, add following information in the script:
1. db_user, db_password, db_port, db_host db_name, db_table
2. Add NVD API key

Run this script using windows task scheduler or Cronjob (Linux) for automation
