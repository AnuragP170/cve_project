The CVE Project

This web app renders cve entries from an SQL database directly into web app.

SQL database contains all CVE entries compiled from:  NVD, CVE Details, MITRE CVE, CIRCL + SENTNL

Features 
1. List of all CVE entries to date (http://127.0.0.1:8000/cve-list/)
2. Search CVE entries by CVE-ID or any keyword
3. Option to filter ransomware related CVEs
4. List of all ransomware related CVEs and their Recommended Mitigations (http://127.0.0.1:8000/ransomware/)
5. Option to update the list of ransomware related CVEs (using NVD API)
6. Update the local CVE database manually for latest CVE entries (http://127.0.0.1:8000/update)


To Run web app, in terminal/CMD

use command - python3 manage.py runserver


INSTALLATION OF PRE-REQUISITES

1. pip install openpyxl django-import-export

and other dependencies in requirements.txt
