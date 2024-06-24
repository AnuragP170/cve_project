# cve_project
This web app renders cve entries from excel file directly into web app.

the current excel file being displayed - extracted_cve_details.xlsx

to run server
use command - python3 manage.py runserver

enter url - http://127.0.0.1:8000/cve-list/

to modify backend code - cve_app/views.py and cve_app/models.py

to modify front end code - cve_app/templates/cve_app/list_cve.html

to modify settings/url config - cve_project/url.py and settings.py


INSTALLATION OF PRE-REQUISITES

1. pip install openpyxl django-import-export
2. pip install django-redis
3. enter command: redis-server 
