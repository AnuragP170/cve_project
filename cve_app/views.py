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


def check_programs_view(request):
    status = cve_app.security_detection.get_security_status()
    print(status)
    return render(request, 'cve_app/status.html', {'status': status})


