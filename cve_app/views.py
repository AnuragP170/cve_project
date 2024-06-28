from django.shortcuts import render
from django.core.cache import cache
import openpyxl
from django.core.paginator import Paginator

def load_cve_data(request):
    query = request.GET.get('q')  # Get the search query from request

    cve_entries = cache.get('cve_entries')
    if not cve_entries:
        # Load data from Excel file
        wb = openpyxl.load_workbook('extracted_cve_details.xlsx')
        sheet = wb.active

        cve_entries = []
        for row in sheet.iter_rows(min_row=6, values_only=True):
            cve_entry = {
                'cve_id': row[0],
                'description': row[1] if row[1] else "",
                'published_date': row[2] if row[2] else "",
                'modified_date': row[3] if row[3] else "",
                'references': row[4] if row[4] else "",
                'version': row[5] if row[5] else "",
                'vector_string': row[6]
            }
            cve_entries.append(cve_entry)
        
        cache.set('cve_entries', cve_entries, timeout=60*15)  # Cache for 15 minutes
    
    # Filter entries based on search query if it exists
    if query:
        filtered_entries = [entry for entry in cve_entries if query.lower() in entry['cve_id'].lower()]
    else:
        filtered_entries = cve_entries

    # Paginate the filtered entries
    paginator = Paginator(filtered_entries, 50)  # Show 50 entries per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'cve_app/cve_list.html', {'page_obj': page_obj})
