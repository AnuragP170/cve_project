import openpyxl
import fitz 
import re
import os
def check_cisa():
    f = open("cves_from_cisa.txt", "r")
    cisa = []
    for line in f:
        cve = line.strip()  # Removes newline characters (\n) from the line
        cisa.append(cve)
    
    merged_workbook = openpyxl.load_workbook("datasets/ransomware_merged.xlsx")
    merged_sheet = merged_workbook.active
    existing_cve_ids = set() 
    for row in merged_sheet.iter_rows(min_row=2):
            cve_id = row[0].value
            # update those that exists first
            if cve_id in cisa:
                row[5].value = True
            if row[0] is not None:
                existing_cve_ids.add(cve_id)
    
    for cve_id in cisa:
        if cve_id not in existing_cve_ids:
            # Append a new row with CVE_ID and Assigner value
            print(cve_id)
            new_row = [cve_id, None, None, None, None, True, None]
            merged_sheet.append(new_row)

    merged_workbook.save("datasets/ransomware_merged.xlsx")
    print("save")
    f.close()


def check_school():
    workbook = openpyxl.load_workbook("datasets/ransomware_past_year.xlsx")
    sheet = workbook.active
    # Initialize an empty dictionary to store CVE_ID to Assigner mapping
    cve_to_col_B_value = {}
     # Create mapping of CVE_ID to Ransomware (Column A to Column B mapping)
    for row in sheet.iter_rows(min_row=2, max_col=2, values_only=True):
        if row[0] is not None and row[1] is not None:
            cve_to_col_B_value[row[0]] = row[1]

    merged_workbook = openpyxl.load_workbook("datasets/ransomware_merged.xlsx")
    merged_sheet = merged_workbook.active

    for row in merged_sheet.iter_rows(min_row=2):
            cve_id = row[0].value
            # update those that exists first
            if cve_id in cve_to_col_B_value:
                # Update Column X (assigner column)
                row[3].value = cve_to_col_B_value[cve_id]
                row[4].value = True
    
    merged_workbook.save("datasets/ransomware_merged.xlsx")


def retrieve_description():
    workbook = openpyxl.load_workbook("datasets/merged.xlsx")
    sheet = workbook.active
    # Initialize an empty dictionary to store CVE_ID to Assigner mapping
    cve_to_col_B_value = {}
     # Create mapping of CVE_ID to Ransomware (Column A to Column B mapping)
    for row in sheet.iter_rows(min_row=2, max_col=21, values_only=True):
        if row[0] is not None and row[20] is not None:
            cve_to_col_B_value[row[0]] = row[20]

    merged_workbook = openpyxl.load_workbook("datasets/ransomware_merged.xlsx")
    merged_sheet = merged_workbook.active
    print("ready to merge")
    for row in merged_sheet.iter_rows(min_row=2):
            cve_id = row[0].value
            # update those that exists first
            if cve_id in cve_to_col_B_value:
                # Update Column X (assigner column)
                row[6].value = cve_to_col_B_value[cve_id]
            print(cve_id)
    merged_workbook.save("datasets/ransomware_merged.xlsx")
    print("save")

def url():
    occurrences = []
    pdf_file = "reports/Ransomware_Report_2022_compressed.pdf"
    with fitz.open(pdf_file) as doc:
        for page_num in range(len(doc)):
            page = doc.load_page(page_num)
            text = page.get_text()
            words = text.split()
            for word in words:
                if "CVE-" in word:
                    cleaned_cve = re.sub(r'[^\w\-]', '', word)
                    occurrences.append(cleaned_cve)
                    print(word)

    merged_workbook = openpyxl.load_workbook("datasets/ransomware_merged.xlsx")
    merged_sheet = merged_workbook.active
    print("ready to merge")
    for row in merged_sheet.iter_rows(min_row=2):
            cve_id = row[0].value
            # update those that exists first
            if cve_id in occurrences:
                current_value = row[7].value
                if current_value is not None:
                # Update Column X (assigner column)
                    new_value = f"{current_value},https://cybersecurityworks.com/howdymanage/uploads/file/Spotlight%20Report%20-%20Index%20Update%20Q2%20-%20Q3%20-%20Final%20Version_compressed.pdf"
                    row[7].value = new_value
                else:
                    row[7].value = "https://cybersecurityworks.com/howdymanage/uploads/file/Spotlight%20Report%20-%20Index%20Update%20Q2%20-%20Q3%20-%20Final%20Version_compressed.pdf"
    merged_workbook.save("datasets/ransomware_merged.xlsx")
    print("save")
def get_all_ransomware_cves():
    check_cisa()
    check_school()
    retrieve_description()
    url()
    
    merged_workbook = openpyxl.load_workbook("datasets/ransomware_merged.xlsx")
    merged_sheet = merged_workbook.active
    
    ransomware_cves = []
    for row in merged_sheet.iter_rows(min_row=2, values_only=True):
        ransomware_cves.append({
            'cve_id': row[0],
            'description': row[1],
            'published_date': row[2],
            'modified_date': row[3],
            'references': row[4],
            'cisa_flag': row[5],
            'assigner': row[6],
            'source_url': row[7]
        })
        
    return ransomware_cves

# Ensure static directory exists
if not os.path.exists('static'):
    os.makedirs('static')