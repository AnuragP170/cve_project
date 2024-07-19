import platform
import time
import sys, os

import openpyxl

sys.path.append(os.getcwd())
from cve_app.OS_checks.windows_check import *
from cve_app.OS_checks.ubuntu_check import *


def get_security_status():
    if platform.system() == "Windows":
        firewall = check_windows_firewall()
        antivirus = check_windows_antivirus()
        ports = check_open_ports_windows()
        firewall_logging = check_windows_firewall_logging()
        agent_logging = check_agent_based_log_collection_windows()
        tic = time.perf_counter()
        software_dict = get_installed_software_powershell()
        software_dict = [f"{k}: {v}" for k, v in software_dict.items()]
        installed_software_and_version = software_dict
        toc = time.perf_counter()
        print(f"Finished function in {toc - tic:0.4f} seconds")

    else:
        firewall = check_ubuntu_firewall()
        antivirus = check_ubuntu_antivirus()
        ports = check_open_ports_ubuntu()
        agent_logging = check_agent_based_log_collection_ubuntu()
        tic = time.perf_counter()

        toc = time.perf_counter()
        installed_software_and_version = get_installed_programs_ubuntu()
        print(f"Finished function in {toc - tic:0.4f} seconds")

    syslog = check_syslog()

    results = {
        "Firewall": firewall,
        "Antivirus": antivirus,
        "Firewall logging": firewall_logging,
        "Open Ports": ports,
        "Syslog": syslog,
        "Agent-based Log Collection": agent_logging,
        "Installed Software": installed_software_and_version
    }
    filename = "security_check_results{OS}.txt".format(OS=platform.system())
    write_results_to_file(results, filename)
    return results


def write_results_to_file(results, filename="security_check_results.txt"):
    with open(filename, 'w') as file:
        for key, value in results.items():
            file.write(f"{key}:\n")
            if isinstance(value, list):
                for item in value:
                    file.write(f"  {item}\n")
            else:
                file.write(f"  {value}\n")
            file.write("\n")


def search_excel_for_software(excel_path, software_name):
    wb = openpyxl.load_workbook(excel_path)
    sheet = wb.active

    results = []
    for row in sheet.iter_rows(min_row=2, values_only=True):  # Skip the header row
        description = row[1]  # Assuming Description is the second column (index 1)
        if software_name in description:
            results.append(row)

    return results


if __name__ == "__main__":
    #installed_software = get_installed_software_powershell()
    #print key and value
    #open xlsx file to search for software

    # Path to your Excel file
    excel_path = '../cleaned_cve_data.xlsx'  # Replace with the actual path to the Excel file

    #get windows version
    os=platform.system()
    windows_number=platform.version()

    tic = time.perf_counter()
    print("checking for software: ", os)
    matching_rows = search_excel_for_software(excel_path, os)
    #end time
    toc = time.perf_counter()
    #extract version numbers in description
    version_numbers = re.findall(r'\d+\.\d+', windows_number)

    print(f"Finished searching for {os} in {toc - tic:0.4f} seconds")
    if matching_rows:
        print(f"Matching rows for {os}:")
        for row in matching_rows:
            print(row)
            version_numbers = re.findall(r'\d+\.\d+', row[2])
            #if windows_number is lower than all values in version_numbers
            if version_numbers:
                if windows_number < max(version_numbers):
                    print("The system is not up to date")
            print(row)

    # for key in installed_software.keys():
    #     #start time
    #     tic = time.perf_counter()
    #     print("checking for software: ", key)
    #     matching_rows = search_excel_for_software(excel_path, key)
    #     #end time
    #     toc = time.perf_counter()
    #     print(f"Finished searching for {key} in {toc - tic:0.4f} seconds")
    #     if matching_rows:
    #         print(f"Matching rows for {key}:")
    #         for row in matching_rows:
    #             print(row)
