import platform
import time

from windows_check import *
from ubuntu_check import *


def get_security_status():
    if platform.system() == "Windows":
        firewall = check_windows_firewall()
        antivirus = check_windows_antivirus()
        ports = check_open_ports_windows()
        firewall_logging = check_windows_firewall_logging()
        agent_logging = check_agent_based_log_collection_windows()
        tic = time.perf_counter()
        installed_software_and_version = get_installed_software_powershell()
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
        "Open Ports": ports,
        "Syslog": syslog,
        "Agent-based Log Collection": agent_logging,
        "Installed Software": installed_software_and_version
    }
    write_results_to_file(results)
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




if __name__ == "__main__":
    security_status = get_security_status()
    print(security_status)
    # if platform.system() == "Windows":
    #     os_version = get_windows_version()
    #     updates_needed = check_windows_updates()
    # else:
    #     os_version = platform.system()
    #     updates_needed = "Update checking not implemented for Linux"
    #
    # results = {
    #     "OS Version": os_version,
    #     "Updates Needed": updates_needed
    # }
    # print(results)
    #
