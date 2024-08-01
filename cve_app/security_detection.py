import platform
import time
import sys, os


sys.path.append(os.getcwd())
from cve_app.OS_checks.windows_check import *
from cve_app.OS_checks.ubuntu_check import *


def get_security_status():
    firewall_logging = []
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
        results = {
            "Firewall": firewall,
            "Antivirus": antivirus,
            "Firewall logging": firewall_logging,
            "Open Ports": ports,
            "Agent-based Log Collection": agent_logging,
            "Installed Software": installed_software_and_version
        }
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




if __name__ == "__main__":
    # Sample code for testing, this part is for just getting values from the programs
    print(get_security_status())


