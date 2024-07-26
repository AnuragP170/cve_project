
# For checklist branch (this branch):


## Files relevant to checklist functionality
cve_app/security_detection.py
cve_app/OS_checks/ubuntu_check.py
cve_app/OS_checks/windows_check.py
cve_app/templates/cve_app/status.html - for rendering page



## Enabled URLS
 - urls in urls.py only have the checklist functionality Enabled.
	
 - If accessing ```127.0.0.1:8000/``` link does not immediately redirect you to /checklist, then access it via ```127.0.0.1:8000/checklist/``` in your browser.

 > [!TIP]
> If the program throws a 301 when trying to access 127.0.0.1:8000/checklist/ , try clearing the cache or ensuring that the link has a trailing slash


## Description of how the user environment checklist works

### cve_app/security_detection.py
 - This is the main script that determines the operating system and then calls the appropriate functions from the OS-specific scripts (windows_check.py or ubuntu_check.py) to gather security information.
It checks the firewall status, antivirus status, open ports, firewall logging, agent-based log collection, installed software.

Codes for ubuntu and linux are done in a way that allows for easy additions to the functionality of security detection.py.

Results are written to a .txt file in the format "security_check_results{OS}.txt"

Refer to get_installed_software_powershell() and get_installed_programs_ubuntu() for how windows and ubuntu are checked respectively.

Installed programs and their versions may be useful for correlating to the CVE database and finding vulnerable versions, but currently it is not achieved in this project

### ubuntu_check.py:
 - Codes here have been tested on ubuntu 20.04
This script contains functions to check various security aspects specific to Ubuntu systems.
Functions include checking the status of the firewall, antivirus, open ports, agent-based log collection, and syslog.
It provides details such as whether the programs are running and their versions.

Wazuh agent is detectable along with version number.

> [!NOTE]
>requires admin permissions on ubuntu for checking firewall status.



### windows_check.py:
 - Codes here have been tested on windows 11
This script has functions to check various security aspects specific to Windows systems.
Functions include checking the status of the firewall, antivirus, open ports, firewall logging, agent-based log collection, installed software, and system updates.
It utilizes Windows-specific commands and tools (e.g., netsh, powershell) to gather this information.

 check_agent_based_log_collection_windows has only been tested for Wazuh, as certain programs need to be paid for, thus we do not have access to test and check whether those programs exist on a system.
 
 firewall logging and firewall are assumed to be the windows version number, since they are related.
 
 on windows, obtaining a version number for wazuh has not been found yet, although wazuh agents can be detected.
