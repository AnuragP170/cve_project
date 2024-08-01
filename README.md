
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

check_ubuntu_firewall():
Function: Checks if the firewall (UFW) is active and retrieves its version.
How it works: Executes the systemctl status ufw command to check the firewall status and the ufw --version command to get the version. If the status command returns 0 or 3, it adds the firewall to the detected programs list along with its version.

check_ubuntu_antivirus(): 
NOTE: does not work yet
Function: Detects if any antivirus programs are running and retrieves their versions.
How it works: Iterates through a predefined list of antivirus programs and executes the systemctl status <program> command to check their status and the <program> --version command to get the version. Adds detected antivirus programs to the list with their version.

check_open_ports_ubuntu():
Function: Lists the open network ports on the system.
How it works: Runs the netstat -tuln command and parses its output to find ports in a listening state. Extracts and returns a list of these ports.

check_agent_based_log_collection_ubuntu():
Function: Detects if specific log collection agents are running and retrieves their versions.
How it works: Iterates through a list of known log collection agent services and executes the systemctl status <program> command to check their status. For "wazuh-agent", it runs /var/ossec/bin/wazuh-control info to get the version. For other programs, it runs the <program> --version command to get the version. Adds detected programs to the list with their version.

check_syslog():
Function: Checks if Syslog (or RSyslog) is running.
How it works: Executes the systemctl status syslogd command to check the status. If the command returns 0 or 3, it returns "Detected"; otherwise, it returns "Not detected".

get_installed_programs_ubuntu():
Function: Retrieves a list of installed programs.
How it works: Runs the dpkg-query -W command to list installed packages. Parses the command output and returns a list of installed programs. If the command fails, it returns an error message.





### windows_check.py:
 - Codes here have been tested on windows 11
This script has functions to check various security aspects specific to Windows systems.
Functions include checking the status of the firewall, antivirus, open ports, firewall logging, agent-based log collection, installed software, and system updates.
It utilizes Windows-specific commands and tools (e.g., netsh, powershell) to gather this information.

 check_agent_based_log_collection_windows has only been tested for Wazuh, as certain programs need to be paid for, thus we do not have access to test and check whether those programs exist on a system.
 
check_windows_firewall():
Function: Checks if the Windows Firewall is enabled or disabled.
How it works: Executes the netsh advfirewall show allprofiles command and searches the output for the firewall state. If it finds "ON" or "OFF", it returns the firewall status and the Windows version. If it can't determine the state, it returns an error message.

check_windows_antivirus():
Function: Detects if certain antivirus programs are running and retrieves their versions.
How it works: Iterates through running processes using psutil.process_iter() and matches process names against a predefined list of antivirus programs. 
If a match is found, it runs a wmic command to get the process version. Only tested on Wazuh so far

check_open_ports_windows():
Function: Lists the open network ports on the system.
How it works: Runs the netstat -an command and parses its output to find ports in a listening state. It extracts and returns a list of these ports.

check_windows_firewall_logging():
Function: Checks the logging status of the Windows Firewall for different profiles.
How it works: Runs the netsh advfirewall show <profile> state command for domain, private, and public profiles. It checks the output for the logging state and returns the status for each profile.

check_agent_based_log_collection_windows():
Function: Detects if specific log collection agents are running.
How it works: Iterates through a list of known log collection agent services and checks if they are running using psutil.win_service_iter(). If a service is found, it's added to the detected programs list.
on windows, obtaining a version number for wazuh has not been found yet, although wazuh agents can be detected.




get_windows_version():
Function: Retrieves the current Windows version.
How it works: Uses the platform.platform() function to get the Windows version and returns it.

get_installed_software_powershell():
Function: Retrieves a list of installed software and their versions.
How it works: Runs a PowerShell command to get information on installed software using Get-WmiObject. It parses the output to extract software names and versions and returns them in a dictionary format.
 
firewall logging and firewall version are assumed to be the windows version number, since they are related.
 