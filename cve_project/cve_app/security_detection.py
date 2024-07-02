# check_programs.py
import re
import subprocess
import psutil
import platform


def check_windows_firewall():
    try:
        result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True)
        if 'State                                 ON' in result.stdout:
            return ["Windows Firewall: ON"]
        elif 'State                                 OFF' in result.stdout:
            return ["Windows Firewall: OFF"]
        else:
            return "Error: Unable to determine"
    except Exception as e:
        print(f"Error checking Windows Firewall: {e}")
    return "Not detected"


def check_linux_firewall():
    programs = [
        "ufw",  # Ubuntu
    ]
    detected_programs = []
    for program in programs:
        try:
            result = subprocess.run(['systemctl', 'status', program], capture_output=True, text=True)
            if result.returncode == 0 or result.returncode == 3:  # 0: Active, 3: Inactive
                detected_programs.append(program)
        except Exception as e:
            print(f"Error checking {program}: {e}")
    return detected_programs if detected_programs else ["Not detected"]


def check_windows_antivirus():
    antivirus_processes = {
        "MsMpEng.exe": "Windows Defender",
        "avp.exe": "Kaspersky Antivirus",
        "mcshield.exe": "McAfee Antivirus"
    }
    detected_antivirus = []
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] in antivirus_processes:
            detected_antivirus.append(antivirus_processes[proc.info['name']])
    return detected_antivirus if detected_antivirus else ["Not detected"]


def check_linux_antivirus():
    detected_antivirus = []
    # cant find a good way to check for antivirus on linux
    return detected_antivirus if detected_antivirus else ["Not detected"]


def check_syslog():
    try:
        result = subprocess.run(['systemctl', 'status', 'rsyslogd'], capture_output=True, text=True)
        if result.returncode == 0 or result.returncode == 3:  # 0: Active, 3: Inactive
            return ["Detected"]
    except Exception as e:
        print(f"Error checking Syslog/RSyslog: {e}")
    return ["Not detected"]


def check_agent_based_log_collection():
    # This is an example; you might need specific checks based on the agent you are using
    try:
        result = subprocess.run(['pgrep', 'agent_name'], capture_output=True, text=True)
        if result.returncode == 0:
            return "Detected"
    except Exception as e:
        print(f"Error checking Agent-based Log Data Collection: {e}")
    return "Not detected"


def check_agent_based_log_collection_linux():
    programs = [
        "wazuh-agent",  # Wazuh
        "splunkd",  # Splunk
        "qradar",  # IBM QRadar
        "arcsight",  # ArcSight (assuming 'arcsight' is the process name)
        "logrhythm",  # LogRhythm (assuming 'logrhythm' is the process name)
        "sumologic",  # Sumo Logic (assuming 'sumologic' is the process name)
        "securonix"  # Securonix (assuming 'securonix' is the process name)
    ]
    detected_programs = []
    for program in programs:
        try:
            result = subprocess.run(['systemctl', 'status', program], capture_output=True, text=True)
            if result.returncode == 0 or result.returncode == 3:  # 0: Active, 3: Inactive
                detected_programs.append(program)
        except Exception as e:
            print(f"Error checking {program}: {e}")
    return detected_programs.insert(0, "detected programs:") if detected_programs else ["Not detected"]


def check_local_logging():
    # Example placeholder for checking local logging on various devices
    # You will need to define specific checks based on your logging setup
    return "Not detected"


def check_siem_tool():
    # Example placeholder for checking SIEM Tool Application
    # You will need to define specific checks based on your SIEM tool
    return "Not detected"


def check_open_ports_linux():
    try:
        # Run netstat command to list listening ports
        result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True)
        if result.returncode != 0:
            return "Error: netstat command failed"

        # Extract listening ports
        listening_ports = []
        lines = result.stdout.splitlines()
        for line in lines[2:]:  # Skip the first two header lines
            if re.search(r'\s+LISTEN\s+', line):
                # Extract port number using regex
                port_match = re.search(r':(\d+)\s+', line)
                if port_match:
                    listening_ports.append(int(port_match.group(1)))

        return listening_ports

    except Exception as e:
        return f"Error checking open ports: {e}"


def check_open_ports_windows():
    try:
        # Run netstat command to list listening ports
        result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
        if result.returncode != 0:
            return "Error: netstat command failed"

        # Extract unique listening ports
        listening_ports = set()
        lines = result.stdout.splitlines()

        for line in lines:

            # Extract port number using regex
            port_match = re.search(r':(\d+)\s', line)
            if port_match:
                listening_ports.add(int(port_match.group(1)))
        message = "Listening Ports: "
        listening_ports = list(listening_ports)
        listening_ports.insert(0, message)
        return list(listening_ports)

    except Exception as e:
        return f"Error checking open ports: {e}"


def check_open_ports():
    # Example placeholder for checking SIEM Tool Application
    # You will need to define specific checks based on your SIEM tool
    return "Not detected"


def check_windows_firewall_logging():
    # currently just checking windows firewall logging status
    try:
        profiles = ['domainprofile', 'privateprofile', 'publicprofile']
        logging_status = []

        for profile in profiles:
            result = subprocess.run(['netsh', 'advfirewall', 'show', profile, 'state'], capture_output=True, text=True)
            if 'State                                 ON' in result.stdout:
                logging_status.append(profile+ " Logging: ON")
            elif 'State                                 OFF' in result.stdout:
                logging_status.append(profile+ " Logging: OFF")
            else:
                logging_status[profile] = "Error: Unable to determine"
        return logging_status

    except Exception as e:
        print(f"Error checking Windows Firewall Logging: {e}")
        return ["Not detected"]


def check_agent_based_log_collection_windows():
    programs = [
        "wazuh-agent",  # Wazuh
        "splunkd",  # Splunk
        "qradar",  # IBM QRadar
        "arcsight",  # ArcSight (assuming 'arcsight' is the process name)
        "logrhythm",  # LogRhythm (assuming 'logrhythm' is the process name)
        "sumologic",  # Sumo Logic (assuming 'sumologic' is the process name)
        "securonix"  # Securonix (assuming 'securonix' is the process name)
    ]
    detected_programs = []
    for program in programs:
        try:
            result = subprocess.run(['sc', 'query', program], capture_output=True, text=True)
            if 'RUNNING' in result.stdout:
                detected_programs.append(program)
        except Exception as e:
            print(f"Error checking {program}: {e}")
    return detected_programs.insert(0, "detected programs:") if detected_programs else ["Not detected"]


def get_security_status():
    os_type = platform.system()
    print(f"OS Type: {os_type}")
    status = {}
    if os_type == "Windows":
        firewall_status = check_windows_firewall()
        antivirus_status = check_windows_antivirus()
        open_ports_info = check_open_ports_windows()
        log_status = check_agent_based_log_collection_windows()
        firewall_logging_status = check_windows_firewall_logging()

    elif os_type == "Linux":
        firewall_status = check_linux_firewall()
        antivirus_status = check_linux_antivirus()
        open_ports_info = check_open_ports_linux()
        log_status = check_agent_based_log_collection_linux()
        firewall_logging_status = check_windows_firewall_logging()

    else:
        firewall_status = "Not detected"
        antivirus_status = ["Not detected"]

    status['Have installation of firewall tools?'] = firewall_status
    status['Antivirus'] = antivirus_status
    status['Have local logging on all firewalls?'] = firewall_logging_status
    status['Have only approved ports are running?'] = open_ports_info
    status['Agent-based Log Data Collection'] = log_status

    return status


if __name__ == '__main__':
    print(get_security_status())
