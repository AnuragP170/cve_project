import platform
import re
import subprocess
import psutil


def check_windows_firewall():
    try:
        result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], capture_output=True, text=True)
        windowsversion = get_windows_version()
        version = windowsversion
        if 'State                                 ON' in result.stdout:
            return [f"Windows Firewall: ON, Version: {version}"]
        elif 'State                                 OFF' in result.stdout:
            return [f"Windows Firewall: OFF, Version: {version}"]
        else:
            return "Error: Unable to determine"
    except Exception as e:
        print(f"Error checking Windows Firewall: {e}")
    return "Not detected"


def check_windows_antivirus():
    antivirus_processes = {
        "MsMpEng.exe": "Windows Defender",
        "avp.exe": "Kaspersky Antivirus",
        "mcshield.exe": "McAfee Antivirus"
    }
    detected_antivirus = []
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] in antivirus_processes:
            try:
                version_result = subprocess.run(
                    ['wmic', 'path', 'win32_process', 'where', f'name="{proc.info["name"]}"', 'get', 'version'],
                    capture_output=True, text=True)
                version = re.search(r'\b(\d+\.\d+\.\d+\.\d+)', version_result.stdout).group(
                    1) if version_result.returncode == 0 else "Unknown version"
                detected_antivirus.append(f"{antivirus_processes[proc.info['name']]}, Version: {version}")
            except Exception as e:
                print(f"Error checking version for {proc.info['name']}: {e}")
                detected_antivirus.append(f"{antivirus_processes[proc.info['name']]}, Version: Unknown")
    return detected_antivirus if detected_antivirus else ["Not detected"]


def check_open_ports_windows():
    try:
        result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
        if result.returncode != 0:
            return "Error: netstat command failed"

        listening_ports = set()
        lines = result.stdout.splitlines()

        for line in lines:
            port_match = re.search(r':(\d+)\s', line)
            if port_match:
                listening_ports.add(int(port_match.group(1)))
        message = "Listening Ports: "
        listening_ports = list(listening_ports)
        listening_ports.insert(0, message)
        return list(listening_ports)

    except Exception as e:
        return f"Error checking open ports: {e}"


def check_windows_firewall_logging():
    try:
        profiles = ['domainprofile', 'privateprofile', 'publicprofile']
        logging_status = []

        for profile in profiles:
            result = subprocess.run(['netsh', 'advfirewall', 'show', profile, 'state'], capture_output=True, text=True)
            version_result = subprocess.run(['netsh', 'advfirewall', 'show', 'version'], capture_output=True, text=True)
            version = re.search(r'\bVersion\s*:\s*(\S+)', version_result.stdout).group(
                1) if version_result.returncode == 0 else "Unknown version"

            if 'State                                 ON' in result.stdout:
                logging_status.append(f"{profile} Logging: ON, Version: {version}")
            elif 'State                                 OFF' in result.stdout:
                logging_status.append(f"{profile} Logging: OFF, Version: {version}")
            else:
                logging_status[profile] = "Error: Unable to determine"
        return logging_status

    except Exception as e:
        print(f"Error checking Windows Firewall Logging: {e}")
        return ["Not detected"]


def check_agent_based_log_collection_windows():
    programs = [
        "wazuh-agent",
        "splunkd",
        "qradar",
        "arcsight",
        "logrhythm",
        "sumologic",
        "securonix"
    ]
    detected_programs = []
    for program in programs:
        try:
            result = subprocess.run(['sc', 'query', program], capture_output=True, text=True)
            version_result = subprocess.run([program, '--version'], capture_output=True, text=True)
            version = re.search(r'\b(\d+\.\d+)', version_result.stdout).group(
                1) if version_result.returncode == 0 else "Unknown version"

            if 'RUNNING' in result.stdout:
                detected_programs.append(f"{program}, Version: {version}")
        except Exception as e:
            print(f"Error checking {program}: {e}")
    return detected_programs if detected_programs else ["Not detected"]


def get_windows_version():
    os = platform.platform()
    return f"{os}"


def check_windows_updates():
    try:
        result = subprocess.run(
            ['powershell', '-Command', 'Import-Module PSWindowsUpdate; Get-WindowsUpdate -ListOnly'],
            capture_output=True, text=True)

        if result.returncode == 0:
            updates = result.stdout.strip()
            return updates if updates else "No updates available"
        else:
            return "Error: Unable to check for updates"
    except Exception as e:
        print(f"Error checking Windows updates: {e}")
        return "Not detected"


def get_installed_software_powershell():
    try:
        result = subprocess.run(
            ['powershell', 'Get-WmiObject -Class Win32_Product | Select-Object -Property Name, Version'],
            capture_output=True, text=True, check=True)

        software_list = result.stdout.split('\n')
        software_list = [line.strip() for line in software_list if line.strip()]
        software_list = software_list[2:]

        software_dict = {}
        pattern = re.compile(r'(.*\S)\s+(\d+\.\d+\.\d+\.\d+)')

        for software in software_list:
            match = pattern.match(software)
            if match:
                name = match.group(1).strip()
                version = match.group(2).strip()
                software_dict[name] = version
        #convert to newline separated string
        return software_dict

    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e}")
