import re



def check_ubuntu_firewall():
    programs = [
        "ufw", # tested, but needs admin
    ]
    detected_programs = []
    for program in programs:
        try:
            result = subprocess.run(['systemctl', 'status', program], capture_output=True, text=True)
            version_result = subprocess.run([program, '--version'], capture_output=True, text=True)
            version = re.search(r'\b(\d+\.\d+)', version_result.stdout).group(
                1) if version_result.returncode == 0 else "Unknown version"

            if result.returncode == 0 or result.returncode == 3:
                detected_programs.append(f"{program}, Version: {version}")
        except Exception as e:
            print(f"Error checking {program}: {e}")
    return detected_programs if detected_programs else ["Not detected"]


def check_ubuntu_antivirus():
    detected_antivirus = []
    programs = [
        "None" #no ubuntu antiviruses have been tested yet
    ]
    for program in programs:
        try:
            result = subprocess.run(['systemctl', 'status', program], capture_output=True, text=True)
            version_result = subprocess.run([program, '--version'], capture_output=True, text=True)
            version = re.search(r'\b(\d+\.\d+\.\d+)', version_result.stdout).group(
                1) if version_result.returncode == 0 else "Unknown version"

            if result.returncode == 0 or result.returncode == 3:
                detected_antivirus.append(f"{program}, Version: {version}")
        except Exception as e:
            print(f"Error checking {program}: {e}")
    return detected_antivirus if detected_antivirus else ["Not detected"]


def check_open_ports_ubuntu():
    try:
        result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True)
        if result.returncode != 0:
            return "Error: netstat command failed"

        listening_ports = []
        lines = result.stdout.splitlines()
        for line in lines[2:]:
            if re.search(r'\s+LISTEN\s+', line):
                port_match = re.search(r':(\d+)\s+', line)
                if port_match:
                    listening_ports.append(int(port_match.group(1)))
        return listening_ports

    except Exception as e:
        return f"Error checking open ports: {e}"






def check_agent_based_log_collection_ubuntu():
    programs = [
        "wazuh-agent", # the only one tested so far, add as needed
    ]
    detected_programs = []

    for program in programs:
        try:
            result = subprocess.run(['systemctl', 'status', program], capture_output=True, text=True)
            #get wazuh-agent version number
            if program == "wazuh-agent":
                version_result = subprocess.run(['/var/ossec/bin/wazuh-control', 'info'], capture_output=True,
                                                text=True)
                version_match = re.search(r'WAZUH_VERSION="v(\d+\.\d+\.\d+)"', version_result.stdout)
                version = version_match.group(1) if version_match else "Unknown version"
            else:
                version_result = subprocess.run([program, '--version'], capture_output=True, text=True)
                version = re.search(r'\b(\d+\.\d+)', version_result.stdout).group(
                    1) if version_result.returncode == 0 else "Unknown version"

            if result.returncode == 0 or result.returncode == 3:
                detected_programs.append(f"{program}, Version: {version}")
        except Exception as e:
            print(f"Error checking {program}: {e}")

    return detected_programs if detected_programs else ["Not detected"]


if __name__ == "__main__":
    programs_status = check_agent_based_log_collection_ubuntu()
    for status in programs_status:
        print(status)


def check_syslog():
    try:
        result = subprocess.run(['systemctl', 'status', 'syslogd'], capture_output=True, text=True)
        if result.returncode == 0 or result.returncode == 3:
            return ["Detected"]
    except Exception as e:
        print(f"Error checking Syslog/RSyslog: {e}")
    return ["Not detected"]


import subprocess


def get_installed_programs_ubuntu():
    #has limitations, for example, programs that were  installed manually.
    try:
        result = subprocess.run(['dpkg-query', '-W'], capture_output=True,
                                text=True)
        if result.returncode != 0:
            return "Error: dpkg-query command failed"

        installed_programs = result.stdout.splitlines()

        return installed_programs

    except Exception as e:
        return f"Error retrieving installed programs: {e}"



