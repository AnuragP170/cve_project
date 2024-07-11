def generate_ip_list(start, end):
    ip_list = []
    for i in range(start, end + 1):
        ip_list.append(f"127.0.0.{i}")
    return ip_list

# Generate IP list from 127.0.0.1 to 127.0.0.125
ip_list = generate_ip_list(1, 125)

# Print the IP addresses
for ip in ip_list:
    print(ip)
