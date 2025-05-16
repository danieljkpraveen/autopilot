from netmiko import ConnectHandler
from xml.etree import ElementTree as ET
from tabulate import tabulate
import csv

# Firewall login credentials
hostname = "192.168.29.55"
username = "admin"
password = "P@ssw0rd"

# Valid PAN-OS log types
valid_log_types = [
    "traffic", "threat", "url", "wildfire", "data",
    "config", "system", "hipmatch", "gpc", "iptag",
    "tunnel", "alarm", "auth", "user-id", "decryption", "unified"
]

# Get user input
print("Available log types:")
for name in valid_log_types:
    print(f"- {name}")

log_type_input = input("\nEnter log type ('all' to display all logs): ").strip().lower()
log_limit_input = input("Enter number of logs to fetch: ")
log_limit = int(log_limit_input) if log_limit_input.isdigit() else 10

start_time = input("Start time (YYYY/MM/DD HH:MM:SS): ").strip()
end_time = input("End time (YYYY/MM/DD HH:MM:SS): ").strip()

# Determine log types
if log_type_input == "all":
    log_types = valid_log_types
elif log_type_input in valid_log_types:
    log_types = [log_type_input]
else:
    print(f"Invalid log type: {log_type_input}")
    exit(1)

# Connect to the firewall using Netmiko
device = {
    "device_type": "paloalto_panos",
    "host": hostname,
    "username": username,
    "password": password,
}

print("\nConnecting to the firewall via SSH...")
try:
    ssh = ConnectHandler(**device)
    ssh.send_command("set cli scripting-mode on")  # Enable scripting mode (important)
except Exception as e:
    print(f"Connection failed: {e}")
    exit(1)

# Fetch logs for each type
for log_type in log_types:
    print(f"\nFetching {log_type} logs...")

    cmd = (
        f"show log {log_type} direction equal forward "
        f"time '{start_time}' to '{end_time}' max {log_limit}"
    )

    try:
        output = ssh.send_command(cmd)
        root = ET.fromstring(output)
        entries = root.findall(".//entry")

        if not entries:
            print("No log entries found.")
            continue

        # Extract headers dynamically
        field_names_set = set()
        for entry in entries:
            for elem in entry:
                field_names_set.add(elem.tag)

        field_names = sorted(list(field_names_set))

        # Build table rows
        table = []
        for entry in entries:
            row = [entry.findtext(field, default="-") for field in field_names]
            table.append(row)

        # Print table to terminal
        print(tabulate(table, headers=field_names, tablefmt="grid"))

        # Save to CSV
        filename = f"{log_type}_logs.csv"
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(field_names)
            writer.writerows(table)

        print(f"Logs exported to: {filename}")

    except Exception as e:
        print(f"Error fetching {log_type} logs: {e}")

# Close SSH connection
ssh.disconnect()
