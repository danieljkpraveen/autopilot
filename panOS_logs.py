from panos.firewall import Firewall
from xml.etree import ElementTree as ET
from tabulate import tabulate
import csv

# Replace with your firewall details
hostname = "your_firewall_ip"
api_key = "YOUR_API_KEY"

# Connect to the firewall
fw = Firewall(hostname, api_key=api_key)

# Log type mapping
log_type_mapping = {
    "traffic": "traffic",
    "threat": "threat",
    "url filtering": "url",
    "wildfire submissions": "wildfire",
    "data filtering": "data",
    "config": "config",
    "system": "system",
    "hip match": "hipmatch",
    "globalprotect": "gpc",
    "ip-tag": "iptag",
    "tunnel inspection": "tunnel",
    "alarms": "alarm",
    "authentication": "auth",
    "user-id": "user-id",
    "decryption": "decryption",
    "unified": "unified"
}

# Get user input
print("Available log types:")
for name in log_type_mapping:
    print(f"- {name.title()}")

log_type_input = input("\nEnter log type ('all' to display all logs): ").strip().lower()
log_limit = input("Enter number of logs to fetch: ")
log_limit = int(log_limit) if log_limit.isdigit() else 10

start_time = input("Start time (YYYY/MM/DD HH:MM:SS): ").strip()
end_time = input("End time (YYYY/MM/DD HH:MM:SS): ").strip()

# Determine log types to fetch
if log_type_input == "all":
    log_types = list(log_type_mapping.values())
elif log_type_input in log_type_mapping:
    log_types = [log_type_mapping[log_type_input]]
else:
    print(f"Invalid log type: {log_type_input}")
    exit(1)

for log_type in log_types:
    print(f"\nFetching {log_type} logs...")

    cmd = (
        f"show log {log_type} direction equal forward "
        f"time {start_time} to {end_time} max {log_limit}"
    )

    try:
        xml_response = fw.op(cmd, cmd="show")
        root = ET.fromstring(xml_response)
        entries = root.findall(".//entry")

        if not entries:
            print("No log entries found.")
            continue

        # Get all field names dynamically
        field_names = sorted({elem.tag for entry in entries for elem in entry})
        table = []

        for entry in entries:
            row = [entry.findtext(field, default="-") for field in field_names]
            table.append(row)

        # Display in terminal
        print(tabulate(table, headers=field_names, tablefmt="grid"))

        # Write to CSV
        filename = f"logs.csv"
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(field_names)
            writer.writerows(table)

        print(f"Logs exported to: {filename}")

    except Exception as e:
        print(f"Error fetching {log_type} logs: {e}")
