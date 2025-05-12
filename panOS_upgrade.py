from panos.firewall import Firewall
from panos.updater import SoftwareUpdater

# Replace with your firewall details
hostname = "your_firewall_ip"
api_key = "YOUR_API_KEY"

# Connect to the firewall
fw = Firewall(hostname, api_key=api_key)

# Attach the SoftwareUpdater
updater = SoftwareUpdater()
fw.add(updater)

# Get all available software versions
print("Checking for available software updates...")
updates = updater.check()

if not updates:
    print("No updates available.")
    exit()

print("\nAvailable PAN-OS Versions:")
for update in updates:
    print(f"- {update.version} (Downloaded: {update.downloaded}, Current: {update.current})")

# Let the user select a version
target_version = input("\nEnter the version to upgrade to: ").strip()
target = next((u for u in updates if u.version == target_version), None)

if not target:
    print(f"Version {target_version} not found.")
    exit()

# Perform download, install, and reboot in one step
print(f"\nUpgrading to PAN-OS {target_version} (download + install + reboot)...")
updater.download_install_reboot(version=target_version, sync=True)
print("Upgrade and reboot process initiated successfully.")
