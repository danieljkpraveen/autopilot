from panos.firewall import Firewall
from panos.updater import SoftwareUpdater

# Replace with your firewall details
hostname = "your_firewall_ip"
api_key = "YOUR_API_KEY"

# Connect to the firewall
print("Connecting to the firewall...")
fw = Firewall(hostname, api_key=api_key)

# Attach the SoftwareUpdater
print("Initializing software updater...")
updater = SoftwareUpdater()
fw.add(updater)

# Check for available software updates
print("Checking for available software updates...")
updates = updater.check()

# Filter out the version that's currently running
upgrade_candidates = []
for update in updates:
    if not update.current:
        upgrade_candidates.append(update)

# Exit if no upgrade options are found
if len(upgrade_candidates) == 0:
    print("No upgrade candidates available.")
    exit()

# Display available upgrade versions
print("\nAvailable PAN-OS Versions for Upgrade:")
for update in upgrade_candidates:
    if update.downloaded:
        status = "Downloaded"
    else:
        status = "Not downloaded"
    print(f"- {update.version} ({status})")

# Prompt user to select a version
target_version = input("\nEnter the version to upgrade to: ").strip()

# Find the selected version object
target = None
for update in upgrade_candidates:
    if update.version == target_version:
        target = update
        break

# Exit if selected version is invalid
if target is None:
    print(f"Version {target_version} not found among upgrade candidates.")
    exit()

# Perform upgrade (download, install, reboot)
print(f"\nUpgrading to PAN-OS {target_version} (download + install + reboot)...")
updater.download_install_reboot(version=target_version, sync=True)
print("Upgrade and reboot process initiated successfully.")
