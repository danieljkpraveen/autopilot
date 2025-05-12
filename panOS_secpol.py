from panos.firewall import Firewall
from panos.policies import SecurityRule

# Connect to the firewall
hostname = input("Enter firewall IP/hostname: ").strip()
api_key = input("Enter API key: ").strip()

fw = Firewall(hostname, api_key=api_key)

# Get user inputs for the rule
rule_name = input("Enter rule name: ").strip()
from_zone = input("Enter source zone: ").strip()
to_zone = input("Enter destination zone: ").strip()
source_ip = input("Enter source IP (or 'any'): ").strip() or "any"
destination_ip = input("Enter destination IP (or 'any'): ").strip() or "any"
application = input("Enter application (or 'any'): ").strip() or "any"
service = input("Enter service (or 'application-default' or 'any'): ").strip() or "application-default"
action = input("Enter action (allow/deny/drop): ").strip().lower()

# Create rule object
rule = SecurityRule(
    name=rule_name,
    fromzone=[from_zone],
    tozone=[to_zone],
    source=[source_ip],
    destination=[destination_ip],
    application=[application],
    service=[service],
    action=action
)

# Attach to firewall and apply
fw.add(rule)

try:
    rule.apply()  # or use rule.create() if preferred
    print(f"✅ Rule '{rule_name}' created successfully.")
except Exception as e:
    print(f"❌ Failed to create rule: {e}")
