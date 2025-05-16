import requests
import urllib3
import xml.etree.ElementTree as ET
from urllib.parse import urlencode

# Disable only the insecure request warning from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FIREWALL_HOST = "192.168.29.55"
USERNAME = "admin"
PASSWORD = "P@ssw0rd"

def get_api_key():
    """ This function uses url and data to send a post request to the firewall
    and accepts an xml response. If key in response is none - API key is not
    found. Else it returns API key.
    """
    url = f"{FIREWALL_HOST}/api/"
    data = {
        "type": "keygen",
        "user": USERNAME,
        "password": PASSWORD
    }
    resp = requests.post(
        url,
        data=urlencode(data),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        verify=False
    )

    if resp.status_code != 200:
        raise Exception(f"Failed to get API key: HTTP {resp.status_code}")

    root = ET.fromstring(resp.text)
    key = root.find(".//key")
    if key is None:
        print("Firewall response for keygen:")
        print(resp.text)
        raise Exception("API key not found. Check credentials or firewall API settings.")
    return key.text

def run_op_cmd(api_key, cmd_xml):
    """ This function makes a get request to the firewall using api_key and cmd_xml.
    If response status is not 200 - API call has failed, else it returns the response text.
    """
    url = f"{FIREWALL_HOST}/api/?type=op&key={api_key}&cmd={cmd_xml}"
    resp = requests.get(url, verify=False)
    if resp.status_code != 200:
        raise Exception(f"API call failed: {resp.status_code} {resp.text}")
    return ET.fromstring(resp.text)

def get_content_versions(api_key):
    """ This function calls the ru_op_cmd() to make a API request that executes the cmd, 
    response text is returned. It checks if each key-value pair from content_keys dict is
    present in the response text, retrieves version information, and returns versions.
    """
    cmd = "<request><content><upgrade><info></info></upgrade></content></request>"
    root = run_op_cmd(api_key, cmd)

    content_keys = {
        "antivirus-version": "Antivirus",
        "url-filtering-version": "URL Filtering",
        "threats-version": "Threat Prevention",
    }

    versions = {}
    for key in content_keys:
        name = content_keys[key]
        elem = root.find(f".//{key}")
        if elem is not None and elem.text:
            versions[name] = elem.text
        else:
            versions[name] = "Not Installed / Unknown"
    return versions


if __name__ == "__main__":
    print("Connecting to firewall...")
    api_key = get_api_key()
    versions = get_content_versions(api_key)

    print("\nInstalled Content Versions:")
    for name in versions:
        version = versions[name]
        print(f"{name}: {version}")
