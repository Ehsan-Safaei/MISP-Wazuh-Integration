# 🔍 IOC Lookup Script for Wazuh Alerts

This Python script extracts IPs, domains, or hashes from Wazuh alerts and checks whether they exist in predefined threat intelligence feed files (from sources like MISP or custom lists).
It’s designed for fast lookups and easy integration into Wazuh or other security automation workflows.

## 🚀 Features

Detects and classifies event parameters as:

✅ IP address
✅ Domain name
✅ File hash (SHA256)

Checks if the extracted IOC exists in:

/var/ossec/lists/MISP_ip.txt
/var/ossec/lists/MISP_domain.txt
/var/ossec/lists/MISP_hash.txt

Efficient set-based lookup for high performance.
Graceful handling of missing files or malformed alerts.
Simple to extend or integrate with additional feeds or formats.

## ⚙️ Configuration

Edit the following paths in the script to match your environment:

ip_feed_file = "/var/ossec/lists/MISP_ip.txt"
domain_feed_file = "/var/ossec/lists/MISP_domain.txt"
hash_feed_file = "/var/ossec/lists/MISP_hash.txt"

Each file should contain one IOC per line:

`1.2.3.4`

`malicious.com`

`9b74c9897bac770ffc029102a200c5de`

## 🧠 Example

Example usage with a Wazuh Sysmon alert:

`alert = {
    "rule": {"groups": ["windows", "sysmon", "sysmon_event3"]},
    "data": {"win": {"eventdata": {"destinationIp": "8.8.8.8", "destinationIsIpv6": "false"}}},
}`

 _The script detects the IP and checks if it exists in the MISP_ip.txt list_

## ⚠️ Notes

Designed for local IOC list lookups, not online threat feeds.
Supports SHA256 hashes by default; can be extended to MD5/SHA1.
Run in an environment where Wazuh alert JSONs are available.

## 🧰 Requirements

Python 3.7+
Works on Linux systems (default file paths use /var/ossec)
No external dependencies are required — all libraries are standard in Python.

## 📜 License

This project is released under the MIT License.
Feel free to modify and adapt for your SOC, Wazuh, or threat intelligence workflows.
