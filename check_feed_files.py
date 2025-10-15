#!/var/ossec/framework/python/bin/python3
## MISP API Integration
#
import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
import ipaddress
import hashlib
import re

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = "{0}/queue/sockets/queue".format(pwd)
false = False

##File Pathes
ip_feed_file = "/var/ossec/lists/MISP_ip.txt"
domain_feed_file = "/var/ossec/lists/MISP_domain.txt"
hash_feed_file = "/var/ossec/lists/MISP_hash.txt"

##For send event tp wazuh queue
def send_event(msg, agent=None):
    if not agent or agent["id"] == "000":
        string = "1:misp:{0}".format(json.dumps(msg))
    else:
        string = "1:[{0}] ({1}) {2}->misp:{3}".format(
            agent["id"],
            agent["name"],
            agent["ip"] if "ip" in agent else "any",
            json.dumps(msg),
        )
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

## Regex Pattern used based on SHA256 lenght (64 characters)
regex_file_hash = re.compile("\w{64}")

##For Checkings
def load_file_content(filepath):
    """Load file content into set for fast lookup."""
    if not os.path.exists(filepath):
        return set()
    with open(filepath, 'r') as f:
        return set(line.strip() for line in f if line.strip())

def check_in_file(value, filepath):
    """Check if value exists in file."""
    content = load_file_content(filepath)
    return value in content

def check_ip_exists(ip):
    """Check if IP exists in IP feed file."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_global:
            return check_in_file(ip, ip_feed_file)
    except ValueError:
        pass
    return False

def check_domain_exists(domain):
    """Check if domain exists in domain feed file."""
    return check_in_file(domain, domain_feed_file)

def check_hash_exists(hash_val):
    """Check if hash exists in hash feed file."""
    match = regex_file_hash.fullmatch(hash_val)
    if match:
        return check_in_file(match.group(0), hash_feed_file)
    return False

# Read configuration parameters
alert_file = open(sys.argv[1])
# Read the alert file
alert = json.loads(alert_file.read())
alert_file.close()
# New Alert Output if MISP Alert
alert_output = {}

## Extract Sysmon for Windows/Sysmon for Linux and Sysmon Event ID
event_source = alert["rule"]["groups"][0]
event_type = alert["rule"]["groups"][2]

if event_source == "windows":
    if event_type == "sysmon_event1":
        try:
            wazuh_event_param = regex_file_hash.search(
                alert["data"]["win"]["eventdata"]["hashes"]
            ).group(0)
            wazuh_event_param_type = "hash"
        except IndexError:
            sys.exit()
    elif (
        event_type == "sysmon_event3"
        and alert["data"]["win"]["eventdata"]["destinationIsIpv6"] == "false"
    ):
        try:
            dst_ip = alert["data"]["win"]["eventdata"]["destinationIp"]
            if ipaddress.ip_address(dst_ip).is_global:
                wazuh_event_param = dst_ip
                wazuh_event_param_type = "ip"
            else:
                sys.exit()
        except IndexError:
            sys.exit()
    elif (
        event_type == "sysmon_event3"
        and alert_output["data"]["win"]["eventdata"]["destinationIsIpv6"] == "true"
    ):
        sys.exit()
    elif event_type == "sysmon_event6":
        try:
            wazuh_event_param = regex_file_hash.search(
                alert["data"]["win"]["eventdata"]["hashes"]
            ).group(0)
            wazuh_event_param_type = "hash"
        except IndexError:
            sys.exit()
    elif event_type == "sysmon_event7":
        try:
            wazuh_event_param = regex_file_hash.search(
                alert["data"]["win"]["eventdata"]["hashes"]
            ).group(0)
            wazuh_event_param_type = "hash"
        except IndexError:
            sys.exit()
    elif event_type == "sysmon_event_15":
        try:
            wazuh_event_param = regex_file_hash.search(
                alert["data"]["win"]["eventdata"]["hashes"]
            ).group(0)
            wazuh_event_param_type = "hash"
        except IndexError:
            sys.exit()
    elif event_type == "sysmon_event_22":
        try:
            wazuh_event_param = alert["data"]["win"]["eventdata"]["queryName"]
            wazuh_event_param_type = "domain"
        except IndexError:
            sys.exit()
    elif event_type == "sysmon_event_23":
        try:
            wazuh_event_param = regex_file_hash.search(
                alert["data"]["win"]["eventdata"]["hashes"]
            ).group(0)
            wazuh_event_param_type = "hash"
        except IndexError:
            sys.exit()
    elif event_type == "sysmon_event_24":
        try:
            wazuh_event_param = regex_file_hash.search(
                alert["data"]["win"]["eventdata"]["hashes"]
            ).group(0)
            wazuh_event_param_type = "hash"
        except IndexError:
            sys.exit()
    elif event_type == "sysmon_event_25":
        try:
            wazuh_event_param = regex_file_hash.search(
                alert["data"]["win"]["eventdata"]["hashes"]
            ).group(0)
            wazuh_event_param_type = "hash"
        except IndexError:
            sys.exit()
    else:
        sys.exit()

elif event_source == "linux":
    if (
        event_type == "sysmon_event3"
        and alert["data"]["eventdata"]["destinationIsIpv6"] == "false"
    ):
        try:
            dst_ip = alert["data"]["eventdata"]["DestinationIp"]
            if ipaddress.ip_address(dst_ip).is_global:
                wazuh_event_param = dst_ip
                wazuh_event_param_type = "ip"
            else:
                sys.exit()
        except IndexError:
            sys.exit()
    else:
        sys.exit()
elif event_source == "ossec" and event_type == "syscheck_entry_added":
    try:
        wazuh_event_param = alert["syscheck"]["sha256_after"]
        wazuh_event_param_type = "hash"
    except IndexError:
        sys.exit()
else:
    sys.exit()

if wazuh_event_param and wazuh_event_param_type:
    exists = False
    if wazuh_event_param_type == "ip":
        exists = check_ip_exists(wazuh_event_param)
    elif wazuh_event_param_type == "hash":
        exists = check_hash_exists(wazuh_event_param)
    elif wazuh_event_param_type == "domain":
        exists = check_domain_exists(wazuh_event_param)
    
    if exists:
        #print(f"{wazuh_event_param_type} {wazuh_event_param} found in MISP feed")
        alert_output["misp"] = {}
        alert_output["integration"] = "MISP"
        alert_output["misp"]["source"] = {}
        alert_output["misp"]["category"] = "Network Activity"
        alert_output["misp"]["value"] = wazuh_event_param
        alert_output["misp"]["type"] = wazuh_event_param_type
        alert_output["misp"]["source"]["description"] = "MISP_THREAT_FOUND"
        send_event(alert_output, alert["agent"])
    else:
        #print(f"{wazuh_event_param_type} {wazuh_event_param} not found")
        sys.exit()
