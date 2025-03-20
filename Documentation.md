

# Device Discovery and Inventory Automation Documentation

## Table of Contents

1. Introduction  
2. System Overview  
3. Pre-requisites  
4. Setup and Configuration  
   - 4.1. Directory Structure  
   - 4.2. Configuration File  
   - 4.3. Python Discovery Script  
   - 4.4. Inventory Storage and Reporting  
   - 4.5. Systemd Service Setup  
5. Testing and Validation  
6. Troubleshooting  
7. Best Practices and Recommendations  
8. Conclusion  

---

## 1. Introduction

This document describes an automated system for discovering devices on the network and maintaining an up-to-date inventory. The solution utilizes periodic network scans, processes the discovered data, and updates an inventory database. This information is then available for integration with monitoring tools such as OpenNMS, ensuring that the network inventory remains current and accurate.

---

## 2. System Overview

The device discovery and inventory automation system consists of several key components:

- **Network Scanning:**  
  A Python script performs periodic scans of defined IP ranges using tools like Nmap to discover devices and gather key attributes (IP address, MAC address, hostname, open ports).

- **Data Processing:**  
  The script parses scan results, compares them with an existing inventory, and updates a JSON/CSV-based inventory database.

- **Inventory Reporting:**  
  Generated reports can be integrated into OpenNMS or other network management systems for asset tracking and configuration management.

- **Automation:**  
  A systemd service ensures that device discovery runs automatically at set intervals, keeping the inventory current without manual intervention.

---

## 3. Pre-requisites

Before deploying the system, ensure that you have the following:

- **Operating System:**  
  Unix-like OS (e.g., Linux).

- **Python 3:**  
  Installed on the discovery server.

- **Network Scanning Tool:**  
  Nmap must be installed for performing network scans:
  ```bash
  sudo apt-get update
  sudo apt-get install nmap -y
  ```

- **Required Python Packages:**  
  Install required Python modules:
  ```bash
  pip3 install python-nmap
  ```

- **Network Permissions:**  
  Sufficient permissions to perform network scans and access the device inventory file.

- **Storage:**  
  Ensure there is enough disk space for storing inventory data and logs.

---

## 4. Setup and Configuration

### 4.1. Directory Structure

Organize files and folders as follows:

```bash
/etc/device_inventory/
├── discovery.py             # Main Python script for device discovery
├── config.json              # Configuration file for scan parameters and inventory settings
├── inventory.json           # File storing the current inventory data
└── discovery.log            # Log file for discovery events
```

### 4.2. Configuration File

**Path:** `/etc/device_inventory/config.json`

Example configuration file:
```json
{
    "scan_interval": 3600,
    "ip_range": "192.168.1.0/24",
    "nmap_options": "-sP",
    "inventory_file": "/etc/device_inventory/inventory.json",
    "logging": {
        "log_file": "/etc/device_inventory/discovery.log",
        "log_level": "INFO"
    }
}
```

**Notes:**
- **`scan_interval`**: Time in seconds between scans.
- **`ip_range`**: Target network range for device discovery.
- **`nmap_options`**: Options passed to Nmap (e.g., `-sP` for a ping scan).
- **`inventory_file`**: Path to the JSON file that stores inventory data.

### 4.3. Python Discovery Script

**Path:** `/etc/device_inventory/discovery.py`

Below is a sample Python script that performs device discovery and updates the inventory:

```python
#!/usr/bin/env python3

import json
import os
import time
import logging
import nmap
from datetime import datetime

# ---------------------------
# Load Configuration
# ---------------------------
CONFIG_FILE = "/etc/device_inventory/config.json"

def load_config(config_path):
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file {config_path} not found.")
    with open(config_path, 'r') as f:
        return json.load(f)

config = load_config(CONFIG_FILE)
SCAN_INTERVAL = config.get("scan_interval", 3600)
IP_RANGE = config.get("ip_range", "192.168.1.0/24")
NMAP_OPTIONS = config.get("nmap_options", "-sP")
INVENTORY_FILE = config.get("inventory_file", "/etc/device_inventory/inventory.json")

# ---------------------------
# Setup Logging
# ---------------------------
LOG_CONFIG = config.get("logging", {})
LOG_FILE = LOG_CONFIG.get("log_file", "/etc/device_inventory/discovery.log")
LOG_LEVEL = LOG_CONFIG.get("log_level", "INFO").upper()

logging.basicConfig(
    filename=LOG_FILE,
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ---------------------------
# Device Inventory Functions
# ---------------------------
def load_inventory():
    if os.path.exists(INVENTORY_FILE):
        with open(INVENTORY_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                logging.error("Inventory file is corrupted. Starting with an empty inventory.")
                return {}
    return {}

def save_inventory(inventory):
    with open(INVENTORY_FILE, 'w') as f:
        json.dump(inventory, f, indent=4)

def update_inventory(discovered_devices):
    inventory = load_inventory()
    timestamp = datetime.utcnow().isoformat() + "Z"
    for device in discovered_devices:
        ip = device.get("ip")
        inventory[ip] = {
            "hostname": device.get("hostname"),
            "last_seen": timestamp,
            "ports": device.get("ports", []),
            "mac": device.get("mac")
        }
    save_inventory(inventory)
    logging.info("Inventory updated with discovered devices.")

# ---------------------------
# Device Discovery Function
# ---------------------------
def discover_devices():
    nm = nmap.PortScanner()
    logging.info(f"Starting scan on IP range: {IP_RANGE}")
    try:
        nm.scan(hosts=IP_RANGE, arguments=NMAP_OPTIONS)
    except Exception as e:
        logging.error(f"Error during scanning: {e}")
        return []

    devices = []
    for host in nm.all_hosts():
        device_info = {
            "ip": host,
            "hostname": nm[host].hostname(),
            "ports": list(nm[host].all_tcp().keys()) if nm[host].state() == "up" else [],
            "mac": nm[host]['addresses'].get('mac', 'Unknown')
        }
        devices.append(device_info)
        logging.info(f"Discovered device: {device_info}")
    return devices

# ---------------------------
# Main Loop
# ---------------------------
def main():
    logging.info("Starting Device Discovery Service.")
    while True:
        devices = discover_devices()
        if devices:
            update_inventory(devices)
        else:
            logging.info("No devices discovered during scan.")
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    main()
```

**Notes:**

- The script uses **python-nmap** to perform network scans.
- Discovered devices are parsed to extract IP address, hostname, open ports, and MAC address.
- The inventory is stored in a JSON file and updated with a timestamp for each discovered device.

### 4.4. Inventory Storage and Reporting

- **Storage:**  
  The JSON file serves as a persistent storage for the inventory. You may extend this to a database for larger environments.
  
- **Reporting:**  
  Create custom scripts or dashboards (e.g., with Grafana or OpenNMS) to visualize the inventory data and changes over time.

### 4.5. Systemd Service Setup

**Path:** `/etc/systemd/system/device_discovery.service`

Create a systemd service file to run the discovery script as a daemon:

```ini
[Unit]
Description=Device Discovery and Inventory Automation Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/device_inventory/discovery.py
Restart=on-failure
RestartSec=60
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

**Setup Steps:**

1. Create the service file:
   ```bash
   sudo nano /etc/systemd/system/device_discovery.service
   ```
2. Paste the above content and save the file.
3. Reload systemd and enable the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable device_discovery.service
   ```
4. Start the service:
   ```bash
   sudo systemctl start device_discovery.service
   ```
5. Verify the service status:
   ```bash
   sudo systemctl status device_discovery.service
   ```

---

## 5. Testing and Validation

- **Manual Scan:**  
  Run the discovery script manually:
  ```bash
  sudo /usr/bin/python3 /etc/device_inventory/discovery.py
  ```
  Verify that devices are discovered and the inventory file is updated.

- **Log Review:**  
  Check the log file `/etc/device_inventory/discovery.log` for detailed scan results and any errors.

- **Inventory Inspection:**  
  Open the inventory file to ensure that device details (IP, hostname, MAC, etc.) are correctly recorded:
  ```bash
  cat /etc/device_inventory/inventory.json
  ```

---

## 6. Troubleshooting

- **Scanning Errors:**  
  Verify that Nmap is installed and working correctly by running a manual scan:
  ```bash
  nmap -sP 192.168.1.0/24
  ```

- **Permissions:**  
  Ensure the script has sufficient permissions to write to the inventory and log files.

- **Configuration Validation:**  
  Double-check the settings in `config.json` for any incorrect values (e.g., IP range or file paths).

- **Service Logs:**  
  Use `sudo journalctl -u device_discovery.service` to review systemd logs if the service fails to start.

---

## 7. Best Practices and Recommendations

- **Regular Updates:**  
  Schedule frequent scans based on network size and expected change frequency.
  
- **Security:**  
  Limit access to the inventory and configuration files to authorized personnel only.
  
- **Integration:**  
  Consider integrating inventory data with OpenNMS for enhanced monitoring and alerting capabilities.
  
- **Backup:**  
  Regularly back up the inventory file or database to prevent data loss.

---

## 8. Conclusion

The Device Discovery and Inventory Automation system provides an automated and scalable approach to maintaining a current view of the network assets. By integrating periodic network scans with automated inventory updates, this solution ensures that monitoring tools like OpenNMS have accurate data to work with, aiding in effective network management and incident response.

