# Kintun: Restful Vulnerability Scanner

[![AUR](https://img.shields.io/aur/license/yaourt.svg?maxAge=2592000)](https://github.com/CERTUNLP/Kintun/blob/master/LICENSE)
![Python 3](http://img.shields.io/badge/python-3-blue.svg)

Kintun is a Restful API for scanning network vulnerabilities and exporting results to a specified system. It is designed to work seamlessly with various scanning tools and services.

### Related Projects:
- **NGEN**: (https://github.com/CERTUNLP/ngen)

### Requirements:

- **Python 3**: Ensure you have Python 3.x installed.
- **Flask**: Web framework required for running the API.
- **MongoDB**: A database for storing scan results (configured in `config.json`).
- **Nmap**: Network scanner for vulnerability scanning.
- **SSL Support**: For running the app with SSL encryption.
- **Expect**: For handling scripted interactions with external services.
- **Shelldap**: LDAP client for specialized tasks.
- **Other dependencies**: Check the `requirements.txt` file for Python dependencies.

---

### How to Install

To set up Kintun, follow the steps below depending on whether you want to use **Docker** or run the app locally.

#### 1. Prerequisites

Ensure your system has the necessary tools installed:

- **Python 3** and **pip** for Python package management.
- **MongoDB** for storing scan results.
- **Docker** (optional for Docker-based installation).
  
#### 2. Install Dependencies

For local installation, run the following commands to install system dependencies and Python packages:

##### System Dependencies:

```bash
$ sudo apt update
$ sudo apt install -y python3 python3-pip python3-dev libssl-dev libffi-dev expect shelldap nmap mongodb
```

##### Python Dependencies (we recommend to use virtualenv):
```bash
$ python3 -m venv env
$ source env/bin/activate
$ pip3 install -r requirements.txt
```

#### 3. Configure SSL (Optional)
If you wish to run the app with SSL, you can generate a self-signed certificate using the following Python command:
```bash
$ python3
>>> from werkzeug.serving import make_ssl_devcert
>>> make_ssl_devcert('ssl/key', host='localhost')
```

#### 4. Configure MongoDB and App Settings
1. Copy the example configuration file:
```bash
$ cp config.json.example config.json
```
2. Open the config.json file and modify the MongoDB connection settings as needed (e.g., host, port, authentication).

#### 5. Running Kintun
To make it easier to start Kintun, use the provided start_kintun.sh script. This script checks for Docker, installs requirements if necessary, and prompts you to choose between running Kintun with Docker or locally (if wanted to run locally remember to use virtualenv).
To run Kintun:
```bash
$ ./start_kintun.sh
```

This script will guide you through the setup process and start the Kintun app accordingly, either with Docker or directly on your local machine.

---
How to use it
-------

```python
import requests

url = 'http://KINTUN_URL/api'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
    'x-api-key': 'your_api_key'
}

data = {
    "vuln" : "some_vuln",
    "network" : 'Ip or domain (if web)',
    "ports" : ['port1,port2,..,portX'],
    "params" : {"feed":"your_feed", "send-nmap-report":0},
    "protocol" : ["tcp_or_udp"],
    "outputs" : [],
    "report_to" : ""
}
r = requests.post(url+'/scan', headers=headers, json=data)
```

The type of vulns to choose from are defined in **scannerapp/model/vuln/\_\_init\_\_.py** (it is not a static list, it can be updated with new features)


The response will look like this (example of a web scan to ip):
```json
{
  "_id": "67a0d5f48a5b86d3567baec6",
  "_network": "scanme.org",
  "_origin": "127.0.0.1",
  "_outputs": [],
  "_ports": [
    "80,443"
  ],
  "_protocols": [
    "tcp"
  ],
  "errors": [],
  "finished_at": "",
  "is_vuln": null,
  "output_files": [
    "web-67a0d5f48a5b86d3567baec6.txt"
  ],
  "params": {
    "feed": "test",
    "send-nmap-report": 0
  },
  "result": {},
  "started_at": "2025-02-03 14:43:00.943141",
  "status": "started",
  "uri": "http://KINTUN_URL/api/scan/67a0d5f48a5b86d3567baec6",
  "vulnerability": "web"
}
```
This response contains the uri and UUID of the scan, that can be used to query it and check for the status.
When finished, it looks like this:

```json
{
  "_id": "67a0d5f48a5b86d3567baec6",
  "_network": "scanme.org",
  "_origin": "127.0.0.1",
  "_outputs": [],
  "_ports": [
    "80,443"
  ],
  "_protocols": [
    "tcp"
  ],
  "errors": [],
  "finished_at": "2025-02-03 14:43:01.633616",
  "is_vuln": true,
  "output_files": [
    "web-67a0d5f48a5b86d3567baec6.txt"
  ],
  "params": {
    "feed": "test",
    "send-nmap-report": 0
  },
  "result": {
    "no_vulnerables": [
      {
        "address": "45.33.32.156",
        "evidence": "Servicio: https en estado: closed",
        "port": "443",
        "protocol": "tcp"
      }
    ],
    "vulnerables": [
      {
        "address": "45.33.32.156",
        "evidence": "Servicio: http en estado: open",
        "port": "80",
        "protocol": "tcp"
      }
    ]
  },
  "started_at": "2025-02-03 14:43:00.943141",
  "status": "finished",
  "uri": "http://KINTUN_URL/api/scan/67a0d5f48a5b86d3567baec6",
  "vulnerability": "web"
}
```
The `result` key contains two lists: `no_vulnerables` and `vulnerables`. These lists show which addresses (IP or domain) with the scanned ports and protocols are open.

The `is_vuln` key is a boolean indicating if any vulnerabilities were found. If the `vulnerables` list is not empty, `is_vuln` will be `true`, meaning at least one port or service on the IP address has a vulnerability.

#### Form UI
In **http://KINTUN_URL/form** there is a form to submit a scan request. It includes the following fields:

- **Target (IP or Domain):** A text input for the target IP address or domain name.
- **Vulnerability Type:** A dropdown to select the type of vulnerability to scan for.
- **Protocol:** A dropdown to select the protocol (TCP or UDP).
- **Ports:** A text input for specifying ports as comma-separated values.

The form also includes validation for the target and ports fields. If the input is invalid, an error message will be displayed.

When the form is submitted, a POST request is sent to the `/api/scan` endpoint with the following data:

- `vuln`: The selected vulnerability type.
- `network`: The target IP or domain.
- `protocol`: The selected protocol.
- `ports`: The specified ports as an array.

If the scan is submitted successfully, a link to the scan report will be displayed.

### Authentication Methods

Kintun supports two methods of authentication: API Key and Basic Authentication.

#### API Key Authentication

To use API Key authentication, include the API key in the request headers. The API key should be set in the `.env` file as `KINTUN_API_KEY`.

**Example Request:**
```bash
curl -H "x-api-key: your_api_key" http://kintun_url/api/scan/xxx
```

#### Basic Authentication

To use Basic Authentication, include the username and password in the request headers. User credentials should be set in the .env file in the format `KINTUN_USER_<number>=username:password`

**Example Request:**
```bash
curl -u username:password http://kintun_url/api/scan/xxx
```

#### Environment Variables

```
MXTOOLBOX_API_KEY=your_api_key
KINTUN_API_KEY=your_api_key
KINTUN_USER_1=username:password
# Add more users as needed
```

Note: When accessing the API via a browser, you will be prompted to enter the username and password for Basic Authentication.

License
-------

This application is under the GPL v3.0 license. See the complete license in the application:
[LICENSE](https://github.com/CERTUNLP/Kintun/blob/master/LICENSE)
