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

##### Python Dependencies:
```bash
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
To make it easier to start Kintun, use the provided start_kintun.sh script. This script checks for Docker, installs requirements if necessary, and prompts you to choose between running Kintun with Docker or locally.
To run Kintun:
```bash
$ ./start_kintun.sh
```

This script will guide you through the setup process and start the Kintun app accordingly, either with Docker or directly on your local machine.


License
-------

This application is under the GPL v3.0 license. See the complete license in the application:
[LICENSE](https://github.com/CERTUNLP/Kintun/blob/master/LICENSE)