import requests
from dotenv import load_dotenv
import os

url = 'http://localhost:5000/api'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
}

data = {
    "vuln" : "blocklist",
    "network" : '163.10.29.145',
    "ports" : [],
    "params" : {"feed":"test", "send-nmap-report":0},
	"protocol" : [],
    "outputs" : [],
    "report_to" : ""
}

r = requests.post(url+'/scan', headers=headers, json=data)

print(r.status_code)
print(r.text)
