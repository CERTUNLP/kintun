import requests
from dotenv import load_dotenv
import os

load_dotenv()

api_key = os.getenv("MXTOOLBOX_API_KEY")

url = "https://api.mxtoolbox.com/api/v1/Lookup/blacklist/?argument=163.10.28.130"
headers = {
    'Authorization': api_key
}

# data = {
#     "vuln" : "general",
#     "network" : '163.10.29.168',
#     "ports" : ['80','90','3306'],
#     "params" : {"feed":"test", "send-nmap-report":0},
# 	"protocol" : ["tcp","udp"],
#     "outputs" : [],
#     "report_to" : ""
# }
r = requests.get(url, headers=headers)

if (r.json().get('Failed')):
    print("Ip is blacklisted")
else:
    print("Ip is not blacklisted")
