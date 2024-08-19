import requests

url = 'http://localhost:5000/api'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
}

data = {
    "vuln" : "general",
    "network" : '163.10.11.147',
    "ports" : ['22','90','3306'],
    "params" : {"feed":"test", "send-nmap-report":0},
	"protocol" : ["tcp","udp"],
    "outputs" : [],
    "report_to" : ""
}
r = requests.post(url+'/scan', headers=headers, json=data)

print(r.status_code)
print(r.text)

