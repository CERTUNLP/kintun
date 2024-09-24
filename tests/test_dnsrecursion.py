import requests

url = 'http://localhost:5000/api'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
}


data = {
    "vuln" : "dns-recursion",
    "network" : '',
	"protocol" : ["udp"],
    "ports" : ['53'],
    "params" : {"feed":"test", "send-nmap-report":0},
    "outputs" : [],
    "report_to" : ""
}
r = requests.post(url+'/scan', headers=headers, json=data)

print(r.status_code)
print(r.text)
