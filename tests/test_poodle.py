import requests

url = 'http://localhost:5000/api'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
    'x-api-key': 'api-key'
}

data = {
    "vuln" : "ssl-poodle",
    "network" : '',
    "ports" : ['443'],
    "params" : {"feed":"test", "send-nmap-report":0},
	"protocol" : ["tcp"],
    "outputs" : [],
    "report_to" : ""
}
r = requests.post(url+'/scan', headers=headers, json=data)

print(r.status_code)
print(r.text)

