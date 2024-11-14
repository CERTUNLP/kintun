import requests

url = 'http://localhost:5000/api'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
    'x-api-key': '5aa3d3b427ce47ca7affff903e92674f'
}

data = {
    "vuln" : "mqtt",
    "network" : '163.10.3.72',
    "ports" : ['1883'],
    "params" : {"feed":"test", "send-nmap-report":0},
	"protocol" : ["tcp"],
    "outputs" : [],
    "report_to" : ""
}
r = requests.post(url+'/scan', headers=headers, json=data)

print(r.status_code)
print(r.text)