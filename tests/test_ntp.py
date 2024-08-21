import requests

url = 'http://localhost:5000/api'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
}


data = {
    "vuln" : "ntp-version",
    "network" : '216.152.193.254',
	"protocol" : ['udp'],
    "ports" : ['123'],
    "params" : {"feed":"test", "send-nmap-report":0},
    "outputs" : [],
    "report_to" : ""
}

data2 = {
    "vuln" : "ntp-monlist",
    "network" : '216.152.193.254',
	"protocol" : ['udp'],
    "ports" : ['123'],
    "params" : {"feed":"test", "send-nmap-report":0},
    "outputs" : [],
    "report_to" : ""
}

r = requests.post(url+'/scan', headers=headers, json=data)

print(r.status_code)
print(r.text)

r = requests.post(url+'/scan', headers=headers, json=data2)

print(r.status_code)
print(r.text)