import requests

url = 'http://localhost:5000/api'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
    'x-api-key': 'your_api_key'
}


data = {
    "vuln" : "ntpversion",
    "network" : '',
	"protocol" : ['udp'],
    "ports" : ['123'],
    "params" : {"feed":"test", "send-nmap-report":0},
    "outputs" : [],
    "report_to" : ""
}

data2 = {
    "vuln" : "ntpmonlist",
    "network" : '',
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