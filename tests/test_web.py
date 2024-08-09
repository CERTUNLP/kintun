import requests

url = 'http://localhost:5000/api'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
}

data = { #No se mandaria protocol pq por web es tcp
    "vuln" : "web",
    "network" : '163.10.29.168',
    "ports" : [],
    "params" : {"feed":"test", "send-nmap-report":0},
    "outputs" : [],
    "report_to" : ""
}
r = requests.post(url+'/scan', headers=headers, json=data)

print(r.status_code)
print(r.text)

