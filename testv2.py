import requests

url = 'http://localhost:5000/api'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
}

vulns = {
	"53"  : ["dns-recursion-external"], # no funca porque openresolver esta en cloudflare y no es piola con la automatizacion
	"111" : ["openportmap2"], 
	"137" : ["netbios"],
	"123" : ["ntp-monlist", "ntp-info-readvar"],
 	"161" : ["open-snmp-all"],
	"443" : ["heartbleed", "ssl-poodle"],
	"465" : ["heartbleed", "ssl-poodle"],
	"993" : ["heartbleed", "ssl-poodle"],
	"995" : ["ssl-poodle"],
}


data = {
    "vuln" : "general",
    "network" : '163.10.29.145',
    "ports" : ['5432','80'],
    "params" : {"feed":"test", "send-nmap-report":0},
    "outputs" : [],
    "report_to" : ""
}
r = requests.post(url+'/scanV2', headers=headers, json=data)

print(r.status_code)
print(r.text)

