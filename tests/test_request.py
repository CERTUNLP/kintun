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

# r = requests.get(url)

# data = {
#     "vuln" : "openportmap2",
#     # "vuln" : "netbios",
#     "network" : '',
#     "ports" : ['111'],
#     "params" : {"feed":"test", "send-nmap-report":0},
#     "outputs" : [],
#     "report_to" : ""
# }
# r = requests.post(url+'/scan', headers=headers, json=data)

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


# r = requests.get(url+"/print",  headers=headers, json=data)

print(r.status_code)
print(r.text)

