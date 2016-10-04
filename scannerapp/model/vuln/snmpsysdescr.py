#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan
import requests
import json
## This script uses dns-zone-transfer from nmap shared scripts folder

class OpenSNMPSysdescr(Scan):
    name = "open-snmp-sysdescr"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

# nmap -sU -p 53 --script=dns-recursion <target>
    def getCommand(self):
        command = []
        command += ["nmap"]
        command += ["-sU"]
        command += ["-Pn"]
        command = self.addCommandPorts(command,self.ports)
        command += ["-n"]
        command += [self.network]
        command += ["--script=snmp-sysdescr.nse"]
        command += ["-oA="+self.getOutputNmapAllFilePathName()]
        return command

    def addCommandPorts(self, command, ports):
        return command + ["-pU:"+','.join(ports)]

    def isVulnerable(self, service, host):
        #print(service)
        r = service.get('script', 'Not vulnerable')
        if type(r) == type({}):
            script = r.get('output', 'ERROR')
            if script[0:5] == 'ERROR':
                raise Exception ("SNMP Nmap script error.")
            self.onDetect(service,host)
            return True
        return False

    def onDetect(self, service, host):
        if self.getParamValueFor('send-full-report'):
            self.sendFullReport(service,host)

    def sendFullReport(self, service, host):
        p = self.params.copy()
        del p['send-full-report']
        headers = {'Accept' : '*/*', 'Expect': '100-continue', 'content-type': 'application/json'}
        data = {"vuln":"open-snmp-all",
            "network": host['address']['addr']+"/32",
            "ports": self.ports,
            "params": p,
            "outputs": self.outputs,
            "report_to":self.report_to
            }
        #print(data)
        response = requests.post("https://localhost:5000/api/scan", data=json.dumps(data), headers=headers, verify=False)
        #print(str(response),str(response.text))

    def prepareOutput(self, data):
        return self.parseAsNmapScript(data)

    def getDefaultPorts(self):
        return ["161"]

    def getPortType(self):
        return "udp"

    def getTypeNGEN(self):
        return "open_snmp"

    def getParsedEvidence(self, service, host):
        return service
