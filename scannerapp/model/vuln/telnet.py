#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

import datetime
import re
from ..scan import Scan
## This script uses dns-zone-transfer from nmap shared scripts folder

class Telnet(Scan):
    name = "telnet"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

    # nc -zv -w 5 IP PORT
    def getCommand(self):
        command = []
        command += ["nmap"]
        command += ["-sS"]
        command += ["-Pn"]
        command = self.addCommandPorts(command,self.ports)
        command += ["--script=banner"]
        command += [self.network]
        command += ["-oN="+self.getOutputNmapTxtFilePathName()]
        return command

    def loadOutput(self, data):
        return data    

    def getIterablePossibleNmapPortsTxt(self, script, host):
        ports = []
        try:
            host_section_pattern = re.compile(r'Nmap scan report for (?:[a-zA-Z0-9.-]+ \(' + re.escape(host) + r'\)|' + re.escape(host) + r')\n(.*?)(?=\nNmap scan report for |\Z)', re.DOTALL)
            host_section = host_section_pattern.findall(script)
            if host_section:
                host_section = host_section[0]
                port_pattern = re.compile(
                    r'(\d+)/(tcp|udp)\s+(open|filtered|closed|open\|filtered)\s+(\S+)(?:\n\|_banner: (.*))?')
                ports = port_pattern.findall(host_section)
                ports = [{"portid": port[0], "protocol": port[1], "state": port[2], "service": port[3], "banner": port[4] if len(port) > 4 else None} for port in ports]
        except Exception as e:
            print(e)
            pass
        
        if type(ports) != list:
            ports = [ports]
        return ports


    def parseAsTelnet(self, data):
        v = []
        notv = []
        hosts = self.getIterableNmapHostsTxt(data)
        for host in hosts:
            services = self.getIterablePossibleNmapPortsTxt(data, host)
            for s in services:
                if s["state"] == "open" and s["banner"]:
                    try:
                        evidence = f"Servicio: {s['service']} en estado: {s['state']} - Banner: {s['banner']}"
                        v.append({"address": host, "port": s["portid"], "protocol": s["protocol"], "evidence": evidence})
                    except Exception as e:
                        self.errors.append(
                            str(datetime.datetime.now())
                            + " - Cant get evidence:  "
                            + str(e)
                        )
                else:
                    evidence = f"Servicio: {s['service']} en estado: {s['state']}"
                    if not s["banner"]:
                        evidence += " - No banner"
                    notv.append({"address": host, "port": s["portid"], "protocol": s["protocol"], "evidence": evidence})
        return {"vulnerables": v, "no_vulnerables": notv}

    def prepareOutput(self, data):
        return self.parseAsTelnet(data)

    def addCommandPorts(self, command, ports):
        return command + ["-p " + ",".join(ports)]

    def getDefaultPorts(self):
        return ["23"]

    def getPortType(self):
        return "tcp"

    def getTypeNGEN(self):
        return "telnet"