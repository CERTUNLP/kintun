#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan
import json

class OpenSNMP(Scan):
    name = "open-snmp-all"

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
        command += ["-A"]
        command += ["--host-timeout=60s"]
        command += ["--min-hostgroup=32"]
        command += [self.network]
        command += ["-oA="+self.getOutputNmapAllFilePathName()]
        return command

    def addCommandPorts(self, command, ports):
        return command + ["-pU:"+','.join(ports)]

    def isVulnerable(self, service, host):
        #print(service)
        r = service.get('script', 'Not vulnerable')
        if type(r) == type({}):
            try:
                if not r["id"] in ["snmp-hh3c-logins", "snmp-info"]:
                    return True
            except KeyError:
                pass
        elif type(r) == type([]):
            for d in r:
                try:
                    if not d["id"] in ["snmp-hh3c-logins", "snmp-info"]:
                        return True
                except KeyError:
                    pass
        return False

    def prepareOutput(self, data):
        return self.parseAsNmapScript(data)

    def getDefaultPorts(self):
        return ["161"]

    def getTypeNGEN(self):
        return "open_snmp"

    def getParsedEvidence(self, service, host):
        return {'timestamp':str(self._id.generation_time),'evidence':json.loads(json.dumps(service).replace('\n',''))}

    def getPortType(self):
        return "udp"

    def isEnabledExternal(self):
        return True
