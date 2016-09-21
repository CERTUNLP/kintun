#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan

class OpenPortmap(Scan):
    name = "openportmap"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

    def getNGENName(self):
        return "Open Portmap"

# nmap -sV --version-light --script ssl-poodle -p 443 <host>
    def getCommand(self):
        command = []
        command += ["nmap"]
        #command += ["-T2"]
        command += ["-sV"]
        command = self.addCommandPorts(command,self.ports)
        #no funciona con script del sistema, solo con path parcial
        command += ["--script="+self.getNseFolder()+"rpcinfo.nse"]
        command += [self.network]
        command += ["-oA="+self.getOutputNmapAllFilePathName()]
        return command

    def addCommandPorts(self, command, ports):
        return command + ["-p "+','.join(ports)]

    def prepareOutput(self, data):
        return self.parseAsNmapScript(data)

    def getParsedEvidence(self, port, host):
        result = port.get('script', '')
        if not result:
            raise Exception ("Cannot parse evidence as openportmap")
        return result

    def getDefaultPorts(self):
        return ["111"]

    def getPortType(self):
        return "udp"

    def getTypeNGEN(self):
        return "open_portmap"
