#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan

class DnsRecursive(Scan):
    name = "dns-recursion"

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
        command += ["--script="+self.getNseFolder()+"dns-recursion.nse"]
        command += [self.network]
        command += ["-oA="+self.getOutputNmapAllFilePathName()]
        return command

    def addCommandPorts(self, command, ports):
        return command + ["-p "+','.join(ports)]

    def prepareOutput(self, data):
        return self.parseAsNmapScript(data)

    def getDefaultPorts(self):
        return ["53"]

    def getPortType(self):
        return "udp"

    def getTypeNGEN(self):
        return "open_dns"
