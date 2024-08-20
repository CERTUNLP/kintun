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

    # dig +short test.openresolver.com TXT @1.2.3.4
    def getCommand(self):
        command = []
        command += ["dig"]
        command += ["+short"]
        command += ["test.openresolver.com"]
        command += ["TXT"]
        command += ["@"+self.network]
        return command

    def loadOutput(self, data):
        return data

    def parseAsDig(self, response):
        v = []
        notv = []
        if ("open-resolver-detected" in response):
            v.append({"address": self.network, "evidence": f"La ip {self.network} es un servidor DNS recursivo abierto"})
        else:
            notv.append({"address": self.network, "evidence": f"La ip {self.network} NO es un servidor DNS recursivo abierto"})
        return {"vulnerables": v, "no_vulnerables": notv}

    def prepareOutput(self, data):
        return self.parseAsDig(data)

    def getDefaultPorts(self):
        return ["53"]

    def getPortType(self):
        return "udp"

    def getTypeNGEN(self):
        return "open_dns"
