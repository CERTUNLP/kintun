#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan

class DnsZoneTransfer(Scan):
    name = "dnszonetransfer"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

    # dig +short <zone> @IP axfr
    def getCommand(self):
        command = []
        command += ["dig"]
        command += ["zonetransfer.me"]
        command += ["@"+self.network]
        command += ["axfr"]
        return command

    def loadOutput(self, data):
        return data

    def parseAsDig(self, response):
        v = []
        notv = []

        if all(fail not in response for fail in ["Transfer failed", "connection refused","failed"]):
            resources = []

            lines = response.splitlines()

            for line in lines:
                if line and not line.startswith(";"):
                    parts = line.split()
                    resources.append(f"Domain name: {parts[0]} - Type: {parts[3]} - Data: {parts[4]}")

            if resources:
                v.append({"address": self.network, "evidence": f"El recurso {self.network} en la zona zonetransfer.me permite transferencia de zona", "resources": resources})
        else:
            notv.append({"address": self.network, "evidence": f"El recurso {self.network} en la zona zonetransfer.me no permite transferencia de zona"})
        return {"vulnerables": v, "no_vulnerables": notv}

    def prepareOutput(self, data):
        return self.parseAsDig(data)

    def getDefaultPorts(self):
        return ["53"]

    def getPortType(self):
        return "udp"

    def getTypeNGEN(self):
        return "open_dns"