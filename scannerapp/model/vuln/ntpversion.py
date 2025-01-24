#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan
import re

class NtpVersion(Scan):
    name = "ntpversion"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

    # ntpq -c readvar IP
    def getCommand(self):
        command = []
        command += ["ntpq"]
        command += ["-c"]
        command += ["readvar"]
        command += [self.network]
        return command

    def loadOutput(self, data):
        return data

    def parseAsDig(self, response):
        v = []
        notv = []
        pattern = r'version="([^"]+)"'
        match = re.search(pattern, response)
        if (match):
            version = match.group(1)
            v.append({"address": self.network, "evidence": f"La ip {self.network} expone la version {version} de NTP"})
        else:
            notv.append({"address": self.network, "evidence": f"La ip {self.network} no expone la version de NTP"})
        return {"vulnerables": v, "no_vulnerables": notv}

    def prepareOutput(self, data):
        return self.parseAsDig(data)

    def getDefaultPorts(self):
        return ["123"]

    def getPortType(self):
        return "udp"

    def getTypeNGEN(self):
        return "ntp_version"
