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

class Mongo(Scan):
    name = "mongo"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

    # mongosh --verbose IP
    def getCommand(self):
        command = []
        command += ["mongosh"]
        command += ["--verbose"]
        command += [self.network]
        return command

    def loadOutput(self, data):
        return data

    def parseAsMongosh(self, response):
        v = []
        notv = []
        match = re.search(r'Using MongoDB:\s+(\d+\.\d+(?:\.\d+)?)', response)
        if (match):
            v.append({"address": self.network, "evidence": f"La ip {self.network} tiene un servidor MongoDB accesible en la versión {match.group(1)}"})
        else:
            notv.append({"address": self.network, "evidence": f"La ip {self.network} NO tiene un servidor MongoDB accesible"})
        return {"vulnerables": v, "no_vulnerables": notv}

    def prepareOutput(self, data):
        return self.parseAsMongosh(data)

    def getDefaultPorts(self):
        return ["27017"]

    def getPortType(self):
        return "tcp"
