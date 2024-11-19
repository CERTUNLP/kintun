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

class Openredis(Scan):
    name = "openredis"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

    # timeout 4 redis-cli -h IP -p PORT PING
    def getCommand(self):
        command = []
        command += ["timeout"]
        command += ["4"]
        command += ["redis-cli"]
        command += ["-h"]
        command += [self.network]
        command += ["-p"]
        command += [self.ports[0]]
        command += ["PING"]
        return command

    def loadOutput(self, data):
        return data

    def parseAsRedis(self, response):
        v = []
        notv = []
        if "PONG" in response:
            v.append({"address": self.network, "evidence": f"La ip {self.network} tiene un servidor Redis accesible en el puerto {self.ports[0]}"})
        else:
            notv.append({"address": self.network, "evidence": f"La ip {self.network} NO tiene un servidor Redis accesible en el puerto {self.ports[0]}"})
        return {"vulnerables": v, "no_vulnerables": notv}

    def prepareOutput(self, data):
        return self.parseAsRedis(data)

    def getDefaultPorts(self):
        return ["6379"]

    def getPortType(self):
        return "tcp"
