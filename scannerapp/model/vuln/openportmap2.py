#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan

class OpenPortmap2(Scan):
    name = "openportmap2"

    def __init__(self, *initial_data, **kwargs):
        Scan.__init__(self, initial_data, kwargs)

    @classmethod
    def getName(cls):
        return cls.name

    def getNGENName(self):
        return "rcpinfo"

# rpcinfo -T udp -p localhost
    def getCommand(self):
        command = []
        command += ["rpcinfo"]
        command += ["-T"]
        command += ["udp"]
        command += [self.getAddress()]
        return command

    def loadOutput(self, data):
        return data

    def parseAsCustom(self, result):
        v = []
        notv = []
        if self.isVulnerable(result):
            v.append({"address":self.getAddress(),"ports":self.getDefaultPorts(),"evidence":' '.join(self.getCommand())+'\n'+result})
        else:
            notv.append({"address":self.getAddress(),"ports":self.getDefaultPorts(),"evidence":' '.join(self.getCommand())+'\n'+result})
        return {"vulnerables":v, "no_vulnerables":notv}

    def isNmapScan():
        return False

    def isVulnerable(self, result):
        return result.find('   program version netid     address                service    owner') >= 0

    def getFormatedEvidence(self, data):
        return data

    def addCommandPorts(self, command, ports):
        return command + ["-p "+','.join(ports)]

    def prepareOutput(self, data):
        return self.parseAsCustom(data)

    def addCommandPorts(self, command, ports):
        return command + ["-p "+','.join(ports)]

    def getDefaultPorts(self):
        return ["111"]

    def getTypeNGEN(self):
        return "open_portmap"
