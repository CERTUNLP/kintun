#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan

class General(Scan):
    name = "general"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

# nmap -p <PORT> <target>
    def getCommand(self):
        command = []
        command += ["nmap"]
        command += ["-sU"]
        command += ["-Pn"]
        command = self.addCommandPorts(command,self.ports)
        command += [self.network]
        command += ["-oN="+self.getOutputNmapTxtFilePathName()]
        return command

    def addCommandPorts(self, command, ports):
        return command + ["-p "+','.join(ports)]

    def prepareOutput(self, data):
        return self.parseAsStandardOutput(data)