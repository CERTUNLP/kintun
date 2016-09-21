#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan

class SocksOpenProxy(Scan):
    name = "socks-open-proxy"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

# nmap --script=socks-open-proxy \
#      --script-args proxy.url=<host>,proxy.pattern=<pattern>
    def getCommand(self):
        command = []
        command += ["nmap"]
        command += ["-Pn"]
        #command = self.addCommandPorts(command,self.ports)
        #no funciona con script del sistema, solo con path parcial
        command += ["--script="+self.getNseFolder()+"socks-open-proxy.nse"]
        command += [self.network]
        command += ["-oA="+self.getOutputNmapAllFilePathName()]
        return command

    #def addCommandPorts(self, command, ports):
    #    return command + ["-p "+','.join(ports)]

    def prepareOutput(self, data):
        return self.parseAsNmapScript(data)

    def getTypeNGEN(self):
        return ""

    def getPortType(self):
        return "udp"

    #def getDefaultPorts(self):
    #    return ["123"]
