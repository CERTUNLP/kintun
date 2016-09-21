#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan
## This script uses dns-zone-transfer from nmap shared scripts folder

class DnsZoneTransfer(Scan):
    name = "dns-zone-transfer"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

# nmap -sU -p 53 --script=dns-recursion <target>
    def getCommand(self):
        command = []
        command += ["nmap"]
        command = self.addCommandPorts(command,self.ports)
        command += ["--script=dns-zone-transfer.nse"]
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

#    def getIterablePossibleNmapPorts(self, host):
#        ports = []
#        try:
#            ports = host['hostscript']['script']
#        except:
#            pass
#            raise Exception ("Cannot get info about scan hostscript. Maybe wrong parsed output")
#        if type(ports) != type([]):
#            ports = [ports]
#        return ports

    def getParsedEvidence(self, service, host):
        return {'timestamp':str(self._id.generation_time),'service':service,'evidence':host.get('ports', 'Evidence error').get('port', 'Evidence error').get('script','Evidence Error').get('output','Evidence Error').replace('\n', '')}
