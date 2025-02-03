#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan
import pprint

# NO ESTA DISPONIBLE!
class NetbiosSMB(Scan):
    name = "netbiossmb"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

# nmap -sU -p 53 --script=dns-recursion <target>
    def getCommand(self):
        command = []
        command += ["smbclient"]
        command += ["-N"]
        command += ["-L"]
        command += [self.network]
        return command

    #def addCommandPorts(self, command, ports):
    #    return command + ["-p "+','.join(ports)]

    def prepareOutput(self, data):
        print(data)

    def loadOutput(self, output):
        print(output)

    def getPortType(self):
        return "udp"

    #def getDefaultPorts(self):
    #    return ["137"]

    def getTypeNGEN(self):
        return "open_netbios"

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

    def isVulnerable(self, service, host):
    #    r = host.get('hostscript', 'Not vulnerable')
    #    if type(r) == type({}):
    #        return True
        return False

    def getParsedEvidence(self, service, host):
        return {'timestamp':str(self._id.generation_time),'service':service,'evidence':host.get('hostscript', 'Evidence error').get('script', 'Evidence error').get('output','Evidence Error').replace('\n', '')}
