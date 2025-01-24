#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan

class SmtpOpenRelay(Scan):
    name = "smtpopenrelay"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

# nmap --script smtp-open-relay.nse [--script-args smtp-open-relay.domain=<domain>,smtp-open-relay.ip=<address>,...] -p 25,465,587 <host>
    def getCommand(self):
        command = []
        command += ["nmap"]
        command += ["-Pn"]
        command = self.addCommandPorts(command,self.ports)
        #no funciona con script del sistema, solo con path parcial
        command += ["--script=smtp-open-relay.nse"]
        command += [self.network]
        command += ["-oA="+self.getOutputNmapAllFilePathName()]
        return command

    def addCommandPorts(self, command, ports):
        return command + ["-p "+','.join(ports)]

    def prepareOutput(self, data):
        return self.parseAsNmapScript(data)

    def isVulnerable(self, service, host):
        #print(service)
        r = service.get('script', 'ERROR')
        if type(r) == type({}):
            #print(r)
            x = r.get('output', 'ERROR')
            if x.find('Server is an open relay') >= 0:
                return True
        return False

    def getDefaultPorts(self):
        return ["25","465","587"]

    def getPortType(self):
        return "tcp"

    def getTypeNGEN(self):
        return ""
