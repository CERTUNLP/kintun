#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan

class NtpInfo(Scan):
    name = "ntp-info-readvar"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

# nmap -sU -p 123 --script ntp-info <target>
    def getCommand(self):
        command = []
        command += ["nmap"]
        command += ["-sU"]
        command = self.addCommandPorts(command,self.ports)
        #no funciona con script del sistema, solo con path parcial
        command += ["--script=ntp-info"]
        command += [self.network]
        command += ["-oA="+self.getOutputNmapAllFilePathName()]
        return command

    def addCommandPorts(self, command, ports):
        return command + ["-p "+','.join(ports)]

    def isVulnerable(self, port, host):
        r = False
        try:
            script = port.get('script', 'Not vulnerable')
            if type(script['elem']) == type([]):
                # More than 1 element, otherwise be a {}
                r = True
        except:
            r = False
        return r

    def getParsedEvidence(self, port, host):
        result = port.get('script', '')
        if not result:
            raise Exception ("Cannot parse evidence as ntpinforeadvar")
        return result

    def prepareOutput(self, data):
        return self.parseAsNmapScript(data)

    def getDefaultPorts(self):
        return ["123"]

    def getPortType(self):
        return "udp"

    def getTypeNGEN(self):
        return "open_ntp_version"
