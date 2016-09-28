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

class Heartbleed(Scan):
    name = "heartbleed"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

# nmap -p 443 --script ssl-heartbleed <target>
    def getCommand(self):
        command = []
        command += ["nmap"]
        command = self.addCommandPorts(command,self.ports)
        command += ["--script="+self.getNseFolder()+"ssl-heartbleed.nse"]
        command += [self.network]
        command += ["-oA="+self.getOutputNmapAllFilePathName()]
        return command

    def isVulnerable(self, port, host):
        r = port.get('script', 'Not vulnerable')
        if type(r) == type({}):
            return True
        return False

    def addCommandPorts(self, command, ports):
        return command + ["-p "+','.join(ports)]

    def prepareOutput(self, data):
        return self.parseAsNmapScript(data)

    def getDefaultPorts(self):
        return ["443","465","993"]

    def getPortType(self):
        return "tcp"

    def getTypeNGEN(self):
        return "heartbleed"

    def getParsedEvidence(self, service, host):
        return service

# AGREGADOS:
#                Keyword         Decimal         Description
#        -------         -------         -----------
#        nsiiops         261/tcp         IIOP Name Service over TLS/SSL
#        https           443/tcp         http protocol over TLS/SSL
#        ddm-ssl         448/tcp         DDM-SSL
#        smtps           465/tcp         smtp protocol over TLS/SSL
#        nntps           563/tcp         nntp protocol over TLS/SSL
#        sshell          614/tcp         SSLshell
#        ldaps           636/tcp         ldap protocol over TLS/SSL
#        ftps-data       989/tcp         ftp protocol, data, over TLS/SSL
#        ftps            990/tcp         ftp, control, over TLS/SSL
#        telnets         992/tcp         telnet protocol over TLS/SSL
#        imaps           993/tcp         imap4 protocol over TLS/SSL
#        ircs            994/tcp         irc protocol over TLS/SSL
#        pop3s           995/tcp         pop3 protocol over TLS/SSL

# NO AGREGADOS:
        # Web
        # Webdisk=2078
        # cPanel
        # cPanel=2083, WHM=2087, Webmail=2096
        # Other
        # PleskControlPanel=8443
