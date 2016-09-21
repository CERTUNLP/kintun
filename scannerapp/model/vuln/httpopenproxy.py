#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan

class HttpOpenProxy(Scan):
    name = "http-open-proxy"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

# nmap --script http-open-proxy.nse \
#      --script-args proxy.url=<url>,proxy.pattern=<pattern>
    def getCommand(self):
        command = []
        command += ["nmap"]
        command += ["-Pn"]
        command = self.addCommandPorts(command,self.ports)
        #no funciona con script del sistema, solo con path parcial
        command += ["--script="+self.getNseFolder()+"http-open-proxy.nse"]
        command += [self.network]
        command += ["-oA="+self.getOutputNmapAllFilePathName()]
        return command

    def addCommandPorts(self, command, ports):
        return command + ["-p "+','.join(ports)]

    def prepareOutput(self, data):
        return self.parseAsNmapScript(data)

    def getDefaultPorts(self):
        return ["80","3128","8000","8010","8080","8081","8123","8888"]

    def getPortType(self):
        return "tcp"

    def getTypeNGEN(self):
        return ""

    def parseAsNmapScript(self,data):
        v = []
        notv = []
        if type(data) == type({}):
            try:
                hosts = data['nmaprun']['host']
            except:
                raise Exception ("Cannot get info about scan hosts. Maybe wrong parsed output")
            if type(hosts) == type({}):
                hosts = [hosts]
            for host in hosts:
                try:
                    services = host['ports']['port']
                except:
                    raise Exception ("Cannot get info about scan ports. Maybe wrong parsed output")
                pvulnerables = []
                pnot_vulnerables = []
                if type(services) != type([]):
                    services = [services]
                for service in services:
                    r = service.get('script', 'Not vulnerable')
                    if type(r) == type({}):
                        r = r.get('output','no output')
                        #v.append(host['address']['addr'])
                        pvulnerables.append({"port":service['portid'],"info":r})
                    else:
                        ###notv.append(host['address']['addr'])
                        #pnot_vulnerables.append(service['portid'])
                        pass
                if pvulnerables != []:
                    v.append({"address":host['address']['addr'],"ports":pvulnerables})
                #.append({"address":host['address']['addr'],"ports":pnot_vulnerables})
        return {"vulnerables":v, "no_vulnerables":notv}
