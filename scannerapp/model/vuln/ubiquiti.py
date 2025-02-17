import datetime
import re
from ..scan import Scan

class Ubiquiti(Scan):
    name = "ubiquiti"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

    def getCommand(self):
        command = []
        command += ["nmap"]
        command += ["-sU"]
        command += ["-Pn"]
        command += self.addCommandPorts(self.ports)
        command += ["--script=ubiquiti-discovery"]
        command += [self.network]
        print(f"Command: {command}")
        command += ["-oN=" + self.getOutputNmapTxtFilePathName()]
        return command

    def loadOutput(self, data):
        return data    

    def getIterablePossibleNmapPortsTxt(self, script, host):
        ports = []
        try:
            host_section_pattern = re.compile(r'Nmap scan report for (?:[a-zA-Z0-9.-]+ \(' + re.escape(host) + r'\)|' + re.escape(host) + r')\n(.*?)(?=\nNmap scan report for |\Z)', re.DOTALL)
            host_section = host_section_pattern.findall(script)
            if host_section:
                host_section = host_section[0]
                port_pattern = re.compile(
                    r'(\d+)/(tcp|udp)\s+(open|filtered|closed|open\|filtered)\s+(\S+)(?:\n\| ubiquiti-discovery:.*?protocol: (\S+).*?firmware: (\S+))?', re.DOTALL)
                ports = port_pattern.findall(host_section)
                print(f"Ports: {ports}")
                ports = [{"portid": port[0], "protocol": port[1], "state": port[2], "service": port[3], "info": f"protocol {port[4]} and firmware {port[5]}" if port[4] and port[5] else None} for port in ports]
        except Exception as e:
            print(e)
            pass
        
        if type(ports) != list:
            ports = [ports]
        return ports

    def parseAsUbiquiti(self, data):
        v = []
        notv = []
        hosts = self.getIterableNmapHostsTxt(data)
        for host in hosts:
            services = self.getIterablePossibleNmapPortsTxt(data, host)
            for s in services:
                if s["state"] == "open" and s["info"]:
                    try:
                        evidence = f"Servicio: {s['service']} en estado: {s['state']} - Ubiquiti info: {s['info']}"
                        v.append({"address": host, "port": s["portid"], "protocol": s["protocol"], "evidence": evidence})
                    except Exception as e:
                        self.errors.append(
                            str(datetime.datetime.now())
                            + " - Cant get evidence:  "
                            + str(e)
                        )
                else:
                    evidence = f"Servicio: {s['service']} en estado: {s['state']}"
                    if not s["info"]:
                        evidence += " - No ubiquiti info"
                    notv.append({"address": host, "port": s["portid"], "protocol": s["protocol"], "evidence": evidence})
        return {"vulnerables": v, "no_vulnerables": notv}

    def prepareOutput(self, data):
        return self.parseAsUbiquiti(data)

    def addCommandPorts(self, ports):
        return ["-p " + ",".join(ports)]

    def getDefaultPorts(self):
        return ["10001"]

    def getPortType(self):
        return "udp"

    def getTypeNGEN(self):
        return "ubiquiti"