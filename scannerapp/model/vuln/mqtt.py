#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan
import re

class Mqtt(Scan):
    name = "mqtt"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

    # nmap -p <PORT> <target>
    def getCommand(self):
        command = []
        command += ["nmap"]
        command += self.addProtocol(self.protocols)
        command += ["-Pn"]
        command = self.addCommandPorts(command,self.ports)
        command += ["--script=mqtt-subscribe"]
        command += [self.network]
        command += ["-oN="+self.getOutputNmapTxtFilePathName()]
        return command

    def getIterableNmapScriptResultsTxt(self, script, host, service):
        script_results = []
        try:
            host_section_pattern = re.compile(
                r'Nmap scan report for .* \(' + re.escape(host) + r'\)\n(.*?)(?=Nmap scan report for |\Z)', 
                re.DOTALL
            )
            host_section = host_section_pattern.findall(script)
            if not host_section:
                return script_results
            
            host_section = host_section[0]
            
            portid = re.escape(service["portid"])
            protocol = re.escape(service["protocol"])
            
            port_section_pattern = re.compile(
                rf'({portid}/{protocol}\s+\w+\s+\w+\n(?:\|\_.*(?:\n|\Z))*)',
                re.MULTILINE
            )
            
            port_section_matches = port_section_pattern.findall(host_section)
            
            for port_section in port_section_matches:
                if "mqtt-subscribe" in port_section:
                    result_match = re.search(r'mqtt-subscribe:\s+(.+)', port_section)
                    if result_match:
                        result_state = result_match.group(1).strip()
                        script_results.append({
                            "script_name": "mqtt-subscribe",
                            "state": result_state
                        })

        except Exception as e:
            raise Exception("Cannot get script results. Maybe wrong parsed output: " + str(e))

        return script_results


    def addCommandPorts(self, command, ports):
        return command + ["-p "+','.join(ports)]

    def prepareOutput(self, data):
        return self.parseAsStandardOutput(data)

    def loadOutput(self, output):
        return self.loadOutputTxt(output)