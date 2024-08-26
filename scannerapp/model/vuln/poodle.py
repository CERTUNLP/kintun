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

class Poodle(Scan):
    name = "ssl-poodle"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

    def getNGENName(self):
        return "poodle"

# nmap -sV --version-light --script ssl-poodle -p 443 <host>
    def getCommand(self):
        command = []
        command += ["nmap"]
        command += ["-sV"]
        command += ["--version-light"]
        command = self.addCommandPorts(command,self.ports)
        #no funciona con script del sistema, solo con path parcial
        command += ["--script="+self.getNseFolder()+"ssl-poodle.nse"]
        command += [self.network]
        command += ["-oN="+self.getOutputNmapTxtFilePathName()]
        return command

    def addCommandPorts(self, command, ports):
        return command + ["-p "+','.join(ports)]

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

            port_section_pattern = re.compile(
                re.escape(service["portid"] + '/' + service["protocol"]) + r'.*?\n(\|\s+\S+.*?)\n\n', 
                re.DOTALL
            )
            port_section_matches = port_section_pattern.findall(host_section)
            
            for port_section in port_section_matches:
                if ("VULNERABLE" in port_section):
                    state_matches = re.search(r'State:\s*(.+)$', port_section, re.MULTILINE)
                    script_results.append({
                        "script_name": "ssl-poodle",
                        "state": state_matches.group(1).strip() 
                    })

        except Exception as e:
            raise Exception("Cannot get script results. Maybe wrong parsed output: " + str(e))

        return script_results

    def prepareOutput(self, data):
        return self.parseAsStandardOutput(data)

    def loadOutput(self, output):
        return self.loadOutputTxt(output)

    def getDefaultPorts(self):
        return ["443"]

    def getPortType(self):
        return "tcp"

    def getTypeNGEN(self):
        return "poodle"
