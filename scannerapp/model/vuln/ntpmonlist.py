#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan

class NtpMonlist(Scan):
	name = "ntp-monlist"

	def __init__(self, *initial_data, **kwargs):
		Scan.__init__(self, initial_data, kwargs)

	@classmethod
	def getName(cls):
		return cls.name

# nmap -sU -pU:123 -Pn -n --script=ntp-monlist <target>
	def getCommand(self):
		command = []
		command += ["nmap"]
		command += ["-sU"]
		command += ["-Pn"]
		command += ["-n"]
		command = self.addCommandPorts(command,self.ports)
		command += ["--script="+self.getNseFolder()+"ntp-monlist.nse"]
		command += [self.network]
		command += ["-oX="+self.getOutputXmlFilePath()]
		return command

	def addCommandPorts(self, command, ports):
		return command + ["-pU:"+','.join(ports)]

	def prepareOutput(self, data):
		return self.parseAsNmapScript(data)

	def getDefaultPorts(self):
		return ["123"]

	def getTypeNGEN(self):
		return "open_ntp_monitor"
