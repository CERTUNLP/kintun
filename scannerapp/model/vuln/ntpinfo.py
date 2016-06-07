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

	def __init__(self, *initial_data, **kwargs):
		Scan.__init__(self, initial_data, kwargs)

	@classmethod
	def getName(cls):
		return cls.name

# nmap -sU -p 123 --script ntp-info <target>
	def getCommand(self):
		command = []
		command += ["nmap"]
		command += ["-Pn"]
		command = self.addCommandPorts(command,self.ports)
		#no funciona con script del sistema, solo con path parcial
		command += ["--script="+self.getNseFolder()+"ntp-info.nse"]
		command += [self.network]
		command += ["-oX="+self.getOutputXmlFilePath()]
		return command

	def addCommandPorts(self, command, ports):
		return command + ["-p "+','.join(ports)]

	def prepareOutput(self, data):
		return self.parseAsNmapScript(data)

	def getDefaultPorts(self):
		return ["123"]

	def getTypeNGEN(self):
		return "open_ntp_version"
