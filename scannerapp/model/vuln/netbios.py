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

class Netbios(Scan):
	name = "netbios"

	def __init__(self, *initial_data, **kwargs):
		Scan.__init__(self, initial_data, kwargs)

	@classmethod
	def getName(cls):
		return cls.name

# nmap -sU -p 53 --script=dns-recursion <target>
	def getCommand(self):
		command = []
		command += ["nmap"]
		command += ["-sU"]
		command += ["-v"]
		command = self.addCommandPorts(command,self.ports)
		command += ["--script="+self.getNseFolder()+"nbstat.nse"]
		command += [self.network]
		command += ["-oA="+self.getOutputFilePath()]
		return command

	def addCommandPorts(self, command, ports):
		return command + ["-p "+','.join(ports)]

	def prepareOutput(self, data):
		return self.parseAsNmapScript(data)

	def getDefaultPorts(self):
		return ["137"]

	def getTypeNGEN(self):
		return "open_netbios"

#	def getIterablePossibleNmapPorts(self, host):
#		ports = []
#		try:
#			ports = host['hostscript']['script']
#		except:
#			pass
#			raise Exception ("Cannot get info about scan hostscript. Maybe wrong parsed output")
#		if type(ports) != type([]):
#			ports = [ports]
#		return ports

	def isVulnerable(self, service, host):
		r = host.get('hostscript', 'Not vulnerable')
		if type(r) == type({}):
			return True
		return False

	def getParsedEvidence(self, service, host):
		return {'timestamp':str(self._id.generation_time),'service':service,'evidence':host.get('hostscript', 'Evidence error').get('script', 'Evidence error').get('output','Evidence Error').replace('\n', '')}
