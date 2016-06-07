#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan
import requests, datetime

class DnsRecursiveExternal(Scan):
	name = "dns-recursion-external"

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
		command += ["-Pn"]
		command = self.addCommandPorts(command,self.ports)
		command += ["--script="+self.getNseFolder()+"dns-recursion.nse"]
		command += [self.network]
		command += ["-oX="+self.getOutputFilePath()]
		return command

	def execute(self):
		try:
			net = self.network.split('/')[0]
			r = requests.get('http://openresolver.com/?ip={0}'.format(net))
			return r, b''
		except Exception as e:
			return None, bytes(str(datetime.datetime.now())+'Error in connection with OpenResolver openresolver.com'+str(sys.exc_info()[1]),'utf-8')

	def loadOutput(self, data):
		return data

	def parseAsRequests(self, request):
		v = []
		notv = []
		if request.status_code != 200:
			raise Exception('OpenResolver openresolver.com is not working correctly.')
		net = self.getAddress()
		if self.isVulnerable(request):
			v.append({"address":net,"ports":['53'],"evidence":'http://openresolver.com/?ip={0}'.format(net)})
		else:
			notv.append({"address":net,"ports":['53'],"evidence":'http://openresolver.com/?ip={0}'.format(net)})
		return {"vulnerables":v, "no_vulnerables":notv}

	def isVulnerable(self, request):
		return request.text.find('Open recursive resolver detected') >= 0

	def addCommandPorts(self, command, ports):
		return command + ["-p "+','.join(ports)]

	def prepareOutput(self, data):
		return self.parseAsRequests(data)

	def getDefaultPorts(self):
		return ["53"]

	def getTypeNGEN(self):
		return "open_dns"
