#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan
import codecs

class Ldap(Scan):
	name = "ldap"

	def __init__(self, *initial_data, **kwargs):
		Scan.__init__(self, initial_data, kwargs)

	@classmethod
	def getName(cls):
		return cls.name

# nmap -sU -p 123 --script ntp-info <target>
	def getCommand(self):
		command = []
		command += ["expect"]
		command += [self.getCustomFolder()+"ldaptest.exp"]
		command += [self.getLibFolder()+"shelldap"]
		command += [self.getAddress()]
		return command

	def loadOutput(self, data):
		return data

	def parseAsCustom(self, result):
		v = []
		notv = []
		if result.find('vulnerable') < 0:
			raise Exception ("Execution shelldap error. " + result)
		if self.isVulnerable(result):
			v.append({"address":self.getAddress(),"ports":['389','636'],"evidence":result})
		else:
			notv.append({"address":self.getAddress(),"ports":['389','636'],"evidence":result})
		return {"vulnerables":v, "no_vulnerables":notv}

	def isVulnerable(self, result):
		return result.find('Shelldap service is vulnerable') >= 0

	def addCommandPorts(self, command, ports):
		return command + ["-p "+','.join(ports)]

	def prepareOutput(self, data):
		x = codecs.decode(data)
		try:
			s = x.split('\n')
			print(s)
			s = s[-2:] + s
			print(s)
			s = s [:-3]
			s[2] = s[2].replace('spawn timeout 5 ./scannerapp/model/vuln/custom/lib/', '~ # ')
			x = '\n'.join(s)
		except Exception as e:
			print(str(e))
			print('cannot parse ldap correctly.')
			raise e
		return self.parseAsCustom(x)

	def getFormatedEvidence(self, data):
		return data.replace('\x1b[24m','').replace('\x1b[4m','')

	def getDefaultPorts(self):
		return ["123"]

	def getTypeNGEN(self):
		return "open_ldap"
