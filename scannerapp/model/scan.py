#!flask/bin/python
#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

#from core.logger import logger
import threading
import time
import datetime
import subprocess as sub
import string
import random
from .xml2JsonParser import Xml2JsonParser
from flask import jsonify
from bson.objectid import ObjectId
from pymongo import MongoClient
import requests

import json
import pprint

import sys
import traceback

import xmlrpc.client
import socket

from config import conf, dbconf, scanconf, endpointsconf, logger, db

class Scan:
    name = "AbstractScan"
    # TODO: Serializar al instanciar objetos y que sean grabados.
    def __setDefaults(self):
        self._id = None
        self._network = None
        self._ports = []
        self._outputs = []
        self.params = {}
        self.report_to = ""
        self.origin = ""
        self.status = "created"
        self.started_at = ""
        self.finished_at = ""
        self.result = {}
        self.errors = []
        self.output_files = []
        self.vulnerability = self.__class__.name

    def __init__(self, kwargs, kwargs2):
        self.__setDefaults()
        for k in kwargs:
            setattr(self, k, kwargs[k])
        for k in kwargs2:
            setattr(self, k, kwargs2[k])
        self.save()

    @staticmethod
    def get_scans():
        scans = {}
        for c in Scan.__subclasses__():
            scans[c.getName()] = c
        return scans

    def parseXmlToJson(self, xml_file, json_file):
        p = Xml2JsonParser(xml_file,json_file)
        p.parse()

    def loadXmlAsJson(self, xml_file):
        data = ""
        self.parseXmlToJson(xml_file, self.getOutputJsonFilePath())
        with open(self.getOutputJsonFilePath()) as f:
            data = f.read()
        return json.loads(data)

    def getAddress(self):
        return self.network.split('/')[0]

    def start(self):
        thr = threading.Thread(target=self.__run, args=(), kwargs={})
        logger.info("Procesos activos: "+str(threading.active_count()))
        thr.start() # will run "__run"
        self.status = "started"
        self.started_at = str(datetime.datetime.now())
        self.save()
        logger.info("Procesos activos: "+str(threading.active_count()))
        #thr.is_alive() # will return whether foo is running currently
        #thr.join() # will wait till "foo" is done

    def getOutputFolder(self):
        return scanconf['folder_output']

    def getFilePrefix(self):
        return scanconf['file_prefix']

    def getNseFolder(self):
        #return scanconf['folder_nse']
        return ""

    def getCustomFolder(self):
        return scanconf['folder_custom']

    def getLibFolder(self):
        return scanconf['folder_lib']

    def getNameId(self):
        return self.vulnerability + "-" + self.getStrId()

    def getOutputFileName(self):
        return self.getFilePrefix() + self.getNameId()

    def relativeOutputFilePrefix(self):
        return self.getOutputFolder() + "/"

    def getOutputFilePathName(self):
        return self.relativeOutputFilePrefix() + self.getOutputFileName()

    def getOutputXmlFileName(self):
        return self.__addOutputFile(".xml")

    def getOutputJsonFileName(self):
        return self.__addOutputFile(".json")

    def getOutputXmlFilePathName(self):
        return self.relativeOutputFilePrefix() + self.getOutputXmlFileName()

    def getOutputJsonFilePath(self):
        return self.relativeOutputFilePrefix() + self.getOutputJsonFileName()

    def getOutputNmapAllFileName(self):
        for ext in ['.xml','.nmap','.gnmap']:
            self.__addOutputFile(ext)
        return self.getOutputFileName()

    def getOutputNmapAllFilePathName(self):
        return self.relativeOutputFilePrefix() + self.getOutputNmapAllFileName()

    def __addOutputFile(self, extension=""):
        name = self.getOutputFileName() + extension
        if name not in self.output_files:
            self.output_files.append(name)
        return name

    def isEnabledExternal(self):
        return True

##### THREADED FUNCTIONS #####
    def __run(self):
        try:
            try:
                logger.info("Corriendo: " + self.getNameId())
                out, err = self.execute()
                out = out.decode("utf-8")
                err = err.decode("utf-8")
                #print(out)
                #print(err)
                if err != '':
                    self.errors.append(str(datetime.datetime.now()) + " - Output error from command:  " + err)
            except Exception as e:
                self.errors.append(str(datetime.datetime.now())+" - Cant execute command:  "+str(sys.exc_info()[1]))
                raise e
            try:
                data = self.loadOutput(out)
            except Exception as e:
                self.errors.append(str(datetime.datetime.now())+" - Cant get data from output data file:  "+str(sys.exc_info()[1]))
                raise e
            try:
                self.result = self.prepareOutput(data)
            except Exception as e:
                self.errors.append(str(datetime.datetime.now())+" - Cant parse outputs:  "+str(sys.exc_info()[1]))
                raise e
            try:
                self.sendFeedback()
                self.status = "finished"
            except Exception as e:
                self.errors.append(str(datetime.datetime.now())+" - Cant send feedback:  "+str(sys.exc_info()[1]))
                raise e
        except Exception as e:
            self.status = "error"
            t, v, tb = sys.exc_info()
            time = str(datetime.datetime.now())
            tbinfo = traceback.format_tb(tb)#[0]
            #errormsg = "\nError info:\n" + str(sys.exc_info()[1])+"\n"
            debugmsg = "\nTraceback info:\n" + ''.join(tbinfo) + "\n"
            #logger.error("exception\n" + time + errormsg)
            logger.error("exception in scan: " + self.getNameId() + "\n" + '\n'.join(self.errors))
            logger.debug("exception in scan: " + self.getNameId() + "\n" + time + debugmsg+str(t.__name__)+":"+str(v)+"\n")
            #raise e

        self.finished_at = str(datetime.datetime.now())
        self.save()
        logger.info("Terminado: " + self.getNameId())

    def execute(self):
        logger.info(self.getCommand())
        p = sub.Popen(self.getCommand(),stdout=sub.PIPE,stderr=sub.PIPE)
        return p.communicate()

    def loadOutput(self, output):
        return self.loadXmlAsJson(self.getOutputXmlFilePathName())

    def getIterableNmapHosts(self, script):
        hosts = []
        try:
            hosts = script['nmaprun']['host']
        except:
            raise Exception ("Cannot get info about scan hosts. Maybe wrong parsed output")
        if type(hosts) != type([]):
            hosts = [hosts]
        return hosts

    def getIterablePossibleNmapPorts(self, host):
        ports = []
        try:
            ports = host['ports']['port']
        except:
            #raise Exception ("Cannot get info about scan ports. Maybe wrong parsed output")
            pass
        if type(ports) != type([]):
            ports = [ports]
        return ports

    def isVulnerable(self, port, host):
        r = port.get('script', 'Not vulnerable')
        if type(r) == type({}):
            return True
        return False

    def getParsedEvidence(self, port, host):
        #print("base evidence")
        result = host.get('script', '')
        if not result:
            raise Exception ("Cannot parse evidence as default")
        return result

    def getIpv4(self, host):
        value = host
        if type(host) == type([]):
            for h in host:
                if h['addrtype'] == 'ipv4':
                    value = h
        return value['addr']

    def parseAsNmapScript(self, data):
        v = []
        notv = []
        hosts = self.getIterableNmapHosts(data)
        for host in hosts:
            services = self.getIterablePossibleNmapPorts(host)
            pvulnerables = []
            pnot_vulnerables = []
            evidences = []
            evidence = "None"
            for port in services:
                if self.isVulnerable(port,host):
                    pvulnerables.append(port['portid'])
                    try:
                        evidences.append(self.getParsedEvidence(port,host))
                    except Exception as e:
                        self.errors.append(str(datetime.datetime.now())+" - Cant get evidence:  "+str(sys.exc_info()[1]))
                else:
                    #pnot_vulnerables.append(port['portid'])
                    pass
            if pvulnerables != []:
                ipv4 = self.getIpv4(host['address'])
                v.append({"address":ipv4,"ports":pvulnerables,"evidence":evidences})
            #notv.append({"address":host['address']['addr'],"ports":pnot_vulnerables})
        return {"vulnerables":v, "no_vulnerables":notv}

    # def printKeyVals(self, data, indent=0):
    #     res = ''
    #     if isinstance(data, list):
    #         for item in data:
    #             res += str(self.printKeyVals(item, indent+1))
    #     elif isinstance(data, dict):
    #         #print()
    #         for k, v in data.items():
    #             if (isinstance(v, str)):
    #                 res += str(" " * indent, k + ":", v)
    #             else:
    #                 res += str(" " * indent, k + ":", self.printKeyVals(v, indent + 1))
    #     else:
    #         res += str(data)
    #     return res

    def getParamValueFor(self, index):
        if index in self.params:
            if self.params[index] in [True, 1]:
                return True
            if self.params[index] in [False, 0]:
                return False
        else:
            if index == 'send-full-report':
                return False
            if index == 'send-nmap-report':
                return False
            if index == 'send-report':
                return False

    def getFormatedEvidence(self, data):
        return pprint.pformat(data, indent=2)

    def getEvidenceReport(self, data):
        if self.getParamValueFor('send-nmap-report'):
            return open(self.getOutputFilePathName()+".nmap", "rb").read()
        else:
            return self.getFormatedEvidence(data)

    def sendFeedback(self):
        if self.getParamValueFor('send-full-report'):
            return False
        for out in self.outputs:
            payloads = []
            url = endpointsconf[out]
            #url = 'http://localhost:8088/'
            if out in ["NGEN", "NGEN-dev", "NGEN-staging"]:
                print("PARA NGEN")
                hosts = self.prepareForNGEN()
                headers = {'Accept' : '*/*', 'Expect': '100-continue'}
                for h in hosts:
                    evidence = self.getEvidenceReport(h['evidence'])
                    files = {'evidence_file': ("evidence.txt", evidence, 'text/plain', {'Expires': '0'})}
                    response = requests.post(url, data=h['data'], headers=headers, files=files, verify=False)
                    print(str(response)+str(response.text))
            elif out in ["faraday"]:
                hosts = self.sendToFaraday(endpointsconf[out])
            else:
                hosts = [self.toJson()]
                headers = {'Accept' : '*/*', 'Expect': '100-continue'}
                for h in hosts:
                    evidence = self.getEvidenceReport(h['evidence'])
                    files = {'evidence_file': ("evidence.txt", evidence, 'text/plain', {'Expires': '0'})}
                    response = requests.post(url, data=h['data'], headers=headers, files=files, verify=False)
                    print(str(response)+str(response.text))


    def prepareForNGEN(self):
        hosts = []
        feed = "external_report"
        if "feed" in self.params:
            feed = self.params['feed']
        for host in self.result['vulnerables']:
            h = {'data':dict(
                    type = self.getTypeNGEN(),
                    hostAddress = host['address'],
                    feed = feed
                ),
                'evidence': host['evidence']
            }
            if self.getParamValueFor('send-report'):
                h['data']['sendReport'] = 1
            hosts.append(h)
        #print(hosts)
        return hosts

    def sendToFaraday(self, url):
        api = xmlrpc.client.ServerProxy(url)
        for host in self.result['vulnerables']:
            h_id = api.createAndAddHost(host['address'],"")
            i_id = api.createAndAddInterface(
                h_id,
                host['address'],
                "00:00:00:00:00:00",
                host['address'],
                "0.0.0.0",
                "0.0.0.0",
                [],
                "0000:0000:0000:0000:0000:0000:0000:0000",
                "00",
                "0000:0000:0000:0000:0000:0000:0000:0000",
                [],
                "",
                socket.gethostbyaddr(host['address'])[0]
                )
            for port in self.ports:
                s_id = api.createAndAddServiceToInterface(
                    h_id,
                    i_id,
                    socket.getservbyport(int(port)),
                    self.getPortType(),
                    port,
                    "open",
                    "",
                    host['evidence']
                    )

#### SUBLCLASS RESPONSIBILITY #####
    def getCommand(self):
        pass
    def addCommandPorts(self, command, ports):
        pass
    def prepareOutput(self, out, errors):
        pass
    def getDefaultPorts(self):
        pass
    def getTypeNGEN(self):
        pass

####### DB-USE #######
    def save(self, db=None):
        if not db:
            client = MongoClient(dbconf['host'], dbconf['port'])
            db = client[dbconf['db']]
        if not self._id:
            self._id = ObjectId()
        db.scans.update(
                { "_id": self._id },
                self.__dict__,
                upsert=True
            )
        #return db.insert_one(self.toDict()).inserted_id
        return self._id

    @classmethod
    def get(cls, scan_id, db=db):
        d = db.scans.find_one({"_id": ObjectId(scan_id)})
        return cls.get_scans()[d['vulnerability']](**d)


##### CONVERTION #####
    def toJson(self):
        return json.dumps(self.toDict(), sort_keys=True, indent=4)

    def toDict(self):
        return dict(
                _id=str(self._id),
                _network=self.network,
                _outputs=self.outputs,
                _origin=self.origin,
                _ports=self.ports,
                errors=self.errors,
                output_files=self.output_files,
                finished_at=self.finished_at,
                params=self.params,
                report_to=self.report_to,
                result=self.result,
                started_at=self.started_at,
                status=self.status,
                vulnerability=self.vulnerability
            )

    def toDefaultDict():
        return self.__dict__


##### PROPERTIES #####
    @property
    def network(self):
        return self._network

    @network.setter
    def network(self, n):
        if not n: raise Exception("Network cannot be empty")
        aux = n.split("/")
        if len(aux) > 2: raise Exception("Network malformed")
        if len(aux) == 2 and len(aux[1]) > 2:
            raise Exception("Network malformed")
        address = aux[0].split(".")
        if len(address) > 4: raise Exception("Network malformed")
        for octet in address:
            nums = octet.split(",")
            for num in nums:
                ranges = num.split("-")
                if len(ranges) > 2: raise Exception("Network malformed")
                for r in ranges:
                    try:
                        val = int(r)
                        if val < 0 or val > 255: raise Exception("Network malformed")
                    except:
                        raise Exception("Network malformed")
        self._network = n

    def setParams(self, p):
        if type(p) != dict: raise Exception("Params must be a dictionary")
        self.params = p

    @property
    def outputs(self):
        return self._outputs

    @outputs.setter
    def outputs(self, o):
        if type(o) != list: raise Exception("Outputs must be a list")
        for endpoint in o:
            if not endpoint in list(endpointsconf.keys()):
                raise Exception("Bad endpoints")
        self._outputs = o

    @property
    def ports(self):
        return self._ports

    @ports.setter
    def ports(self, p):
        if type(p) != list: raise Exception("Ports must be a list")
        if p == []:
            p = self.getDefaultPorts()
        self._ports = p

    @property
    def origin(self):
        return self._origin

    @origin.setter
    def origin(self, ip):
        print(ip)
        if not self.isEnabledExternal() and ip != '127.0.0.1':
            raise Exception("This scan is only enabled for localhost.")
        self._origin = ip

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, i=None):
        if type(i) == ObjectId:
            self._id = i
        elif type(i) == str:
            self._id = ObjectId(i)
        else:
            self._id = ObjectId()

    def getStrId(self):
        return str(self._id)

#s = Scan()

#with open("outputs/outputsssl-poodle-I46ZJ3.json") as f:
#    data = f.read()
#j = json.loads(data)
#res = s.parseAsNmapScript(j,b'')
#print(res)
