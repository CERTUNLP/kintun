#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

import json
from pprint import pprint
import logging
from logging.handlers import TimedRotatingFileHandler
import sys
import os
from pymongo import MongoClient
from send_mail import MailLog

################################################################
############################ CONFIG ############################
################################################################

base_path = os.path.dirname(os.path.abspath(__file__))

os.chdir(base_path)

print(base_path)

with open('config.json', encoding='utf-8') as json_data_file:
    conf = json.load(json_data_file)

dbdriver = conf['databases']['driver']
dbconf = conf['databases'][dbdriver]

scanconf = conf['scan']

endpointsconf = conf['endpoints']

sslconf = conf['ssl']

logconf = conf['log']


################################################################
############################ LOGGER ############################
################################################################

# create logger with 'app_log'
logger = logging.getLogger(logconf['name'])
logger.setLevel(logging.DEBUG)

# create stdout handler with a higher log level
sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.DEBUG)
log_path = logconf["folder"]+'/'

# create stdout_file handler whiefh logs even debug messages
sfh = TimedRotatingFileHandler(
    log_path+logconf['stdout']['name'],
    when="W0",
    interval=1,
    backupCount=5)
sfh.setLevel(logging.DEBUG)

# create file handler with a higher log level
efh = TimedRotatingFileHandler(
    log_path+logconf['error']['name'],
    when="W0",
    interval=1,
    backupCount=5)
efh.setLevel(logging.ERROR)

# create formatter and add it to the handlers
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s: %(message)s')
sh.setFormatter(formatter)
sfh.setFormatter(formatter)
efh.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(sh)
logger.addHandler(sfh)
logger.addHandler(efh)

logger.info('Config Loaded\n'+str(conf))

################################################################
############################ CONTEXT ###########################
################################################################

sslpath = sslconf['folder']+'/'
ssl = (sslpath+sslconf['crt'], sslpath+sslconf['key'])

if not os.path.exists(scanconf["folder_output"]):
    os.makedirs(scanconf["folder_output"])

################################################################
############################ DATABASE ##########################
################################################################

print(dbconf['user'], dbconf['password'])
client = MongoClient(dbconf['host'], dbconf['port'], username=dbconf['user'], password=dbconf['password'])
db = client[dbconf['db']]
scans = db.scans

################################################################
############################ MAILLOG ###########################
################################################################

maillog = MailLog(conf['maillog'])
