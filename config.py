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
import sys
import os
from utils.logger import setup_logger
from utils.db import setup_db
from utils.send_mail import MailLog

# Config
base_path = os.path.dirname(os.path.abspath(__file__))

os.chdir(base_path)

with open('config.json', encoding='utf-8') as json_data_file:
    conf = json.load(json_data_file)

scanconf = conf['scan']
endpointsconf = conf['endpoints']
sslconf = conf['ssl']


# Logger
logger = setup_logger(conf['log'])
logger.info('Config Loaded\n'+str(conf))

# Context
sslpath = sslconf['folder']+'/'
ssl = (sslpath+sslconf['crt'], sslpath+sslconf['key'])

if not os.path.exists(scanconf["folder_output"]):
    os.makedirs(scanconf["folder_output"])

# Database
dbdriver = conf['databases']['driver']
db = setup_db(conf['databases'][dbdriver])

# MailLog
maillog = MailLog(conf['maillog'])