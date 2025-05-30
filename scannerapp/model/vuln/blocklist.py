#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from ..scan import Scan
from dotenv import load_dotenv
import requests, datetime, sys, os, json
from stamina import retry

load_dotenv()
mxtoolbox_api_key = os.getenv("MXTOOLBOX_API_KEY")


class Blocklist(Scan):
    name = "blocklist"

    def __init__(self, *kwargs, **kwargs2):
        Scan.__init__(self, kwargs, kwargs2)

    @classmethod
    def getName(cls):
        return cls.name

    def getCommand(self):
        pass

    # Command as a request instead of scanning
    # MXTOOLBOX  api/v1/Lookup/{Command}/?argument={argument}
    @retry(on=Exception, attempts=3, wait_initial=2)
    def execute(self):
        header = {"Authorization": mxtoolbox_api_key}
        r = requests.get(f"https://api.mxtoolbox.com/api/v1/Lookup/blacklist/?argument={self.network}", headers=header)
        return bytes(r.text, "utf-8"), b""

    def loadOutput(self, data):
        return data

    def parseAsRequests(self, response):
        v = []
        notv = []
        response = json.loads(response)
        network = response.get("CommandArgument")
        failed_feeds = response.get("Failed")
        if (failed_feeds):
            for feed in failed_feeds:
                v.append({"address": network, "evidence": f"La ip {network} se encuentra en la lista negra de {feed.get('Name')}. Para delistearla, contacte a {feed.get('DelistUrl')}"})
        else:
            notv.append({"address": network, "evidence": f"La ip {network} no se encuentra en ninguna lista negra"})
        return {"vulnerables": v, "no_vulnerables": notv}

    def prepareOutput(self, data):
        return self.parseAsRequests(data)