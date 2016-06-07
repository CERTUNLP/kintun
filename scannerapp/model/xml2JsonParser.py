#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

import xml.etree.ElementTree as ET
from collections import defaultdict
import sys
import json
import pprint

# on python 2 use iteritems()
# on python 3 use items()

class Xml2JsonParser():

    def __init__(self, origen, destino):
        self.origen = origen
        self.destino = destino

    def etree_to_dict(self,t):
        d = {t.tag: {} if t.attrib else None}
        children = list(t)
        if children:
            dd = defaultdict(list)
            for dc in map(self.etree_to_dict, children):
                for k, v in dc.items():
                    dd[k].append(v)
            d = {t.tag: {k:v[0] if len(v) == 1 else v for k, v in dd.items()}}
        if t.attrib:
            d[t.tag].update(('' + k, v) for k, v in t.attrib.items())
    #        d[t.tag].update(('@' + k, v) for k, v in t.attrib.items())
        if t.text:
            text = t.text.strip()
            if children or t.attrib:
                if text:
                  d[t.tag]['#text'] = text
            else:
                d[t.tag] = text
        return d

    def parse(self):
        e = ET.parse(self.origen)
        dic = self.etree_to_dict(e.getroot())
        #pp = pprint.PrettyPrinter(indent=1)
        #pp.pprint(dic)
        with open(self.destino, 'w') as outfile:
            json.dump(dic, outfile)
