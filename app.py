#!flask/bin/python
#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from scannerapp import app
from config import ssl

app.run( host = "0.0.0.0", debug = True)
# app.run( host = "0.0.0.0", debug = True, ssl_context = ssl )
# app.run( host = "0.0.0.0", ssl_context = ssl )
