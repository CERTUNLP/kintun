API Vulnerability Scanner
=============

You need here key and cert file.
Create them as the main README says in the fifth step:


Install SSL dependencies:

```
$ sudo apt-get install python3-dev libssl-dev libffi-dev
$ sudo pip3 install pyopenssl pycrypto cryptography
```
Then set up your certificate and key at ssl directory:

```
>>> from werkzeug.serving import make_ssl_devcert
>>> make_ssl_devcert('ssl/key', host='localhost')
```
