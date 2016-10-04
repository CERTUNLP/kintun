Kintun: Restful Vulnerability Scanner
--------

=============

[![AUR](https://img.shields.io/aur/license/yaourt.svg?maxAge=2592000)](https://github.com/CERTUNLP/Kintun/blob/master/LICENSE)
![Python 3](http://img.shields.io/badge/python-3-blue.svg)

API Restful for search vulnerabilities over networks and export results to a chosen system.

Related Projects:

- NGEN

Requires:
--------

----

- Python 3
- Flask 0.10.1
- MongoDB 3.0.6
- NMap +7.3 (https://launchpad.net/~pi-rho/+archive/ubuntu/security)
- SSL Python Support
- Expect
- Shelldap
- This proyect!

-----------


Install on Linux (simplified):
----------------


1. System dependencies.

    ```
    $ sudo apt-get install python3 python3-pip python3-setuptools mongodb python3-dev libssl-dev libffi-dev expect shelldap
    ```

2. Install Python3 requirements.

    ```
    $ sudo pip3 install -r requirements.txt
    ```

3. Then set up your certificate and key at ssl directory with python3.

    ```
    $ python3
    >>> from werkzeug.serving import make_ssl_devcert
    >>> make_ssl_devcert('ssl/key', host='localhost')
    ```

Install on Linux (detailed):
----------------


1. You may have python3, pip3 and setuptools.

    ```
    $ sudo apt-get install python3 python3-pip python3-setuptools
    ```

2. Install MongoDB and install only for localhost access without user (by now). [Documentation](http://docs.mongodb.org/manual/administration/install-on-linux/).

    ```
    $ sudo apt-get install mongodb
    ```

3. Install SSL dependencies.

    ```
    $ sudo apt-get install python3-dev libssl-dev libffi-dev
    ```

4. Install specific scan utilities.

    ```
    $ sudo apt-get install expect
    $ sudo apt-get install shelldap
    ```

5. Install Python3 requirements.

    ```
    $ sudo pip3 install -r requirements.txt
    ```

6. Then set up your certificate and key at ssl directory with python3.

    ```
    $ python3
    >>> from werkzeug.serving import make_ssl_devcert
    >>> make_ssl_devcert('ssl/key', host='localhost')
    ```

Run on Linux:
----------------

```
$ sudo python3 startserver.py
```

License
-------

This application is under the GPL v3.0 license. See the complete license in the application:
[LICENSE](https://github.com/CERTUNLP/Kintun/blob/master/LICENSE)
