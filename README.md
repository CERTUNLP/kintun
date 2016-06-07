Kintun: Sistema de búsqueda de vulnerabilidades en redes.

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
- Python virtualenv
- Flask 0.10.1
- MongoDB 3.0.6
- NMap +7.3 (https://launchpad.net/~pi-rho/+archive/ubuntu/security)
- Expect
- Shelldap
- SSL Python Support
- This proyect!

-----------


Install on Linux (easy way):
----------------


1. You may have python3 and pip3.

    ```
    $ sudo apt-get install python3-pip
    ```

2. Install python virtualenv.

    With GVM (http://gvmtool.net/):

    ```
    $ sudo easy_install virtualenv
    ```

    or

    ```
    $ sudo pip3 install virtualenv
    ```

    or

    ```
    $ sudo apt-get install python-virtualenv
    ```

3. Install Flask.

    ```
    $ sudo apt-get install python3-setuptools
    $ sudo pip3 install Flask
    ```

4. Install MongoDB and install only for localhost access without user (by now).

    http://docs.mongodb.org/manual/administration/install-on-linux/

    Ubuntu:
    ```
    $ sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927
    $ echo "deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.2.list
    $ sudo apt-get update
    $ sudo apt-get install -y mongodb-org
    $ sudo apt-get install -y mongodb-org=3.2.1 mongodb-org-server=3.2.1 mongodb-org-shell=3.2.1 mongodb-org-mongos=3.2.1 mongodb-org-tools=3.2.1

    ```
    or:
    ```
    $ sudo apt-get install mongodb
    ```

    then:

    ```
    $ sudo pip3 install pymongo
    $ sudo pip3 install pyOpenSSL

    ```

5. Install SSL dependencies.

    ```
    $ sudo apt-get install python3-dev libssl-dev libffi-dev
    $ sudo pip3 install pyopenssl pycrypto cryptography
    ```
    Then set up your certificate and key at ssl directory:

    ```
    >>> from werkzeug.serving import make_ssl_devcert
    >>> make_ssl_devcert('ssl/key', host='localhost')
    ```

6. Run Application.

    ```
    $ sudo python3 startserver.py
    ```

License
-------

This application is under the GPL v3.0 license. See the complete license in the application:
[LICENSE](https://github.com/CERTUNLP/NgenBundle/blob/master/Resources/meta/LICENSE)
