#!flask/bin/python
#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#

from . import app
from .model.vuln import *
from .model.scan import Scan

from flask import jsonify, abort, make_response, request, url_for, render_template
from bson.objectid import ObjectId

from config import db
import json
from pprint import pprint


@app.route('/hello/')
@app.route('/hello/<name>')
def hello(name=None):
    return render_template('hello.html', name=name)


@app.route('/mqv/<file>')
def mqv(file=None):
    return render_template(file, file=file)


@app.route('/print')
def pp(name=None):
    return render_template('hello.html', name=app.view_functions)


@app.route('/print2')
def pp2(name=None):
    s = ""
    for x in app.url_map.iter_rules():
        s += str(dir(x))
    return render_template('hello.html', name=dir(list(app.url_map.iter_rules())[0]))


@app.route('/print3')
def pp3(name=None):
    return render_template('hello.html', name=list(app.url_map.iter_rules())[0])


def rules():
    f = []
    rules = sorted(list(app.url_map.iter_rules()), key=lambda k: k.rule)
    for r in rules:
        f.append({
            # 'suitable_for': str(r.suitable_for),
            # 'subdomain': r.subdomain,
            # 'alias': r.alias,
            # 'host': r.host,
            'rule': r.rule,
            'arguments': list(r.arguments),
            'methods': r.methods,
            'endpoint': r.endpoint,
            'postargs': app.view_functions[r.endpoint].__doc__
        })
    return f


@app.route('/views')
def pp4():
    pprint(rules())
    return render_template('rules.html', rules=rules())


# site map


@app.route("/")
@app.route("/all-links")
def all_links():
    links = []
    for rule in app.url_map.iter_rules():
        if len(rule.defaults or {}) >= len(rule.arguments or {}):
            url = url_for(rule.endpoint, **(rule.defaults or {}))
            links.append((url, rule.endpoint))
    print(links)
    return render_template("hello.html", links=links)


class data:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


@app.route("/test", methods=['GET'])
def test():
    r = request
    global request
    request = data(json={
        'network': "127.0.0.1",
        'params': "ccc",
        'outputs': [],
        'vuln': "netbios",
        'ports': []
    }, remote_addr=r.remote_addr)
    return create_scan()


@app.route("/view/<method>/<path:api>", methods=['GET'])
def view(method, api):
    api = '/'+api
    print(rules())
    print(api)
    rule = next((r for r in rules() if r['rule'] == api), None)
    return render_template("view.html", method=method, rule=rule)
    # return(api)


# @app.route("/view/<path:api>", methods=['POST'])
# def view_post(api):
#     # rules = rules()
#     return render_template("hello.html", name=api)

# previo


@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    x = Scan.get(scan_id, db)
    return jsonify(make_public_scan(x.toDict()))
    # return x.toJson()


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({
        'error': 'Not found',
        'error_type': '404'
    }), 404)


@app.errorhandler(400)
def bad_request(error):
    return make_response(jsonify({
        'error': 'Bad Request',
        'error_type': '400',
        'error_descriptions': error.description
    }), 400)


@app.route('/api/scan', methods=['POST'])
def create_scan():
    """
    network:
    params:
    outputs:
    vuln:
    ports:
    """
    rj = request.json
    if not rj or not 'network' or not 'params' or not 'outputs' or not 'vuln' or not 'ports' in rj:
        abort(
            400, "Parametros incorrectos. Requiere 'network', 'params', 'outputs', 'ports' y 'vuln'")
    try:
        s = Scan.get_scans()[rj['vuln']](
            network=rj['network'],
            ports=rj['ports'],
            params=rj['params'],
            outputs=rj['outputs'],
            origin=request.remote_addr)
        s.start()
    except Exception as err:
        abort(400, err.args)
    # scan.save(db)
    return jsonify(make_public_scan(s.toDict())), 201


@app.route('/api/scans/<scan_id>', methods=['PUT'])
def update_scan(scan_id):
    # TODO: Reimplement
    s = [scan for scan in [] if scan['id'] == scan_id]
    if len(s) == 0:
        abort(404)
    if not request.json:
        abort(400)
    if 'title' in request.json:  # and type(request.json['title']) != unicode:
        abort(400)
    # and type(request.json['description']) is not unicode:
    if 'description' in request.json:
        abort(400)
    if 'done' in request.json and type(request.json['done']) is not bool:
        abort(400)
    s[0]['title'] = request.json.get('title', s[0]['title'])
    s[0]['description'] = request.json.get('description', s[0]['description'])
    s[0]['done'] = request.json.get('done', s[0]['done'])
    return jsonify({'result': "Not implemented yet."})


@app.route('/api/scans/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    # TODO: Reimplement
    s = [scan for scan in [] if scan['id'] == scan_id]
    if len(s) == 0:
        abort(404)
    # scans.remove(s[0])
    return jsonify({'result': "Not implemented yet."})


def make_public_scan(scan):
    new_scan = {}
    for field in scan:
        if field == '_id':
            new_scan['uri'] = url_for(
                'get_scan', scan_id=str(scan['_id']), _external=True)
            new_scan[field] = str(scan[field])
        else:
            new_scan[field] = scan[field]
    return new_scan


@app.route('/api/scans', methods=['GET'])
def get_scans():
    alls = [make_public_scan(scan) for scan in db.scans.find()]
    return jsonify({"scans": alls, "count": len(alls)})


@app.route('/api/', methods=['GET'])
def get_info():
    return jsonify({"name": 'Kintun Scan API', "version": '0.1'})


@app.route('/api/report/<scan_id>', methods=['GET'])
def report():
    s = db.scans.find()
    return jsonify({'scans': [make_public_scan(scan) for scan in s]})


@app.route('/api/print', methods=['POST'])
def print_something():
    print("Imprimiendo request recibida: ")
    if not request.json:
        abort(400, "Parametros incorrectos, no hay json")
    print(request.json)
    return jsonify(request.json), 201

# if __name__ == '__main__':
    # app.run(debug=True,host="0.0.0.0")
#    app.run(host="0.0.0.0", debug = True, ssl_context=context)
