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

from flask import jsonify, abort, make_response, request, url_for
from bson.objectid import ObjectId

from config import db
import json

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    x = Scan.get(scan_id, db)
    return jsonify(make_public_scan(x.toDict()))
    #return x.toJson()


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({
        'error': 'Not found',
        'error_type': '404'
        }), 404)

@app.errorhandler(400)
def not_found(error):
    return make_response(jsonify({
        'error': 'Bad Request',
        'error_type':'400',
        'error_descriptions': error.description
        }), 400)

@app.route('/api/scan', methods=['POST'])
def create_scan():
    rj = request.json
    if not rj or not 'network' or not 'params' or not 'outputs' or not 'vuln' in rj:
        abort(400,"Parametros incorrectos")
    try:
        s = Scan.get_scans()[rj['vuln']](
                network=rj['network'],
                ports=rj['ports'],
                params=rj['params'],
                outputs=rj['outputs'],
                report_to=rj['report_to'],
                origin=request.remote_addr)
        s.start()
    except Exception as err:
        abort(400,err.args)
    #scan.save(db)
    return jsonify(make_public_scan(s.toDict())), 201

@app.route('/api/scans/<scan_id>', methods=['PUT'])
def update_scan(scan_id):
    s = [scan for scan in scans if scan['id'] == scan_id]
    if len(s) == 0:
        abort(404)
    if not request.json:
        abort(400)
    if 'title' in request.json and type(request.json['title']) != unicode:
        abort(400)
    if 'description' in request.json and type(request.json['description']) is not unicode:
        abort(400)
    if 'done' in request.json and type(request.json['done']) is not bool:
        abort(400)
    s[0]['title'] = request.json.get('title', s[0]['title'])
    s[0]['description'] = request.json.get('description', s[0]['description'])
    s[0]['done'] = request.json.get('done', s[0]['done'])
    return jsonify({'scan': s[0]})

@app.route('/api/scans/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    s = [scan for scan in scans if scan['id'] == scan_id]
    if len(s) == 0:
        abort(404)
    scans.remove(s[0])
    return jsonify({'result': True})

def make_public_scan(scan):
    new_scan = {}
    for field in scan:
        if field == '_id':
            new_scan['uri'] = url_for('get_scan', scan_id=str(scan['_id']), _external=True)
            new_scan[field] = str(scan[field])
        else:
            new_scan[field] = scan[field]
    return new_scan

@app.route('/api/scans', methods=['GET'])
def get_scans():
    alls = [make_public_scan(scan) for scan in db.scans.find()]
    return jsonify({"scans":alls, "count":len(alls)})

@app.route('/api/report/<scan_id>', methods=['GET'])
def report():
    s = db.scans.find()
    return jsonify({'scans': [make_public_scan(scan) for scan in s]})

@app.route('/api/print', methods=['POST'])
def print_something():
    print("Imprimiendo request recibida: ")
    if not request.json:
        abort(400,"Parametros incorrectos, no hay json")
    print(request.json)
    return jsonify(request.json), 201

#if __name__ == '__main__':
    #app.run(debug=True,host="0.0.0.0")
#    app.run(host="0.0.0.0", debug = True, ssl_context=context)
