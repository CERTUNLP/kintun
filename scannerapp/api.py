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
from config import logger

from functools import wraps
from flask import jsonify, abort, make_response, request, url_for, redirect
from bson.objectid import ObjectId

from config import db
import os
from dotenv import load_dotenv

load_dotenv()
VALID_API_KEY = os.getenv("KINTUN_API_KEY","")

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('x-api-key')
        if api_key and api_key == VALID_API_KEY:
            return f(*args, **kwargs)
        else:
            return jsonify({"error": "Unauthorized", "error_type": "401"}), 401
    return decorated_function

@app.route("/", methods=["GET"])
@require_api_key
def get_root():
    return redirect(url_for("get_api_root"))


@app.route("/api/scan/<scan_id>", methods=["GET"])
@require_api_key
def get_scan(scan_id):
    try: 
        x = Scan.get(scan_id, db)
        return jsonify(make_public_scan(x.toDict()))
    except Exception as e:
        logger.error(f"Error: {e}")
        return jsonify({"error": "Scan not found", "error_type": "404"}), 404
    # return x.toJson()


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({"error": "Not found", "error_type": "404"}), 404)


@app.errorhandler(400)
def bad_request(error):
    return make_response(
        jsonify(
            {
                "error": "Bad Request",
                "error_type": "400",
                "error_descriptions": error.description,
            }
        ),
        400,
    )


@app.route("/api/scan", methods=["POST"])
@require_api_key
def create_scan():
    """
    network:
    params:
    outputs:
    vuln:
    ports:
    protocol:
    """
    rj = request.json
    if (
        not rj
        or not "network"
        or not "params"
        or not "outputs"
        or not "vuln"
        or not "ports" in rj
    ):
        abort(
            400,
            "Parametros incorrectos. Requiere 'network', 'params', 'outputs', 'ports' y 'vuln'",
        )
    try:
        s = Scan.get_scans()[rj["vuln"]](
            network=rj["network"],
            ports=rj["ports"],
            params=rj["params"],
            outputs=rj["outputs"],
            origin=request.remote_addr,
            protocols=rj.get("protocol", ["tcp"]),
        )
        s.start()
    except Exception as err:
        raise err
        # abort(400, err.args)
    s.save(db)
    return jsonify(make_public_scan(s.toDict())), 201


@app.route("/api/scan_now", methods=["POST"])
@require_api_key
def create_scan_now():
    """
    network:
    params:
    outputs:
    vuln:
    ports:
    """
    rj = request.json
    if (
        not rj
        or not "network"
        or not "params"
        or not "outputs"
        or not "vuln"
        or not "ports" in rj
    ):
        abort(
            400,
            "Parametros incorrectos. Requiere 'network', 'params', 'outputs', 'ports' y 'vuln'",
        )
    try:
        s = Scan.get_scans()[rj["vuln"]](
            network=rj["network"],
            ports=rj["ports"],
            params=rj["params"],
            outputs=rj["outputs"],
            origin=request.remote_addr,
        )
        s.start(preemptive=True)
    except Exception as err:
        raise err
        # abort(400, err.args)
    s.save(db)
    return jsonify(make_public_scan(s.toDict())), 201


@app.route("/api/scans/<scan_id>", methods=["PUT"])
@require_api_key
def update_scan(scan_id):
    # TODO: Reimplement
    s = [scan for scan in [] if scan["id"] == scan_id]
    if len(s) == 0:
        abort(404)
    if not request.data:
        abort(400)
    if "title" in request.data:  # and type(request.json['title']) != unicode:
        abort(400)
    # and type(request.json['description']) is not unicode:
    if "description" in request.data:
        abort(400)
    if "done" in request.json and type(request.json["done"]) is not bool:
        abort(400)
    s[0]["title"] = request.json.get("title", s[0]["title"])
    s[0]["description"] = request.json.get("description", s[0]["description"])
    s[0]["done"] = request.json.get("done", s[0]["done"])
    return jsonify({"result": "Not implemented yet."})


@app.route("/api/scans/<scan_id>", methods=["DELETE"])
@require_api_key
def delete_scan(scan_id):
    # TODO: Reimplement
    s = [scan for scan in [] if scan["id"] == scan_id]
    if len(s) == 0:
        abort(404)
    # scans.remove(s[0])
    return jsonify({"result": "Not implemented yet."})

def make_public_scan(scan):
    new_scan = {}
    for field in scan:
        if field == "_id":
            new_scan["uri"] = url_for(
                "get_scan", scan_id=str(scan["_id"]), _external=True
            )
            new_scan[field] = str(scan[field])
        else:
            new_scan[field] = scan[field]
    return new_scan


@app.route("/api/scans", methods=["GET"])
@require_api_key
def get_scans():
    alls = [make_public_scan(scan) for scan in db.scans.find()]
    return jsonify({"scans": alls, "count": len(alls)})


@app.route("/api/", methods=["GET"])
@require_api_key
def get_api_root():
    return jsonify({"name": "Kintun Scan API", "version": "0.1"})


@app.route("/api/report/<scan_id>", methods=["GET"])
@require_api_key
def report(scan_id):
    s = db.scans.find()
    return jsonify({"scans": [make_public_scan(scan) for scan in s]})


@app.route("/api/print", methods=["POST", "GET"])
@require_api_key
def print_something():
    print("Imprimiendo request recibida: ")
    print(request.args)
    print(request.data)
    # request.json intenta convertir automaticamente a json y si no puede da un error poco descriptivo
    if not request.data:
        abort(400, "Parametros incorrectos, no hay json")
    print(request.json)
    return jsonify(request.json), 201
