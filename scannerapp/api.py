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
from .model.vuln import __all__ as vulns
from .model.scan import Scan
from config import logger

from functools import wraps
from flask import jsonify, abort, make_response, render_template, request, url_for, redirect

from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

from config import db
import os
from dotenv import load_dotenv

load_dotenv()
VALID_API_KEY = os.getenv("KINTUN_API_KEY","")

USER_CREDENTIALS = {}
for key, value in os.environ.items():
    if key.startswith("KINTUN_USER_"):
        username, password = value.split(":")
        USER_CREDENTIALS[username] = password

auth = HTTPBasicAuth()

users = {username: generate_password_hash(password) for username, password in USER_CREDENTIALS.items()}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username
    return None

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('x-api-key')
        if api_key and api_key == VALID_API_KEY:
            return f(*args, **kwargs)
        elif request.authorization:
            return auth.login_required(f)(*args, **kwargs)
        return make_response(jsonify({"error": "Unauthorized", "error_type": "401"}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})
    return decorated_function


@app.route("/", methods=["GET"])
@require_auth
def get_root():
    return redirect(url_for("get_form"))


@app.route("/api/scan/<scan_id>", methods=["GET"])
@require_auth
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
@require_auth
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
            origin=[request.remote_addr, request.headers.get("X-Forwarded-For"), request.headers.get("X-Real-IP")],
            protocols=rj.get("protocol", ["tcp"]),
        )
        s.start()
    except Exception as err:
        raise err
        # abort(400, err.args)
    s.save(db)
    return jsonify(make_public_scan(s.toDict())), 201


@app.route("/api/scan_now", methods=["POST"])
@require_auth
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
@require_auth
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
@require_auth
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
            scheme = request.headers.get("X-Forwarded-Scheme") or request.headers.get("X-Scheme") or request.headers.get("X-Forwarded-Proto") or request.scheme
            new_scan["uri"] = url_for(
                "get_scan", scan_id=str(scan["_id"]), _external=True, _scheme=scheme
            )
            new_scan[field] = str(scan[field])
        else:
            new_scan[field] = scan[field]
    return new_scan


@app.route("/api/scans", methods=["GET"])
@require_auth
def get_scans():
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 15))
    filter_text = request.args.get('filter', '').lower()
    skips = limit * (page - 1)
    
    query = {}
    if filter_text:
        query = {
            "$or": [
                {"_id": {"$regex": filter_text, "$options": "i"}},
                {"_network": {"$regex": filter_text, "$options": "i"}},
                {"vulnerability": {"$regex": filter_text, "$options": "i"}},
                {"is_vuln": {"$regex": filter_text, "$options": "i"}}
            ]
        }
    
    total_scans = db.scans.count_documents(query)
    scans = db.scans.find(query).sort("started_at", -1).skip(skips).limit(limit)
    
    return jsonify({
        "scans": [make_public_scan(scan) for scan in scans],
        "count": total_scans,
        "page": page,
        "limit": limit
    })


@app.route("/api/", methods=["GET"])
@require_auth
def get_api_root():
    return jsonify({"name": "Kintun Scan API", "version": "0.1"})

@app.route("/form", methods=["GET"])
@require_auth
def get_form():
    return render_template("form.html", vulns=vulns)

@app.route("/api/report/<scan_id>", methods=["GET"])
@require_auth
def report(scan_id):
    s = db.scans.find()
    return jsonify({"scans": [make_public_scan(scan) for scan in s]})


@app.route("/api/print", methods=["POST", "GET"])
@require_auth
def print_something():
    print("Imprimiendo request recibida: ")
    print(request.args)
    print(request.data)
    # request.json intenta convertir automaticamente a json y si no puede da un error poco descriptivo
    if not request.data:
        abort(400, "Parametros incorrectos, no hay json")
    print(request.json)
    return jsonify(request.json), 201


@app.route("/historic", methods=["GET"])
@require_auth
def get_historic_page():
    return render_template("historic.html")

@app.route("/api/vulns", methods=["GET"])
@require_auth
def get_vuln():
    """
    Returns a list of all available vulnerabilities.
    """
    return jsonify(vulns)