from flask import Flask
from flask import request, abort, jsonify
import json

from .analyzer import analyze_ip, analyze_domain, Analyzer

ws = Flask("ipanalyzer")

@ws.route("/")          # quitar cuando pongo el codigo
@ws.route("/analyze")
@ws.route("/analyze/")
@ws.route("/analyze/<analyzer>")
@ws.route("/analyze/<analyzer>/")
def ip_analyze(analyzer = None):
    ip = request.args.get('ip')
    domain = request.args.get('domain')
    if analyzer is None:
        analyzer = "all"
    elif not analyzer in Analyzer.analyzers:
        return abort(400, "Analizador invalido")

    if ip:
        return jsonify(analyze_ip(ip, analyzer))
    elif domain:
        return jsonify(analyze_domain(domain, analyzer))
    else:
        return abort(418, "I don't like coffee")


if __name__ == "__main__":
    ws.debug = True
    ws.run()
