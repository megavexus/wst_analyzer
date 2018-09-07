from flask import Flask
from flask import request, abort, jsonify
import json

from .analyzerFunctions import analyze_ip, analyze_domain
from .analyzer.abstractAnalyzer import Analyzer
from .analyzer.exceptions import DomainNotFoundException, IPNotFoundException
ws = Flask("ipanalyzer")

@ws.route("/")          # quitar cuando pongo el codigo
@ws.route("/analyze")
@ws.route("/analyze/")
@ws.route("/analyze/<analyzer>")
@ws.route("/analyze/<analyzer>/")
def ip_analyze(analyzer = None):
    try:
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
    except DomainNotFoundException as ex:
        return abort(404, "Domain not found: "+ str(ex))
    except IPNotFoundException as ex:
        return abort(404, "IP not found: "+ str(ex))

if __name__ == "__main__":
    ws.debug = True
    ws.run()
