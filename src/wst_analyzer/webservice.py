from flask import Flask
from flask import request, abort, jsonify
import os
import json

from .analyzerFunctions import analyze_ip, analyze_domain
from .analyzer.abstractAnalyzer import Analyzer
from .analyzer.exceptions import DomainNotFoundException, IPNotFoundException
ws = Flask("wst_analyzer")

@ws.route("/")          # quitar cuando pongo el codigo
@ws.route("/analyze")
@ws.route("/analyze/")
@ws.route("/analyze/<analyzer>")
@ws.route("/analyze/<analyzer>/")
def ip_analyze(analyzer = None):
    try:
        ip = request.args.get('ip')
        domain = request.args.get('domain')
        proxy = os.environ.get('http_proxy')
        if analyzer is None:
            analyzer = "all"
        elif not analyzer in Analyzer.analyzers:
            return abort(400, "Analizador invalido")

        if ip:
            res = analyze_ip(ip, analyzer, proxy)
            return jsonify(res)
        elif domain:
            res = analyze_domain(domain, analyzer, proxy)
            return jsonify(res)
        else:
            return abort(418, "I don't like coffee")
    except DomainNotFoundException as ex:
        return abort(404, "Domain not found: "+ str(ex))
    except IPNotFoundException as ex:
        return abort(404, "IP not found: "+ str(ex))

if __name__ == "__main__":
    ws.debug = True
    ws.run(host="0.0.0.0", debug=True)
