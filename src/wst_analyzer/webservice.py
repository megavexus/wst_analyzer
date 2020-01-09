from flask import Flask
from flask import request, abort, jsonify
import os
import json

from wst_analyzer.analyzerFunctions import analyze_ip, analyze_domain
from wst_analyzer.analyzer.abstractAnalyzer import Analyzer
from wst_analyzer.analyzer.exceptions import DomainNotFoundException, IPNotFoundException
ws = Flask("wst_analyzer")

root_dirname = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
tokensfile_path = os.path.join(root_dirname, 'tokens.conf')

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
            res = analyze_ip(ip, analyzer, tokensfile_path, proxy)
            return jsonify(res)
        elif domain:
            res = analyze_domain(domain, analyzer, tokensfile_path, proxy)
            return jsonify(res)
        else:
            return abort(418, "I don't like coffee")
    except DomainNotFoundException as ex:
        return abort(404, "Domain not found: "+ str(ex))
    except IPNotFoundException as ex:
        return abort(404, "IP not found: "+ str(ex))

if __name__ == "__main__":
    ws.debug = True
    port = os.environ.get("WST_PORT", 5000)
    ws.run(host="0.0.0.0", port=port, debug=True)
