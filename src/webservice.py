from flask import Flask
from flask import request, abort, jsonify
import json

from .analyzer import analyze_ip, analyze_domain

ws = Flask("ipanalyzer")

@ws.route("/analyze")
def ip_analyze():
    ip = request.args.get('ip')
    domain = request.args.get('domain')

    if ip:
        return jsonify(analyze_ip(ip))
    elif domain:
        return analyze_domain(domain)
    else:
        return abort(418)


if __name__ == "__main__":
    ws.debug = True
    ws.run()
