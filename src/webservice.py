from flask import Flask
from flask import request, abort
import json

from .analyzer import analyze_ip, analyze_domain

ws = Flask(__name__)


@ws.route("/analyze")
def ip_analyze():
    ip = request.args.get('ip')
    domain = request.args.get('domain')

    if ip:
        return analyze_ip(ip)
    elif domain:
        return analyze_domain(domain)
    else:
        return abort(418)
