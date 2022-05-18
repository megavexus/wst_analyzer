from .exceptions import *
from urllib.request import ProxyHandler

import socket
from wst_analyzer.whois import whois
from wst_analyzer.whois.whois import NICClient

from ipwhois import IPWhois
from ipwhois.exceptions import HTTPLookupError

from shodan import Shodan, exception
from OTXv2 import OTXv2, IndicatorTypes

from retrying import retry
NUM_MAX_RETRY=3

class ScanTools(object):

    def __init__(self, tokens, proxy=None):
        self.tokens = tokens
        self.proxy = proxy
        if self.proxy:
            self.proxy_dict = {
                'http': proxy,
                'https': proxy,
                'ftp': proxy
            }
        else:
            self.proxy_dict = {}

        self.setup_otx()
        self.setup_shodan()
        self.setup_whois()
        
    def setup_whois(self):
        self.proxy_handler = None
        if self.proxy:
            self.proxy_handler = ProxyHandler(self.proxy_dict)

    def setup_otx(self):
        self.otx_api = None
        if self.tokens.get('otx'):
            self.otx_api = OTXv2(self.tokens.get('otx'), proxy=self.proxy)

    def setup_shodan(self):
        self.shodan_api = None
        if self.tokens.get('shodan'):
            self.shodan_api = Shodan(self.tokens.get('shodan'), proxies=self.proxy_dict)

    #@retry(stop_max_attempt_number=NUM_MAX_RETRY) 
    def whois(self, ip=None, domain=None):
        if ip==None and domain==None: 
            raise Exception("No arguments provided")

        results = {}
        if ip != None:
            try:
                ipwhois = IPWhois(
                    ip, 
                    proxy_opener=self.proxy_handler,
                    #allow_permutations=True
                )
            except (ValueError):
                raise IPNotFoundException(ip)
            try:
                results["ip"] = ipwhois.lookup_rdap()   
            except HTTPLookupError:
                pass
        if domain != None:
            try:
                results["domain"] = whois(domain, flags=NICClient.WHOIS_RECURSE)
            except socket.gaierror:
                pass
        return results

    
    #@retry(stop_max_attempt_number=NUM_MAX_RETRY) 
    def otx(self, ip=None, domain=None):
        if ip==None and domain==None: 
            raise Exception("No arguments provided")
        if self.otx_api == None:
            return {"status": "err", "reason": "No api token"}

        results = {}
        if ip != None:
            results["ip"] = self.otx_api.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        if domain != None:
            results["domain"] = self.otx_api.get_indicator_details_full(IndicatorTypes.DOMAIN, domain)
        
        return results 

    
    @retry(stop_max_attempt_number=NUM_MAX_RETRY) 
    def shodan(self, ip=None, domain=None):
        if ip==None and domain==None: 
            raise Exception("No arguments provided")
        if ip==None: 
            return {"status": "err", "reason": "No IP provided"}
        if self.shodan_api == None:
            return {"status": "err", "reason": "No api token"}
        
        try:
            host = self.shodan_api.host(ip)
            return host
        except exception.APIError as e:
            if str(e) == "No information available for that IP.":
                return str(e)
            else:
               raise          
