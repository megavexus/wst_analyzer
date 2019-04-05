from .exceptions import *
from retrying import retry

NUM_MAX_RETRY=7

class ScanTools(object):
    @staticmethod
    @retry(stop_max_attempt_number=NUM_MAX_RETRY) 
    def whois(ip=None, domain=None):
        if ip==None and domain==None: 
            raise Exception("No arguments provided")
        
        results = {}
        if ip != None:
            from ipwhois import IPWhois
            try:
                ipwhois = IPWhois(ip)
            except (ValueError):
                raise IPNotFoundException(ip)
            results["ip"] = ipwhois.lookup_rdap()   
        if domain != None:
            import whois
            results["domain"] = whois.whois(domain)
        return results

    @staticmethod
    @retry(stop_max_attempt_number=NUM_MAX_RETRY) 
    def otx(token, ip=None, domain=None):
        from OTXv2 import OTXv2, IndicatorTypes
        otx=OTXv2(token)
        if ip==None and domain==None: 
            raise Exception("No arguments provided")
        
        results = {}
        if ip != None:
            results["ip"] = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        if domain != None:
            results["domain"] = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, domain)
        
        return results 

    @staticmethod
    @retry(stop_max_attempt_number=NUM_MAX_RETRY) 
    def shodan(token, ip=None, domain=None):
        if ip==None and domain==None: 
            raise Exception("No arguments provided")
        from shodan import Shodan, exception
        try:
            shodan_api = Shodan(token)
        except Exception as e:
            print("Ups! Ha ocurrido un error: %s" % e)
        # Lookup the host
        if domain != None:
            import socket
            ip = socket.gethostbyname(domain)
        try:
            host = shodan_api.host(ip)
            return host
        except exception.APIError as e:
            if str(e) == "No information available for that IP.":
                return str(e)
            else:
               raise          