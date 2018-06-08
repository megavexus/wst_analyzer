import configparser
import os
import logging
FORMAT = "%(asctime)-15s %(clientip)s %(user)-8s %(message)s"
logging.basicConfig(format=FORMAT)

def analyze_ip(ip, analyzer):
    analyzer = IPAnalyzer(ip, analyzer)
    analyzer.analyze()
    return analyzer.report()

def analyze_domain(domain, analyzer):
    analyzer = DomainAnalyzer(domain, analyzer)
    analyzer.analyze()
    return analyzer.report()

class Analyzer:
    analyzers = [
        'all',
        "shodan",
        "whois",
        "otx"
    ]
    
    def __init__(self, *args):
        if args is None or not len(args) or args[0] == 'all':
            self.all = True
        else:
            self.all = False
            self.options_enabled = [ elem for elem in args ]

        # Cogemos las variables de configuracion
        settings = configparser.ConfigParser()
        # rutas absolutas desde el propio fichero
        dirname = os.path.dirname(os.path.abspath(__file__))
        settings.read(os.path.join(dirname, "..", 'tokens.conf'))
        self.TOKENS = settings._sections['Tokens']
        self.results = {}

    def analyze(self):
        raise NotImplementedError("No implementado")

    def report(self):
        raise NotImplementedError("No implementado")


class DomainAnalyzer(Analyzer):

    def __init__(self, domain, *args):
        self.domain = domain
        import socket
        self.ip = socket.gethostbyname(domain)
        super(DomainAnalyzer, self).__init__(*args)
    
    def analyze(self):
        if not self.all:
            self.analyze_opts = [elem for elem in self.options_enabled if elem in self.analyzers]
        else:
            self.analyze_opts = self.analyzers

        for analyzer in self.analyze_opts:
            if analyzer == "shodan":
                self.results['shodan'] = ScanTools.shodan(self.TOKENS["shodan"], domain=self.domain)
            elif analyzer == "whois":
                self.results['whois'] = ScanTools.whois(domain=self.domain)
            elif analyzer == "otx":
                self.results['otx'] = ScanTools.otx(self.TOKENS["otx"], domain=self.domain)

    def report(self):
        return self.results

class IPAnalyzer(Analyzer):

    def __init__(self, ip, *args):
        self.ip = ip
        super(IPAnalyzer, self).__init__(*args)
        
    def analyze(self):
        if not self.all:
            self.analyze_opts = [elem for elem in self.options_enabled if elem in self.analyzers]
        else:
            self.analyze_opts = self.analyzers

        for analyzer in self.analyze_opts:
            if analyzer == "shodan":
                self.results['shodan'] = ScanTools.shodan(self.TOKENS["shodan"], ip=self.ip)
            elif analyzer == "whois":
                self.results['whois'] = ScanTools.whois(ip=self.ip)
            elif analyzer == "otx":
                self.results['otx'] = ScanTools.otx(self.TOKENS["otx"], ip=self.ip)

    def report(self):
        return self.results
    
class ScanTools(object):
    @staticmethod 
    def whois(ip=None, domain=None):
        if ip==None and domain==None: 
            raise Exception("No arguments provided")
        
        results = {}
        if ip != None:
            from ipwhois import IPWhois
            ipwhois = IPWhois(target)
            results["ip"] = ipwhois.lookup_rdap()   
        if domain != None:
            import whois
            results["domain"] = whois.whois(domain)
        return results

    @staticmethod
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

