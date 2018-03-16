import configparser
import os
import logging
FORMAT = "%(asctime)-15s %(clientip)s %(user)-8s %(message)s"
logging.basicConfig(format=FORMAT)

def analyze_ip(ip, analyzer):
    analyzer = IPAnalyzer(ip, analyzer)
    analyzer.analyze()
    return analyzer.report()

def analyze_domain(domain):
    return "TU DOMINIO ES %s" % domain

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


    def report(self):
        raise Exception("No implementado")



class Domain(Analyzer):

    def __init__(self, domain, *args):
        self.domain = domain
        super(Domain, self).__init__(args)

        # 1. Obtener su IP
        # 2. Si obtenemos su IP, construir objeto IP
        # 3. Inicializamos atributos
        pass


class IPAnalyzer(Analyzer):

    def __init__(self, ip, *args):
        self.ip = ip
        super(IPAnalyzer, self).__init__(*args)
        self.results = {}
        


    def analyze(self):
        if not self.all:
            self.analyze_opts = [elem for elem in self.options_enabled if elem in self.analyzers]
        else:
            self.analyze_opts = self.analyzers

        for analyzer in self.analyze_opts:
            if analyzer == "shodan":
                self.analyze_shodan()
            elif analyzer == "whois":
                self.analyze_whois()
            elif analyzer == "otx":
                self.analyze_otx()


    def report(self):
        return self.results

    def analyze_whois(self):
        from ipwhois import IPWhois
        whois = IPWhois(self.ip)
        self.results['whois'] = whois.lookup_rdap()

    def analyze_otx(self):
        from OTXv2 import OTXv2, IndicatorTypes
        self.otx=OTXv2(self.TOKENS["otx"])
        otx_results = self.otx.get_indicator_details_full(IndicatorTypes.IPv4, self.ip)
        self.results["otx"] = otx_results 

    def analyze_shodan(self):
        from shodan import Shodan
        try:
            shodan_api = Shodan(self.TOKENS["shodan"])
        except Exception as e:
            print("Ups! Ha ocurrido un error: %s" % e)

        # Lookup the host
        host = shodan_api.host(self.ip)
        self.results['shodan'] = host

