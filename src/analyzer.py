import configparser

import logging
FORMAT = "%(asctime)-15s %(clientip)s %(user)-8s %(message)s"
logging.basicConfig(format=FORMAT)

def analyze_ip(ip):
    analyzer = IP(ip)
    analyzer.analyze()
    return analyzer.report()


def analyze_domain(domain):
    return "TU DOMINIO ES %s" % domain

class Analyzer:
    def __init__(self, *args):
        if args is not None or not len(args):
            self.all = True
        else:
            self.all = False
            self.options_enabled = args

        # Cogemos las variables de configuracion
        settings = configparser.ConfigParser()
        settings.read('tokens.conf')
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


class IP(Analyzer):
    def __init__(self, ip, *args):
        self.ip = ip
        super(IP, self).__init__(args)
        self.analyzers = [
            "shodan"
        ]


    def analyze(self):
        if not self.all:
            self.analyze_opts = [elem for elem in self.options_enabled if elem in self.analyzers]
        else:
            self.analyze_opts = self.analyzers

        for analyzer in self.analyze_opts:
            if analyzer == "shodan":
                self.analyze_shodan()


    def report(self):
        return self.host



    def analyze_shodan(self):

        from shodan import Shodan
        try:
            shodan_api = Shodan(self.TOKENS["shodan"])
        except Exception as e:
            print("Ups! Ha ocurrido un error: %s" % e)

        # Lookup the host
        host = shodan_api.host(self.ip)
        self.host = host

