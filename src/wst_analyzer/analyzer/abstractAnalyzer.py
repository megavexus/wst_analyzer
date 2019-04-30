import configparser
import os
import logging
FORMAT = "%(asctime)-15s %(clientip)s %(user)-8s %(message)s"
logging.basicConfig(format=FORMAT)

class Analyzer:
    analyzers = [
        'all',
        "shodan",
        "whois",
        "otx"
    ]
    logger = logging.getLogger() 

    def __init__(self, *args):
        if args is None or not len(args) or args[0] == 'all':
            self.all = True
        else:
            self.all = False
            self.options_enabled = [elem for elem in args]

        # Cogemos las variables de configuracion
        settings = configparser.ConfigParser()
        # rutas absolutas desde el propio fichero
        dirname = os.path.dirname(os.path.abspath(__file__))
        settings.read(os.path.join(dirname, "../..", 'tokens.conf'))
        self.TOKENS = settings._sections['Tokens']
        self.results = {}

    def analyze(self):
        raise NotImplementedError("No implementado")

    def report(self):
        raise NotImplementedError("No implementado")
