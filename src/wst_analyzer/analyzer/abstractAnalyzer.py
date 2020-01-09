import configparser
import os
import logging
FORMAT = "%(asctime)-15s %(message)s"
logging.basicConfig(format=FORMAT)

class Analyzer:
    analyzers = [
        'all',
        "shodan",
        "whois",
        "otx"
    ]
    logger = logging.getLogger() 

    def __init__(self, *args, **kwargs):
        if args is None or not len(args) or args[0] == 'all':
            self.all = True
        else:
            self.all = False
            self.options_enabled = [elem for elem in args]

        # Cogemos las variables de configuracion
        settings = configparser.ConfigParser()
        tokens_file = kwargs['tokens_path']
        settings.read(tokens_file)
        self.TOKENS = settings._sections['Tokens']
        self.proxy = kwargs.get('proxy')
        self.results = {}

    def analyze(self):
        raise NotImplementedError("No implementado")

    def report(self):
        raise NotImplementedError("No implementado")
