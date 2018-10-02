from .abstractAnalyzer import Analyzer
from .scanTools import ScanTools
from .exceptions import *

class DomainAnalyzer(Analyzer):

    def __init__(self, domain, *args):
        self.domain = domain
        import socket
        try:
            self.ip = socket.gethostbyname(domain)
        except socket.gaierror:
            raise DomainNotFoundException(domain)
        super(DomainAnalyzer, self).__init__(*args)

    def analyze(self):
        if not self.all:
            self.analyze_opts = [
                elem for elem in self.options_enabled if elem in self.analyzers]
        else:
            self.analyze_opts = self.analyzers

        for analyzer in self.analyze_opts:
            if analyzer == "shodan":
                self.results['shodan'] = ScanTools.shodan(
                    self.TOKENS["shodan"], domain=self.domain)
            elif analyzer == "whois":
                self.results['whois'] = ScanTools.whois(domain=self.domain)
            elif analyzer == "otx":
                self.results['otx'] = ScanTools.otx(
                    self.TOKENS["otx"], domain=self.domain)

    def report(self):
        return self.results
