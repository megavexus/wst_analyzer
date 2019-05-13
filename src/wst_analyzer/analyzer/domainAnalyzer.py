import socket
from .abstractAnalyzer import Analyzer
from .scanTools import ScanTools
from .exceptions import *

class DomainAnalyzer(Analyzer):

    def __init__(self, domain, *args, **kwargs):
        self.domain = domain
        self.ip = None
        try:
            self.ip = socket.gethostbyname(domain)
        except socket.gaierror:
            #raise DomainNotFoundException(domain)
            pass
        super(DomainAnalyzer, self).__init__(*args, **kwargs)

    def analyze(self):
        if not self.all:
            self.analyze_opts = [
                elem for elem in self.options_enabled if elem in self.analyzers]
        else:
            self.analyze_opts = self.analyzers

        scan_tools = ScanTools(tokens=self.TOKENS, proxy=self.proxy)
        for analyzer in self.analyze_opts:
            if analyzer == "shodan":
                self.results['shodan'] = scan_tools.shodan(ip=self.ip, domain=self.domain)
            elif analyzer == "whois":
                self.results['whois'] = scan_tools.whois(ip=self.ip, domain=self.domain)
            elif analyzer == "otx":
                self.results['otx'] = scan_tools.otx(ip=self.ip, domain=self.domain)

    def report(self):
        return self.results
