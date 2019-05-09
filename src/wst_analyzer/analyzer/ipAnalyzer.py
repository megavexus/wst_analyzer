from .abstractAnalyzer import Analyzer
from .scanTools import ScanTools

class IPAnalyzer(Analyzer):

    def __init__(self, ip, *args, **kwargs):
        self.ip = ip
        super(IPAnalyzer, self).__init__(*args, **kwargs)

    def analyze(self):
        if not self.all:
            self.analyze_opts = [
                elem for elem in self.options_enabled if elem in self.analyzers]
        else:
            self.analyze_opts = self.analyzers

        scan_tools = ScanTools(tokens=self.TOKENS, proxy=self.proxy)
        for analyzer in self.analyze_opts:
            if analyzer == "shodan":
                self.results['shodan'] = scan_tools.shodan(ip=self.ip)
            elif analyzer == "whois":
                self.results['whois'] = scan_tools.whois(ip=self.ip)
            elif analyzer == "otx":
                self.results['otx'] = scan_tools.otx(ip=self.ip)

    def report(self):
        return self.results
