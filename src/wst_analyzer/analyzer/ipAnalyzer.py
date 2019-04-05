from .abstractAnalyzer import Analyzer
from .scanTools import ScanTools

class IPAnalyzer(Analyzer):

    def __init__(self, ip, *args):
        self.ip = ip
        super(IPAnalyzer, self).__init__(*args)

    def analyze(self):
        if not self.all:
            self.analyze_opts = [
                elem for elem in self.options_enabled if elem in self.analyzers]
        else:
            self.analyze_opts = self.analyzers

        for analyzer in self.analyze_opts:
            if analyzer == "shodan":
                self.results['shodan'] = ScanTools.shodan(
                    self.TOKENS["shodan"], ip=self.ip)
            elif analyzer == "whois":
                self.results['whois'] = ScanTools.whois(ip=self.ip)
            elif analyzer == "otx":
                self.results['otx'] = ScanTools.otx(
                    self.TOKENS["otx"], ip=self.ip)

    def report(self):
        return self.results
