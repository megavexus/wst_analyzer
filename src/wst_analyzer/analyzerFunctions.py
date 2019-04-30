from .analyzer import *

def analyze_ip(ip, analyzer):
    analyzer = IPAnalyzer(ip, analyzer)
    analyzer.analyze()
    return analyzer.report()

def analyze_domain(domain, analyzer):
    analyzer = DomainAnalyzer(domain, analyzer)
    analyzer.analyze()
    return analyzer.report()

