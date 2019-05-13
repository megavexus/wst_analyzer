from .analyzer import *

def analyze_ip(ip, analyzer, proxy):
    analyzer = IPAnalyzer(ip, analyzer, proxy=proxy)
    analyzer.analyze()
    return analyzer.report()

def analyze_domain(domain, analyzer, proxy):
    analyzer = DomainAnalyzer(domain, analyzer, proxy=proxy)
    analyzer.analyze()
    return analyzer.report()

