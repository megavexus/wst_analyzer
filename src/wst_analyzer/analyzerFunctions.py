from .analyzer import *

def analyze_ip(ip, analyzer, tokens_file, proxy):
    analyzer = IPAnalyzer(ip, analyzer, tokens_path=tokens_file, proxy=proxy)
    analyzer.analyze()
    return analyzer.report()

def analyze_domain(domain, analyzer, tokens_file, proxy):
    analyzer = DomainAnalyzer(domain, analyzer, tokens_path=tokens_file, proxy=proxy)
    analyzer.analyze()
    return analyzer.report()

