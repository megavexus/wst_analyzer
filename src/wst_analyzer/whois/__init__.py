# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import division
from future import standard_library
standard_library.install_aliases()
from builtins import *
import re
import sys
import os
import subprocess
import socket
from .parser import WhoisEntry
from .whois import NICClient


# thanks to https://www.regextester.com/104038
IPV4_OR_V6 = re.compile(r"((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))")


def whois(url, command=False, flags=0):
    # clean domain to expose netloc
    ip_match = IPV4_OR_V6.match(url)
    if ip_match:
        domain = url
        try:
            result = socket.gethostbyaddr(url)
        except socket.herror as e:
            pass
        else:
            domain = extract_domain(result[0])
    else:
        domain = extract_domain(url)
    if command:
        # try native whois command
        r = subprocess.Popen(['whois', domain], stdout=subprocess.PIPE)
        text = r.stdout.read().decode()
    else:
        # try builtin client
        nic_client = NICClient()
        whois_server, text_response = nic_client.whois_lookup(None, domain.encode('idna'), flags)
    response = WhoisEntry.load(domain, text_response)
    if "whois_server" not in response:
        response['whois_server'] = whois_server if whois_server else extract_whois_server(text_response)

        if not response['whois_server']:
            print(text)
    return response

def extract_whois_server(text_whois):
    import re
    pattern= r"(whois\.(?:[a-zA-Z]+\.)+[a-z]+)"
    findings = re.findall(pattern, text_whois)
    if findings:
        return findings[0]

suffixes = None
def extract_domain(url):
    """Extract the domain from the given URL

    >>> print(extract_domain('http://www.google.com.au/tos.html'))
    google.com.au
    >>> print(extract_domain('abc.def.com'))
    def.com
    >>> print(extract_domain(u'www.公司.hk'))
    公司.hk
    >>> print(extract_domain('chambagri.fr'))
    chambagri.fr
    >>> print(extract_domain('www.webscraping.com'))
    webscraping.com
    >>> print(extract_domain('198.252.206.140'))
    stackoverflow.com
    >>> print(extract_domain('102.112.2O7.net'))
    2o7.net
    >>> print(extract_domain('globoesporte.globo.com'))
    globo.com
    >>> print(extract_domain('1-0-1-1-1-0-1-1-1-1-1-1-1-.0-0-0-0-0-0-0-0-0-0-0-0-0-10-0-0-0-0-0-0-0-0-0-0-0-0-0.info'))
    0-0-0-0-0-0-0-0-0-0-0-0-0-10-0-0-0-0-0-0-0-0-0-0-0-0-0.info
    >>> print(extract_domain('2607:f8b0:4006:802::200e'))
    1e100.net
    >>> print(extract_domain('172.217.3.110'))
    1e100.net
    """
    if IPV4_OR_V6.match(url):
        # this is an IP address
        return socket.gethostbyaddr(url)[0]

    # load known TLD suffixes
    global suffixes
    if not suffixes:
        # downloaded from https://publicsuffix.org/list/public_suffix_list.dat
        tlds_path = os.path.join(os.getcwd(), os.path.dirname(__file__), 'data', 'public_suffix_list.dat')
        with open(tlds_path, encoding='utf-8') as tlds_fp:
            suffixes = set(line.encode('utf-8') for line in tlds_fp.read().splitlines() if line and not line.startswith('//'))

    if not isinstance(url, str):
        url = url.decode('utf-8')
    url = re.sub('^.*://', '', url)
    url = url.split('/')[0].lower()

    # find the longest suffix match
    domain = b''
    for section in reversed(url.split('.')):
        if domain:
            domain = b'.' + domain
        domain = section.encode('utf-8') + domain
        if domain not in suffixes:
            break
    return domain.decode('utf-8')


if __name__ == '__main__':
    try:
        url = sys.argv[1]
    except IndexError:
        print('Usage: %s url' % sys.argv[0])
    else:
        print(whois(url))