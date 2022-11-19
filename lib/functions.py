import re
import requests
from urllib.parse import urlparse, parse_qs
import geoip2.database

def count_vowels(text):
    """Return the number of vowels."""
    vowels = ['a', 'e', 'i', 'o', 'u']
    count = 0
    for i in vowels:
        count += text.lower().count(i)
    return count

def count_params(text):
    """Return number of parameters."""
    return len(parse_qs(text))

# def valid_spf(domain):
#     """Check if within the registered domain has SPF and if it is valid."""
#     spf = get_spf_record(domain)
#     if spf is not None:
#         check_spf(spf, domain)
#         return 1
#     return 0

def get_asn_number(url):
    """Return the ANS number associated with the IP."""
    try:
        with geoip2.database.Reader('Phishing-Domain-Detectio/lib/GeoLite2-ASN.mmdb') as reader:
            if valid_ip(url['domain']):
                ip = url['domain']
            else:
                ip = resolver.query(url['domain'], 'A')
                ip = ip[0].to_text()

            if ip:
                response = reader.asn(ip)
                return response.autonomous_system_number
            else:
                return 0
    except Exception:
        return 0

def check_shortener(url):
    """Check if the domain is a shortener."""
    file = open('Phishing-Domain-Detection/lib/shorteners.txt', 'r')
    for line in file:
        with_www = "www." + line.strip()
        if line.strip() == url['domain'].lower() or with_www == url['domain'].lower():
            file.close()
            return 1
    file.close()
    return 0

def check_tld(text):
    """Check for presence of Top-Level Domains (TLD)."""
    file = open('Phishing-Domain-Detection/lib/tlds.txt', 'r')
    pattern = re.compile("[a-zA-Z0-9.]")
    for line in file:
        i = (text.lower().strip()).find(line.strip())
        while i > -1:
            if ((i + len(line) - 1) >= len(text)) or not pattern.match(text[i + len(line) - 1]):
                file.close()
                return 1
            i = text.find(line.strip(), i + 1)
    file.close()
    return 0

def count_tld(text):
    """Return amount of Top-Level Domains (TLD) present in the URL."""
    file = open('Phishing-Domain-Detection/lib/tlds.txt', 'r')
    count = 0
    pattern = re.compile("[a-zA-Z0-9.]")
    for line in file:
        i = (text.lower().strip()).find(line.strip())
        while i > -1:
            if ((i + len(line) - 1) >= len(text)) or not pattern.match(text[i + len(line) - 1]):
                count += 1
            i = text.find(line.strip(), i + 1)
    file.close()
    return count

def valid_email(url):
    """Return if there is an email in the text."""
    if re.findall(r'[\w\.-]+@[\w\.-]+', url):
        return 1
    else:
        return 0
    
def check_ssl(url):
    """Check if the ssl certificate is valid."""
    try:
        requests.get(url, verify=True, timeout=3)
        return 1
    except Exception:
        return 0

def valid_ip(host):
    """Return if the domain has a valid IP format (IPv4 or IPv6)."""
    try:
        ipaddress.ip_address(host['domain'])
        return 1
    except Exception:
        return 0

def count_ips(url):
    """Return the number of resolved IPs (IPv4)."""
    if valid_ip(url['domain']):
        return 1

    try:
        answers = resolver.query(url['domain'], 'A')
        return len(answers)
    except Exception:
        return 0
    

def count_name_servers(url):
    """Return number of NameServers (NS) resolved."""
    count = 0
    if count_ips(url):
        try:
            answers = resolver.query(url['domain'], 'NS')
            return len(answers)
        except (resolver.NoAnswer, resolver.NXDOMAIN):
            split_host = url['domain'].split('.')
            while len(split_host) > 0:
                split_host.pop(0)
                supposed_domain = '.'.join(split_host)
                try:
                    answers = resolver.query(supposed_domain, 'NS')
                    count = len(answers)
                    break
                except Exception:
                    count = 0
        except Exception:
            count = 0
    return count


def count_mx_servers(url):
    """Return Number of Resolved MX Servers."""
    count = 0
    if count_ips(url):
        try:
            answers = resolver.query(url['domain'], 'MX')
            return len(answers)
        except (resolver.NoAnswer, resolver.NXDOMAIN):
            split_host = url['domain'].split('.')
            while len(split_host) > 0:
                split_host.pop(0)
                supposed_domain = '.'.join(split_host)
                try:
                    answers = resolver.query(supposed_domain, 'MX')
                    count = len(answers)
                    break
                except Exception:
                    count = 0
        except Exception:
            count = 0
    return count
    
    
def check_time_response(domain):
    """Return the response time in seconds."""
    try:
        latency = requests.get(domain, headers={'Cache-Control': 'no-cache'}).elapsed.microseconds * .000001
        return latency
    except Exception as e:
        return 1.000000