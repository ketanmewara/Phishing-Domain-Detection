import requests
import socket
from cymruwhois import Client
import whois
import datetime
import dns
from dns import resolver
from googlesearch import search
from urllib.parse import urlparse, parse_qs
from tld import get_tld
import re
import ipaddress
from lib.spf import get_spf_record, check_spf
from lib.functions import *
import geoip2.database

import warnings
warnings.filterwarnings('ignore')


class feature_extraction:

    def __init__(self, url):
        self.url = url
        self.symbols = ['.','-','_','/','?','=','@','&','!',"' '",'~',',','+','∗','#','$','%']
    
    """url infomation"""
    def start_url(self):
        """Split URL into: protocol, host, path, params, query and fragment."""
        if not urlparse(self.url.strip()).scheme:
            self.url = 'http://' + self.url
        
        protocol, domain, path, params, query, fragment = urlparse(self.url.strip())

        result = {
            'url': domain + path + params + query + fragment,
            'protocol': protocol,
            'domain': domain, #host
            'path': path,
            'params': params,
            'query': query,
            'fragment': fragment
        }
        return result

    
    # def get_dict_url_info(self,url):
    #     print(url['domain'])
    
    """url based features"""
    def url_based_feature_extract(self, dict_url):
    
        url_based_counts = []
        
        url = dict_url['url']

        """number of symbols"""
        for i in self.symbols:
            # print(i)
            url_based_counts.append(url.count(i))

        """top level domain character length"""
        # try:
        #     top_level_domain = get_tld(url)
        #     url_based_counts.append(len(top_level_domain))
        # except:
        #     url_based_counts.append(0)
        qty_tld = count_tld(dict_url['url'])
        url_based_counts.append(qty_tld)

        """length of url"""
        url_based_counts.append(len(url))

        return url_based_counts
    
    """domain based features"""
    def domain_based_feature_extract(self, dict_url):
    
        domain_based_counts = []

        """number of symbols"""
        for i in self.symbols:
            # print(i)
            domain_based_counts.append(dict_url['domain'].count(i))

        """number of vowels"""
        qty_vowels = count_vowels(dict_url['url'])
        domain_based_counts.append(qty_vowels)

        """length of domain url"""
        domain_based_counts.append(len(dict_url['domain']))

        """Use of IP or not in domain"""
        # match = re.search(
        #     '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        #     '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        #     '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        #     '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', dict_url['domain'])  # Ipv6
        # if match:
        #     # print match.group()
        #     domain_based_counts.append(1)
        # else:
        #     # print 'No matching pattern found'
        #     domain_based_counts.append(0)
        
        ip_exist = valid_ip(dict_url['domain'])
        domain_based_counts.append(ip_exist)
        

        """whether the "server" or "client" keywords exist in the domain."""

        if "server" in dict_url['domain'].lower() or "client" in dict_url['domain'].lower():
            domain_based_counts.append(1)
        else:
            domain_based_counts.append(0)


        return domain_based_counts
    
    """page based features"""
    def page_based_feature_extract(self, dict_url):
    
        page_based_counts = []

        directory = dict_url['path']

        """number of symbols"""
        for i in self.symbols:
            # print(i)
            page_based_counts.append(directory.count(i))

        """length of directory"""  
        len_directory = len(directory)
        page_based_counts.append(len_directory)

        return page_based_counts
    
    """content based features"""
    def content_based_features(self, dict_url):
        
        # dict_url = start_url(url)
    
        content_based_counts = []
    
        directory = dict_url['path']
        
        file = directory.split('/')[-1]
        
        """number of symbols in file"""
        
        for i in self.symbols:
            content_based_counts.append(file.count(i))
            
        """length of file """ 
        
        len_file = len(file)
        content_based_counts.append(len_file)
        
        """parameters based features"""
    
        """number of symbols in parameters"""
        
        for i in self.symbols:
            content_based_counts.append(dict_url['query'].count(i))
        
        """number of parameters characters"""
        
        chr_len_param = len(dict_url['query'])
        content_based_counts.append(chr_len_param)
        
        """tld in parameters"""
        
        # try:
        #     tld = get_tld(parameters)
        #     content_based_counts.append(1)
        # except:
        #     content_based_counts.append(0)
        
        tld_params = check_tld(dict_url['query'])
        content_based_counts.append(tld_params)
            
        """number of parameters"""
        
        num_of_param = count_params(dict_url['query'])
        content_based_counts.append(num_of_param)
        
        """email in url"""
        
        content_based_counts.append(valid_email(dict_url['url']))
            
        """responce time"""
        
        content_based_counts.append(check_time_response(dict_url['protocol'] + '://' + dict_url['domain']))
        
        """Check if within the registered domain has SPF or not."""
        
        try:
            spf = get_spf_record(dict_url['domain'])
            if spf is not None:
                check_spf(spf, dict_url['domain'])
                content_based_counts.append(1) # True
            else:
                content_based_counts.append(0) #False
        except:
            content_based_counts.append(0)
            
        """fetch_asn_ip"""
        
        asn = get_asn_number(dict_url)
        content_based_counts.append(asn)

        """time_domain_activation"""
        try:
            domain_info = whois.whois(dict_url['domain'])
            activation_date = domain_info.creation_date
            exp_date = domain_info.expiration_date
        except:
            content_based_counts.append(0)
        
        try:
            if type(activation_date) != list:
                diff =  exp_date.date()-activation_date.date()
                content_based_counts.append(diff.days)
            else:
                diff =  exp_date[0].date()-activation_date[0].date()
                content_based_counts.append(diff.days)
                
        except:
            content_based_counts.append(0)
        
        """time_domain_expiration""" 
        
        try:
            if type(exp_date) != list:
                today = datetime.date.today()
                diff =  exp_date.date()-today
                content_based_counts.append(diff.days)
            else:
                today = datetime.date.today()
                diff =  exp_date[0].date()-today
                content_based_counts.append(diff.days)         
        except:
            content_based_counts.append(0)
        
        """number of resolved ip"""
        
        content_based_counts.append(count_ips(dict_url))
                        
        """number of name servers"""
        
        content_based_counts.append(count_name_servers(dict_url))
        
        """number of mx server"""
        
        content_based_counts.append(count_mx_servers(dict_url))
        
        """ttl"""
        
        try:
            ttl_ = dns.resolver.query(dict_url['domain'])
            content_based_counts.append(ttl_.ttl)
        except:
            content_based_counts.append(0)
            
        """check ssl"""
        
        content_based_counts.append(check_ssl(dict_url['protocol'] + '://' + dict_url['url']))
            
        """redirect"""
        
        try:
            response = requests.get(dict_url['protocol'] + '://' + dict_url['url'], timeout=3)
            if response.history:
                content_based_counts.append(len(response.history))
            else:
                content_based_counts.append(0)
        except:
            content_based_counts.append(0)
        
        """url_google_index"""
        
        try:
            site = search(dict_url['url'], 5)
            if site:
                content_based_counts.append(0)
            else:
                content_based_counts.append(1)
        except:
            content_based_counts.append(1)
        
        """domain_google_index"""
        
        try:
            site = search(dict_url['domain'], 5)
            if site:
                content_based_counts.append(0)
            else:
                content_based_counts.append(1)
        except:
            content_based_counts.append(1)
        
        
        """url_shortened"""
        shortener = check_shortener(dict_url)
        content_based_counts.append(shortener)

        return content_based_counts
    
    """get all the features"""
    @staticmethod
    def get_all_features(url_base_feature, domain_base_feature, page_base_feature, content_base_feature):
        return url_base_feature + domain_base_feature + page_base_feature + content_base_feature