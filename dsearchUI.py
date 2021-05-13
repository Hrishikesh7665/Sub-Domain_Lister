#!/bin/python3 -W ignore::DeprecationWarning

import re
import sys
import os
import time
import hashlib
import random
import multiprocessing
import threading
import socket
import json
from collections import Counter
import subprocess
import dns.resolver
import requests
import urllib.parse as urlparse
import urllib.parse as urllib

from tkinter import *
from tkinter import ttk, font, messagebox
import os, signal, time

from pathlib import Path
path2 = str(Path.home())
path2 = path2+"/Domain Search Tool Output"


def resource_path():
    CurrentPath = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    spriteFolderPath = os.path.join(CurrentPath, 'Assets')
    path = os.path.join(spriteFolderPath)
    newPath = path.replace(os.sep, '/')
    return newPath+"/"
path = resource_path()



def subdomain_sorting_key(hostname):
    """Sorting key for subdomains

    This sorting key orders subdomains from the top-level domain at the right
    reading left, then moving '^' and 'www' to the top of their group. For
    example, the following list is sorted correctly:

    [
        'example.com',
        'www.example.com',
        'a.example.com',
        'www.a.example.com',
        'b.a.example.com',
        'b.example.com',
        'example.net',
        'www.example.net',
        'a.example.net',
    ]

    """
    parts = hostname.split('.')[::-1]
    if parts[-1] == 'www':
        return parts[:-1], 1
    return parts, 0


class enumeratorBase(object):
    def __init__(self, base_url, engine_name, domain, subdomains=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.domain = urlparse.urlparse(domain).netloc
        self.session = requests.Session()
        self.subdomains = []
        self.timeout = 25
        self.base_url = base_url
        self.engine_name = engine_name
        self.silent = silent
        self.verbose = verbose
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip',
        }

    def print_(self, text):
        if not self.silent:
            print(text)
        return

    def send_req(self, query, page_no=1):

        url = self.base_url.format(query=query, page_no=page_no)
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return 0
        return response.text if hasattr(response, "text") else response.content

    def check_max_subdomains(self, count):
        if self.MAX_DOMAINS == 0:
            return False
        return count >= self.MAX_DOMAINS

    def check_max_pages(self, num):
        if self.MAX_PAGES == 0:
            return False
        return num >= self.MAX_PAGES

    # override
    def extract_domains(self, resp):
        """ child class should override this function """
        return

    # override
    def check_response_errors(self, resp):
        """ child class should override this function
        The function should return True if there are no errors and False otherwise
        """
        return True

    def should_sleep(self):
        """Some enumerators require sleeping to avoid bot detections like Google enumerator"""
        return

    def generate_query(self):
        """ child class should override this function """
        return

    def get_page(self, num):
        """ child class that user different pagination counter should override this function """
        return num + 10

    def enumerate(self, altquery=False):
        flag = True
        page_no = 0
        prev_links = []
        retries = 0

        while flag:
            query = self.generate_query()
            count = query.count(self.domain)  # finding the number of subdomains found so far

            # if they we reached the maximum number of subdomains in search query
            # then we should go over the pages
            if self.check_max_subdomains(count):
                page_no = self.get_page(page_no)

            if self.check_max_pages(page_no):  # maximum pages for Google to avoid getting blocked
                return self.subdomains
            resp = self.send_req(query, page_no)

            # check if there is any error occurred
            if not self.check_response_errors(resp):
                return self.subdomains
            links = self.extract_domains(resp)

            # if the previous page hyperlinks was the similar to the current one, then maybe we have reached the last page
            if links == prev_links:
                retries += 1
                page_no = self.get_page(page_no)

        # make another retry maybe it isn't the last page
                if retries >= 3:
                    return self.subdomains

            prev_links = links
            self.should_sleep()

        return self.subdomains


class enumeratorBaseThreaded(multiprocessing.Process, enumeratorBase):
    def __init__(self, base_url, engine_name, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        enumeratorBase.__init__(self, base_url, engine_name, domain, subdomains, silent=silent, verbose=verbose)
        multiprocessing.Process.__init__(self)
        self.q = q
        return

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)


class GoogleEnum(enumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = "https://google.com/search?q={query}&btnG=Search&hl=en-US&biw=&bih=&gbv=1&start={page_no}&filter=0"
        self.engine_name = "Google"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 200
        super(GoogleEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.q = q
        return

    def extract_domains(self, resp):
        links_list = list()
        link_regex = re.compile('<cite.*?>(.*?)<\/cite>')
        try:
            links_list = link_regex.findall(resp)
            for link in links_list:
                link = re.sub('<span.*>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def check_response_errors(self, resp):
        if (type(resp) is str or type(resp) is unicode) and 'Our systems have detected unusual traffic' in resp:
            return False
        return True

    def should_sleep(self):
        time.sleep(5)
        return

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS - 2])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)
        return query


class YahooEnum(enumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = "https://search.yahoo.com/search?p={query}&b={page_no}"
        self.engine_name = "Yahoo"
        self.MAX_DOMAINS = 10
        self.MAX_PAGES = 0
        super(YahooEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.q = q
        return

    def extract_domains(self, resp):
        link_regex2 = re.compile('<span class=" fz-.*? fw-m fc-12th wr-bw.*?">(.*?)</span>')
        link_regex = re.compile('<span class="txt"><span class=" cite fw-xl fz-15px">(.*?)</span>')
        links_list = []
        try:
            links = link_regex.findall(resp)
            links2 = link_regex2.findall(resp)
            links_list = links + links2
            for link in links_list:
                link = re.sub("<(\/)?b>", "", link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list

    def should_sleep(self):
        return

    def get_page(self, num):
        return num + 10

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -domain:www.{domain} -domain:{found}'
            found = ' -domain:'.join(self.subdomains[:77])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain}".format(domain=self.domain)
        return query


class AskEnum(enumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'http://www.ask.com/web?q={query}&page={page_no}&qid=8D6EE6BF52E0C04527E51F64F22C4534&o=0&l=dir&qsrc=998&qo=pagination'
        self.engine_name = "Ask"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 0
        enumeratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.q = q
        return

    def extract_domains(self, resp):
        links_list = list()
        link_regex = re.compile('<p class="web-result-url">(.*?)</p>')
        try:
            links_list = link_regex.findall(resp)
            for link in links_list:
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list

    def get_page(self, num):
        return num + 1

    def generate_query(self):
        if self.subdomains:
            fmt = 'site:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -www.{domain}".format(domain=self.domain)

        return query


class BingEnum(enumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.bing.com/search?q={query}&go=Submit&first={page_no}'
        self.engine_name = "Bing"
        self.MAX_DOMAINS = 30
        self.MAX_PAGES = 0
        enumeratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q, silent=silent)
        self.q = q
        self.verbose = verbose
        return

    def extract_domains(self, resp):
        links_list = list()
        link_regex = re.compile('<li class="b_algo"><h2><a href="(.*?)"')
        link_regex2 = re.compile('<div class="b_title"><h2><a href="(.*?)"')
        try:
            links = link_regex.findall(resp)
            links2 = link_regex2.findall(resp)
            links_list = links + links2

            for link in links_list:
                link = re.sub('<(\/)?strong>|<span.*?>|<|>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list

    def generate_query(self):
        if self.subdomains:
            fmt = 'domain:{domain} -www.{domain} -{found}'
            found = ' -'.join(self.subdomains[:self.MAX_DOMAINS])
            query = fmt.format(domain=self.domain, found=found)
        else:
            query = "domain:{domain} -www.{domain}".format(domain=self.domain)
        return query


class BaiduEnum(enumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.baidu.com/s?pn={page_no}&wd={query}&oq={query}'
        self.engine_name = "Baidu"
        self.MAX_DOMAINS = 2
        self.MAX_PAGES = 760
        enumeratorBaseThreaded.__init__(self, base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.querydomain = self.domain
        self.q = q
        return

    def extract_domains(self, resp):
        links = list()
        found_newdomain = False
        subdomain_list = []
        link_regex = re.compile('<a.*?class="c-showurl".*?>(.*?)</a>')
        try:
            links = link_regex.findall(resp)
            for link in links:
                link = re.sub('<.*?>|>|<|&nbsp;', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain.endswith(self.domain):
                    subdomain_list.append(subdomain)
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        found_newdomain = True
                        self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        if not found_newdomain and subdomain_list:
            self.querydomain = self.findsubs(subdomain_list)
        return links

    def findsubs(self, subdomains):
        count = Counter(subdomains)
        subdomain1 = max(count, key=count.get)
        count.pop(subdomain1, "None")
        subdomain2 = max(count, key=count.get) if count else ''
        return (subdomain1, subdomain2)

    def check_response_errors(self, resp):
        return True

    def should_sleep(self):
        time.sleep(random.randint(2, 5))
        return

    def generate_query(self):
        if self.subdomains and self.querydomain != self.domain:
            found = ' -site:'.join(self.querydomain)
            query = "site:{domain} -site:www.{domain} -site:{found} ".format(domain=self.domain, found=found)
        else:
            query = "site:{domain} -site:www.{domain}".format(domain=self.domain)
        return query


class NetcraftEnum(enumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.base_url = 'https://searchdns.netcraft.com/?restriction=site+ends+with&host={domain}'
        self.engine_name = "Netcraft"
        super(NetcraftEnum, self).__init__(self.base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.q = q
        return

    def req(self, url, cookies=None):
        cookies = cookies or {}
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout, cookies=cookies)
        except Exception as e:
            self.print_(e)
            resp = None
        return resp

    def should_sleep(self):
        time.sleep(random.randint(1, 2))
        return

    def get_next(self, resp):
        link_regex = re.compile('<a.*?href="(.*?)">Next Page')
        link = link_regex.findall(resp)
        url = 'http://searchdns.netcraft.com' + link[0]
        return url

    def create_cookies(self, cookie):
        cookies = dict()
        cookies_list = cookie[0:cookie.find(';')].split("=")
        cookies[cookies_list[0]] = cookies_list[1]
        # hashlib.sha1 requires utf-8 encoded str
        cookies['netcraft_js_verification_response'] = hashlib.sha1(urllib.unquote(cookies_list[1]).encode('utf-8')).hexdigest()
        return cookies

    def get_cookies(self, headers):
        if 'set-cookie' in headers:
            cookies = self.create_cookies(headers['set-cookie'])
        else:
            cookies = {}
        return cookies

    def enumerate(self):
        start_url = self.base_url.format(domain='example.com')
        resp = self.req(start_url)
        cookies = self.get_cookies(resp.headers)
        url = self.base_url.format(domain=self.domain)
        while True:
            resp = self.get_response(self.req(url, cookies))
            self.extract_domains(resp)
            if 'Next Page' not in resp:
                return self.subdomains
                break
            url = self.get_next(resp)
            self.should_sleep()

    def extract_domains(self, resp):
        links_list = list()
        link_regex = re.compile('<a class="results-table__host" href="(.*?)"')
        try:
            links_list = link_regex.findall(resp)
            for link in links_list:
                subdomain = urlparse.urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list


class DNSdumpster(enumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://dnsdumpster.com/'
        self.live_subdomains = []
        self.engine_name = "DNSdumpster"
        self.q = q
        self.lock = None
        super(DNSdumpster, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        return

    def check_host(self, host):
        is_valid = False
        Resolver = dns.resolver.Resolver()
        Resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        self.lock.acquire()
        try:
            ip = Resolver.query(host, 'A')[0].to_text()
            if ip:
                is_valid = True
                self.live_subdomains.append(host)
        except:
            pass
        self.lock.release()
        return is_valid

    def req(self, req_method, url, params=None):
        params = params or {}
        headers = dict(self.headers)
        headers['Referee'] = 'https://dnsdumpster.com'
        try:
            if req_method == 'GET':
                resp = self.session.get(url, headers=headers, timeout=self.timeout)
            else:
                resp = self.session.post(url, data=params, headers=headers, timeout=self.timeout)
        except Exception as e:
            self.print_(e)
            resp = None
        return self.get_response(resp)

    def get_csrftoken(self, resp):
        csrf_regex = re.compile('<input type="hidden" name="csrfmiddlewaretoken" value="(.*?)">', re.S)
        token = csrf_regex.findall(resp)[0]
        return token.strip()

    def enumerate(self):
        self.lock = threading.BoundedSemaphore(value=70)
        resp = self.req('GET', self.base_url)
        token = self.get_csrftoken(resp)
        params = {'csrfmiddlewaretoken': token, 'targetip': self.domain}
        post_resp = self.req('POST', self.base_url, params)
        self.extract_domains(post_resp)
        for subdomain in self.subdomains:
            t = threading.Thread(target=self.check_host, args=(subdomain,))
            t.start()
            t.join()
        return self.live_subdomains

    def extract_domains(self, resp):
        tbl_regex = re.compile('<a name="hostanchor"><\/a>Host Records.*?<table.*?>(.*?)</table>', re.S)
        link_regex = re.compile('<td class="col-md-4">(.*?)<br>', re.S)
        links = []
        try:
            results_tbl = tbl_regex.findall(resp)[0]
        except IndexError:
            results_tbl = ''
        links_list = link_regex.findall(results_tbl)
        links = list(set(links_list))
        for link in links:
            subdomain = link.strip()
            if not subdomain.endswith(self.domain):
                continue
            if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                self.subdomains.append(subdomain.strip())
        return links


class Virustotal(enumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.virustotal.com/ui/domains/{domain}/subdomains'
        self.engine_name = "Virustotal"
        self.q = q
        super(Virustotal, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.url = self.base_url.format(domain=self.domain)
        return

    # the main send_req need to be rewritten
    def send_req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            self.print_(e)
            resp = None

        return self.get_response(resp)

    # once the send_req is rewritten we don't need to call this function, the stock one should be ok
    def enumerate(self):
        while self.url != '':
            resp = self.send_req(self.url)
            resp = json.loads(resp)
            if 'error' in resp:
                break
            if 'links' in resp and 'next' in resp['links']:
                self.url = resp['links']['next']
            else:
                self.url = ''
            self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        #resp is already parsed as json
        try:
            for i in resp['data']:
                if i['type'] == 'domain':
                    subdomain = i['id']
                    if not subdomain.endswith(self.domain):
                        continue
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        self.subdomains.append(subdomain.strip())
        except Exception:
            pass


class ThreatCrowd(enumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}'
        self.engine_name = "ThreatCrowd"
        self.q = q
        super(ThreatCrowd, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        return

    def req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None

        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            links = json.loads(resp)['subdomains']
            for link in links:
                subdomain = link.strip()
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain not in self.subdomains and subdomain != self.domain:
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            pass


class CrtSearch(enumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://crt.sh/?q=%25.{domain}'
        self.engine_name = "SSL Certificates"
        self.q = q
        super(CrtSearch, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        return

    def req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None

        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        if resp:
            self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        link_regex = re.compile('<TD>(.*?)</TD>')
        try:
            links = link_regex.findall(resp)
            for link in links:
                link = link.strip()
                subdomains = []
                if '<BR>' in link:
                    subdomains = link.split('<BR>')
                else:
                    subdomains.append(link)

                for subdomain in subdomains:
                    if not subdomain.endswith(self.domain) or '*' in subdomain:
                        continue

                    if '@' in subdomain:
                        subdomain = subdomain[subdomain.find('@')+1:]

                    if subdomain not in self.subdomains and subdomain != self.domain:
                        self.subdomains.append(subdomain.strip())
        except Exception as e:
            print(e)
            pass

class PassiveDNS(enumeratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        base_url = 'https://api.sublist3r.com/search.php?domain={domain}'
        self.engine_name = "PassiveDNS"
        self.q = q
        super(PassiveDNS, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        return

    def req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            resp = None

        return self.get_response(resp)

    def enumerate(self):
        url = self.base_url.format(domain=self.domain)
        resp = self.req(url)
        if not resp:
            return self.subdomains

        self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            subdomains = json.loads(resp)
            for subdomain in subdomains:
                if subdomain not in self.subdomains and subdomain != self.domain:
                    self.subdomains.append(subdomain.strip())
        except Exception as e:
            pass


def main(domain, log):
    silent = False
    verbose = False
    engines = None
    keep_list = set()
    search_list = set()
    d_name = domain

    subdomains_queue = multiprocessing.Manager().list()

    # Validate domain
    domain_check = re.compile("^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    if not domain_check.match(domain):
        return []

    if not domain.startswith('http://') or not domain.startswith('https://'):
        domain = 'http://' + domain

    parsed_domain = urlparse.urlparse(domain)

    supported_engines = {'baidu': BaiduEnum,
                         'yahoo': YahooEnum,
                         'google': GoogleEnum,
                         'bing': BingEnum,
                         'ask': AskEnum,
                         'netcraft': NetcraftEnum,
                         'dnsdumpster': DNSdumpster,
                         'virustotal': Virustotal,
                         'threatcrowd': ThreatCrowd,
                         'ssl': CrtSearch,
                         'passivedns': PassiveDNS
                         }

    chosenEnums = []

    if engines is None:
        chosenEnums = [
            BaiduEnum, YahooEnum, GoogleEnum, BingEnum, AskEnum,
            NetcraftEnum, DNSdumpster, Virustotal, ThreatCrowd,
            CrtSearch, PassiveDNS
        ]
    else:
        engines = engines.split(',')
        for engine in engines:
            if engine.lower() in supported_engines:
                chosenEnums.append(supported_engines[engine.lower()])

    # Start the engines enumeration
    enums = [enum(domain, [], q=subdomains_queue, silent=silent, verbose=verbose) for enum in chosenEnums]
    for enum in enums:
        enum.start()
    for enum in enums:
        enum.join()

    subdomains = set(subdomains_queue)
    for subdomain in subdomains:
        search_list.add(subdomain)


    subdomains = search_list.union(keep_list)

    if subdomains:
        subdomains = sorted(subdomains, key=subdomain_sorting_key)

    progress_Bar_Frame.destroy()
    def scan_Status ():

        if log == "Yes":
            isdir = os.path.isdir(path2)
            if isdir == False and log == "Yes":
                os.mkdir(path2)
            timestr = time.strftime("%I_%M_%S(%d %m %Y "+str(d_name)+")")
            target = open(path2+"/"+str(timestr)+".txt", 'w')
            for i in range(len(subdomains)):
                domain = subdomains[i]
                try:
                    ip = (socket.gethostbyname(domain))
                    table.insert('',END,values=[i,domain,ip,"Working"],tags=('ok',))
                    wr = str(i)+" "+str(domain)+" "+str(ip)+" [Working]\r"
                    target.write(wr)
                except:
                    table.insert('',END,values=[i,domain,"--Null--","Not Responding"],tags=('fail',))
                    wr = str(i)+str(domain)+" --Null-- [Not Responding]\r"
                    target.write(wr)
                table.yview_moveto(1)
            target.close()
            progress_Bar_Frame2.destroy()

        else:
            for i in range(len(subdomains)):
                domain = subdomains[i]
                try:
                    ip = (socket.gethostbyname(domain))
                    table.insert('',END,values=[i,domain,ip,"Working"],tags=('ok',))
                except:
                    table.insert('',END,values=[i,domain,"--Null--","Not Responding"],tags=('fail',))
                table.yview_moveto(1)
            progress_Bar_Frame2.destroy()

        b1.config(state=NORMAL,text="Reset",image=Reset_icon,compound=LEFT)




    t2= threading.Thread(target=scan_Status)

    progress_Bar_Frame2 = Frame(mainwindow,bg="white")
    label_line_progress = Label(progress_Bar_Frame2, bg=background_col)
    label_line_progress.pack(fill="x", expand=True, anchor="sw")

    line_progress = ttk.Progressbar(label_line_progress)
    line_progress.start(100)
    line_progress.pack(fill='x', expand=True, pady=10)
    progress_Bar_Frame2.place(x=692,y=410)
    t2.start()

progress_Bar_Frame = ""

def interactive():

    if b1.cget('text') == "Reset":
        b1.config(text="Start Scan",image=Search_icon,compound=LEFT)
        websiteEntry.config(state=NORMAL,fg = 'grey')
        option.config(state=NORMAL)
        logvar.set("No")
        webadd.set('Example: google.com')
        for row in table.get_children():
            table.delete(row)
        table.focus_set()
        return
    global progress_Bar_Frame
    domain = webadd.get()

    domain_check = re.compile("^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    if not domain_check.match(domain):
        messagebox.showerror('Invalid Domain!!',"Please Enter A Valid Domain")
        return

    progress_Bar_Frame = Frame(mainwindow,bg="white")
    progress_Bar_Frame.place(x=38,y=155)
    Label(progress_Bar_Frame,text="Loading....\nPlease Wait.......",font=("Copperplate Gothic Bold",12),bg="white").pack()
    Label(progress_Bar_Frame,text="   "*60,fg="white",bg="white").pack()
    label_line_progress = Label(progress_Bar_Frame, bg="#333")
    label_line_progress.pack(fill="x", expand=True, anchor="sw")

    line_progress = ttk.Progressbar(label_line_progress)
    line_progress.start(100)
    line_progress.pack(fill='x', expand=True, pady=10)
    Label(progress_Bar_Frame,text="Searching For Domain's.......",font=("Copperplate Gothic Light",10),bg="white").pack()


    log = logvar.get()
    t1 = threading.Thread(target=main,args=(domain, log))
    b1.config(state=DISABLED)
    websiteEntry.config(state=DISABLED)
    option.config(state=DISABLED)
    t1.start()


# UI----------------------

background_col = "#fff1d0"

mainwindow = Tk()
mainwindow.config(bg=background_col)

def center_window(w,h):
    ws = mainwindow.winfo_screenwidth()
    hs = mainwindow.winfo_screenheight()
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)
    mainwindow.geometry('%dx%d+%d+%d' % (w, h, x, y))

center_window(812,450)

TOPFRAME = Frame(bg=background_col)

deli = 220           # milliseconds of delay per character
svar = StringVar()
webadd = StringVar()
webadd.set("Example: google.com")
limitvar = StringVar()
limitvar.set("No Limit")
logvar = StringVar()
logvar.set("No")

labl = Label(TOPFRAME, textvariable=svar,bg="#4c4c4c",fg="white")

def shif():
    shif.msg = shif.msg[1:] + shif.msg[0]
    svar.set(shif.msg)
    TOPFRAME.after(deli, shif)

shif.msg = '                        Tool For Sub-Domain Search With IP Address Python 3.9 With Tkinter Gui For Linux                                                                            Tool For Sub-Domain Search With IP Address Python 3.9 With Tkinter Gui For Linux                                                   '
shif()
labl.pack(side=TOP,fill=BOTH)

homeLabel = Label(mainwindow, text="HR", font=("Eras Demi ITC", 10),bg="lavender blush", fg="gray17")
homeLabel.place(x=752,y=0)

def tic():
    homeLabel['text'] = time.strftime('%I:%M:%S')

tic()

def tac():
    tic()
    homeLabel.after(1000, tac)

tac()



Label(TOPFRAME,text=" ",font=("arial",3),bg=background_col).pack()

webLabel = Label(TOPFRAME,text="  Enter Website  ",font=("Arial Rounded MT Bold",12),bg=background_col)
webLabel.pack(side=LEFT)

websiteEntry = Entry(TOPFRAME,textvariable=webadd,bg="azure",fg = 'grey',font=("Segoe Print",10),width=19)
websiteEntry.pack(side=LEFT)

Label(TOPFRAME,text="        ",bg=background_col).pack(side=LEFT)


Label(TOPFRAME,text="                                                                    ",bg=background_col).pack(side=LEFT)

log_lbl = Label(TOPFRAME,text="Create Log File  ",font=("Arial Rounded MT Bold",12),bg=background_col)
log_lbl.pack(side=LEFT)

option = ttk.Combobox(TOPFRAME,width=4,textvariable = logvar,state="readonly",values= ('Yes',' No'),font=("ArialBlack",11))
option.current()
option.pack(side=LEFT)


TOPFRAME.pack(side=TOP,fill=BOTH)

table_frame = Frame(mainwindow,bg=background_col)
table_frame.pack(fill=BOTH,expand=1)

scrollbar_x = Scrollbar(table_frame,orient=HORIZONTAL)
scrollbar_y = Scrollbar(table_frame,orient=VERTICAL)



def fixed_map(option):
    return [elm for elm in style.map('Treeview', query_opt=option) if elm[:2] != ('!disabled', '!selected')]

style = ttk.Style(mainwindow)
style.theme_use("clam")
style.configure("Treeview.Heading",font=("arial",12, "bold"))
style.configure("Treeview",font=("arial",12),rowheight=25)
style.map('Treeview', foreground=fixed_map('foreground'),background=fixed_map('background'))

table = ttk.Treeview(table_frame,style = "Treeview",
            columns =("No","Domain","IP","Status"),xscrollcommand=scrollbar_x.set,
            yscrollcommand=scrollbar_y.set)

table.heading("No",text="Num.")
table.heading("Domain",text="Sub-Domain")
table.heading("IP",text="IP Address")
table.heading("Status",text="Domain Status")
table["displaycolumns"]=("No", "Domain", "IP", "Status")
table["show"] = "headings"
table.column("No",anchor='center',width=2)
table.column("Domain",anchor='center')
table.column("IP",anchor='center')
table.column("Status",anchor='center',width=40)

scrollbar_x.pack(side=BOTTOM,fill=X)
scrollbar_y.pack(side=RIGHT,fill=BOTH)

scrollbar_x.configure(command=table.xview)
scrollbar_y.configure(command=table.yview)

table.pack(fill=BOTH,expand=1)

table.tag_configure("ok",background='#00b300',foreground="white")
table.tag_configure('fail', background='#ff6a33',foreground="white")

stop = False

Search_icon = PhotoImage(file = path+'Se.png')
Reset_icon = PhotoImage(file = path+'Reset.png')


b1 = Button(mainwindow,text="Start Scan",image=Search_icon,compound=LEFT,command=interactive,font=("Lucida Bright",11),bg="snow2")
b1.pack()

Label(mainwindow,text=" ",font=("arial",1),bg=background_col).pack()

def showAbout():
    messagebox.showinfo("About","Coding By\nHrishikesh Patra\nGitHub: Hrishi7665")


def openL():
    isdir = os.path.isdir(path2)
    if isdir == True:
        subprocess.Popen(["xdg-open", path2])
    elif isdir == False:
        messagebox.showerror("Error", "Log's File Does\nNot Exits.")


def exit_fun ():
    ans = messagebox.askyesno("Exit", "Are You Sure,\nYou want to Exit ?")
    if ans == True:
        mainwindow.destroy()
        pid = os.getpid()
        os.kill(pid,signal.SIGTERM)

mainwindow.tk.call('wm', 'iconphoto', mainwindow._w, PhotoImage(file=path+'web.png'))
mainwindow.title("Domain Search Tool With GUI")
mainwindow.resizable(False,False)
mainwindow.wm_protocol ("WM_DELETE_WINDOW",exit_fun )

def on_websiteEntry_click(e):
    if webadd.get() == 'Example: google.com':
        websiteEntry.delete(0, "end")
        websiteEntry.insert(0, '')
        websiteEntry.config(fg = 'black')


def on_websiteEntry_focusout(e):
    if webadd.get () != 'Example: google.com':
        websiteEntry.config(fg = 'black')
    if webadd.get() == '':
        webadd.set('Example: google.com')
        websiteEntry.config(fg = 'grey')

websiteEntry.bind('<FocusIn>', on_websiteEntry_click)
websiteEntry.bind('<FocusOut>', on_websiteEntry_focusout)

menubar = Menu(mainwindow)

menubar.add_command(label="Open Log File's",command=openL)
menubar.add_command(label="About", command=showAbout)
menubar.add_command(label="Exit", command=exit_fun)

mainwindow.config(menu=menubar)


if __name__ == "__main__":
    import platform
    if platform.system()!="Linux":
        print("This Code Is Only For Linux Based OS")
    else:
        mainwindow.mainloop()