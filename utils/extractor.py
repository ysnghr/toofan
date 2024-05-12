import re
from urllib.parse import urlparse
import tldextract


class DataExtractor:
    """Base class for data extraction methods with common utilities."""

    @staticmethod
    def is_valid_url(url):
        """Validate the given URL by checking if it's a well-formed URL, adding 'http://' if no scheme is provided."""
        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'http://' + url
            parsed = urlparse(url)
        return bool(parsed.scheme) and bool(parsed.netloc)

    @staticmethod
    def extract_domains(text):
        """Extract domain names from the given text using all known TLDs."""
        domain_pattern = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
        domains = re.findall(domain_pattern, text)
        extracted_domains = []
        for domain in domains:
            tld_info = tldextract.extract(domain)
            if tld_info.domain and tld_info.suffix:
                full_domain = '.'.join(part for part in [tld_info.subdomain, tld_info.domain, tld_info.suffix] if part)
                extracted_domains.append(full_domain)
        return list(set(extracted_domains))

    @staticmethod
    def extract_ips(text):
        """Extract IP addresses using a regular expression."""
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        return re.findall(ip_pattern, text)

    @staticmethod
    def extract_urls(text):
        """Extract URLs from text using a regex that captures both fully qualified URLs and simplified URLs like shortened links."""
        url_pattern = re.compile(
            r'\bhttps?:\/\/[^\s()<>]+(?:\([\w\d]+\)|([^[:punct:]\s]|\/))|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s()<>]*)?')
        urls = re.findall(url_pattern, text)
        return [url for url in urls if DataExtractor.is_valid_url(url)]
