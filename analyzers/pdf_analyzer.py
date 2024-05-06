from analyzers.file_analyzer import FileAnalyzer
import PyPDF2
import tldextract
import fitz  # PyMuPDF
from tika import parser as tika_parser
import re
from urllib.parse import urlparse


class PDFAnalyzer(FileAnalyzer):
    """
    Class for analyzing PDF files.
    """
    def analyze(self, file_path):
        """
        Analyze the given PDF file.
        """
        analysis_result = {
            "file_type": "PDF",
            "password_protected": False,
            "urls": [],
            "ips": [],
            "domain_names": []
        }

        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            if pdf_reader.is_encrypted:
                try:
                    pdf_reader.decrypt('')
                    analysis_result["password_protected"] = True
                except Exception:
                    analysis_result["password_protected"] = True
                return analysis_result

            for page in pdf_reader.pages:
                if "/Annots" in page:
                    annotations = page["/Annots"]
                    urls = self.extract_urls_from_annotations(annotations)
                    analysis_result["urls"].extend(urls)

        text_mupdf = self.extract_text_mupdf(file_path)
        text_tika = self.extract_text_tika(file_path)

        combined_text = text_mupdf + text_tika
        analysis_result["ips"].extend(self.extract_ips(combined_text))
        analysis_result["ips"] = list(set(analysis_result["ips"]))
        analysis_result["domain_names"].extend(self.extract_domains(combined_text))
        analysis_result["domain_names"] = list(set(analysis_result["domain_names"]))

        text_urls = self.extract_urls_from_text(combined_text)
        validated_urls = [url for url in text_urls if self.is_valid_url(url)]
        unique_urls = list(set(analysis_result["urls"] + [url for url in validated_urls if url not in analysis_result["urls"]]))
        analysis_result["urls"] = unique_urls

        return analysis_result

    def extract_domains(self, text):
        """
        Extract domain names from the given text using all known TLDs.
        """
        domains = re.findall(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', text)
        extracted_domains = []
        for domain in domains:
            tld_info = tldextract.extract(domain)
            if tld_info.domain and tld_info.suffix:
                full_domain = '.'.join(part for part in [tld_info.subdomain, tld_info.domain, tld_info.suffix] if part)
                extracted_domains.append(full_domain)
        return list(set(extracted_domains))

    def extract_text_mupdf(self, file_path):
        """
        Extract text from PDF using PyMuPDF.
        """
        doc = fitz.open(file_path)
        text = ""
        for page in doc:
            text += page.get_text()
        doc.close()
        return text

    def extract_text_tika(self, file_path):
        """
        Extract text from PDF using Tika.
        """
        raw = tika_parser.from_file(file_path)
        return raw['content'] if raw and 'content' in raw else ""

    def extract_ips(self, text):
        """
        Extract IP addresses using a regular expression.
        """
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return re.findall(ip_pattern, text)

    def extract_urls_from_annotations(self, annotations):
        """
        Extract URLs from PDF annotations.
        """
        urls = []
        for annot in annotations:
            try:
                annot_object = annot.get_object()
                if "/A" in annot_object:
                    action = annot_object["/A"].get_object()
                    if "/URI" in action and action["/URI"] not in urls:
                        urls.append(action["/URI"])
            except Exception as e:
                print(f"Error reading annotation: {e}")
        return urls

    def is_valid_url(self, url):
        """
        Validate the given URL by checking if it's a well-formed URL, adding 'http://' if no scheme is provided.
        """
        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'http://' + url
            parsed = urlparse(url)
        return bool(parsed.scheme) and bool(parsed.netloc)

    def extract_urls_from_text(self, text):
        """
        Extract URLs from text using a regex that captures both fully qualified URLs and simplified URLs like shortened links.
        """
        url_pattern = r'\bhttps?:\/\/[^\s()<>]+(?:\([\w\d]+\)|([^[:punct:]\s]|\/))|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[^\s()<>]*)?'
        return re.findall(url_pattern, text)