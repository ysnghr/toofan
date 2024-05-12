"""
This module contains tests for the PDFAnalyzer class.
"""
import pytest
from file_management.file_manager import FileManager
from analyzers.pdf_analyzer import PDFAnalyzer
from unittest.mock import patch


class TestPDFAnalyzer:
    """Test class for the PDFAnalyzer."""

    @pytest.fixture
    def file_manager(self):
        """Fixture for creating a FileManager instance."""
        return FileManager()

    @pytest.mark.parametrize("file_name, expected_results", [
        ("all-scenarious-protected.pdf", {"password_protected": True, "urls": [],
                               "ips": [],
                               "domain_names": []}),
        ("not-protected.pdf", {"password_protected": False, "urls": ['https://orcid.org/0000-0002-8514-4315',
                                                                     'www.doi.org/10.1017/pps.2021.xx',
                                                                     'https://doi.org/10.1002/andp.19053221004',
                                                                     'http://www-cs-faculty.stanford.edu/~uno/abcde.html'],
                               "ips": [],
                               "domain_names": ['www-cs-faculty.stanford.edu',
                                                'www.doi.org',
                                                'doi.org',
                                                'orcid.org',
                                                'www-cs-faculty.stanford.edu']}),
        ("all-scenarious.pdf", {"password_protected": False, "urls": [
            "http://example.com/yasin/files/123.txt",
            "http://test1.com/sec530/file/syllabus.pdf",
            "bit.ly/2wO7f5k",
            "http://sec530.com/syllabus",
            "hello.com/yasinughur",
            "http://google.net/azerbaijan",
            "http://examplebestwebsite.org",
            "https://cyberbestlessons123.net/resource",
            "https://cyberbestlessons.com/document.pdf",
            "https://secure.example.com/sec530/sabanci",
            "www.sabanci.com/sec530",
            "http://securesabanci.com/document",
            "http://www.securelesson.com",
            "cyberlesson.com",
            "http://bit.ly/xyz",
            "toofan.com/home",
            "https://toofan.org/login",
            "https://toofan.net/register",
            "http://tinyurl.com/abcd",
            "http://sub.yasinughur.com/profile",
            "http://www.ughuryasin12345.net",
            "https://www.ughuryasin123456.com",
            "http://goo.gl/abcd",
            "http://lessons.sabanciuniv.com",
            "http://sabancilessonsfree.com/resource",
            "sabanciuniv.com/page",
            "http://www.examplepage.org/test",
            "https://www.mail.net/login",
            "www.subdomain.skype.com/friends",
            "https://www.yahoo.com/search",
            "subdomain.googlesearch.com/go",
            "http://tiny.cc/abcd",
            "sub.page.com/page",
            "https://sub.loginsystem.org/login",
            "https://sub.searchfiles.net/54.pdf",
            "http://bit.do/abcd",
            "http://www.sub.azeryasin.com",
            "http://www.sub.file.net/file123",
            "https://www.sub.download.org/search?filename=1.pdf",
            "https://sub.sub.gofiles.com?file=123.pdf",
            "sub.sub.cyberfiles.com/documents",
            "http://tinyurl.com/yabcd",
            "http://www.sub.sub.ughur.net/cyber",
            "sub.sub.ughuryasin.org/files/2.pdf",
            "https://www.sub.sub.yasinughur12.com",
            "www.sub.sub.yasinughur12.com/lesson"
        ],
                                "ips": ['192.168.1.100', '10.0.0.1', '192.168.0.1', '192.168.1.1'],
                                "domain_names": ['cyberbestlessons.com', 'secure.example.com', 'toofan.org',
                                                 'sub.sub.gofiles.com', 'sabanciuniv.com', 'www.subdomain.skype.com',
                                                 'cyberlesson.com', 'www.sub.download.org', 'example.com',
                                                 'sub.sub.ughuryasin.org', 'sub.yasinughur.com',
                                                 'sabancilessonsfree.com', 'examplebestwebsite.org', 'test1.com',
                                                 'www.sub.azeryasin.com', 'sub.page.com', 'www.sub.sub.ughur.net',
                                                 'www.yahoo.com', 'www.ughuryasin123456.com', 'www.sabanci.com',
                                                 'hello.com', 'cyberbestlessons123.net', 'sub.searchfiles.net',
                                                 'www.ughuryasin12345.net', 'bit.do', 'www.mail.net', 'tinyurl.com',
                                                 'tiny.cc', 'google.net', 'toofan.com', 'bit.ly',
                                                 'sub.sub.cyberfiles.com', 'goo.gl', 'securesabanci.com',
                                                 'www.examplepage.org', 'toofan.net', 'sub.loginsystem.org',
                                                 'lessons.sabanciuniv.com', 'www.securelesson.com',
                                                 'www.sub.sub.yasinughur12.com', 'sec530.com', 'www.sub.file.net',
                                                 'subdomain.googlesearch.com']}),
    ])
    def test_pdf_analysis(self, file_manager, file_name, expected_results):
        """
        Test the analysis of PDF files for password protection and content extraction.

        This test verifies that the PDFAnalyzer correctly identifies if a PDF is password protected
        and correctly extracts URLs, IP addresses, and domain names from the PDF content.
        """
        file_path = f"tests/resources/pdf-files/{file_name}"
        analyzer = PDFAnalyzer()

        with patch('analyzers.vt_analyzer.VirusTotalAnalyzer.analyze_vt_report') as mock_analyze_vt:
            mock_analyze_vt.return_value = {}

            result = analyzer.analyze(file_path)

            assert result['password_protected'] == expected_results['password_protected'], \
                f"Password protection failed for {file_name}"
            assert all(url in expected_results['urls'] for url in result['urls']), \
                f"Some URLs were not extracted correctly for {file_name}"
            assert all(ip in expected_results['ips'] for ip in result['ips']), \
                f"Some IPs were not extracted correctly for {file_name}"
            assert all(domain in expected_results['domain_names'] for domain in result['domain_names']), \
                f"Some domain names were not extracted correctly for {file_name}"
