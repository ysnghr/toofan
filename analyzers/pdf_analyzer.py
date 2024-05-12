from analyzers.file_analyzer import FileAnalyzer
import PyPDF2
import fitz  # PyMuPDF
from tika import parser as tika_parser
from utils import DataExtractor


class PDFAnalyzer(FileAnalyzer, DataExtractor):
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

        text_urls = self.extract_urls(combined_text)
        validated_urls = [url for url in text_urls if self.is_valid_url(url)]
        unique_urls = list(set(analysis_result["urls"] + [url for url in validated_urls if url not in analysis_result["urls"]]))
        analysis_result["urls"] = unique_urls

        return analysis_result

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
