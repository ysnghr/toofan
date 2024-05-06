from analyzers.pdf_analyzer import PDFAnalyzer
from analyzers.zip_analyzer import ZipAnalyzer
from analyzers.general_analyzer import GeneralAnalyzer


class AnalyzerFactory:
    def get_analyzer(self, file_type):
        if file_type == 'PDF':
            return PDFAnalyzer()
        elif file_type == 'ZIP':
            return ZipAnalyzer()
        else:
            return GeneralAnalyzer()
