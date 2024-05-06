# pylint:disable=too-few-public-methods
"""
This module defines a PDF file analyzer class.
"""
from analyzers.file_analyzer import FileAnalyzer


class PDFAnalyzer(FileAnalyzer):
    """
    Class for analyzing PDF files.

    This class extends the abstract FileAnalyzer class and implements
    the analyze method for PDF files.
    """
    def analyze(self, file):
        """
        Analyze the given PDF file.

        Args:
            file (str): The path to the PDF file to be analyzed.
        """
