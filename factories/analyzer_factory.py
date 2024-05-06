# pylint:disable=too-few-public-methods
"""
This module provides a factory class for creating file analyzers based on the file type.
"""
from analyzers.pdf_analyzer import PDFAnalyzer
from analyzers.zip_analyzer import ZipAnalyzer
from analyzers.general_analyzer import GeneralAnalyzer


class AnalyzerFactory:
    """
    Factory class for creating file analyzers based on the file type.

    This class provides a method to create an appropriate file analyzer object
    based on the given file type.
    """
    def get_analyzer(self, file_type):
        """
        Get an appropriate file analyzer based on the file type.

        Args:
            file_type (str): The type of the file to be analyzed.

        Returns:
            FileAnalyzer: An instance of the appropriate file analyzer subclass.
        """
        if file_type == 'PDF':
            return PDFAnalyzer()
        if file_type == 'ZIP':
            return ZipAnalyzer()
        return GeneralAnalyzer()
