# pylint:disable=too-few-public-methods
"""
This module provides a factory class for creating file analyzers based on the file type.
"""
from analyzers import PDFAnalyzer, ZipAnalyzer, GeneralAnalyzer, OfficeAnalyzer, PEAnalyzer


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
        if file_type in ['DOC', 'DOCX']:
            return OfficeAnalyzer()
        elif file_type == 'PDF':
            return PDFAnalyzer()
        elif file_type == 'ZIP':
            return ZipAnalyzer(file_type)
        elif file_type == 'EXE':
            return PEAnalyzer()
        return GeneralAnalyzer()
