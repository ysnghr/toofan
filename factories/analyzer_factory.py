# pylint:disable=too-few-public-methods
"""
This module provides a factory class for creating file analyzers based on the file type.
"""
from analyzers import PDFAnalyzer, ZipAnalyzer, OfficeAnalyzer, PEAnalyzer


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
        zip_file_types = ['application/x-7z-compressed', 'application/zip', 'application/x-rar']
        if file_type in ['doc', 'docx', 'application/msword', 'application/encrypted']:
            return OfficeAnalyzer()
        elif file_type == 'pdf':
            return PDFAnalyzer()
        elif file_type in zip_file_types:
            return ZipAnalyzer(file_type)
        elif file_type == 'application/x-dosexec':
            return PEAnalyzer()
