# pylint:disable=too-few-public-methods
"""
This module defines a class for analyzing compressed files (ZIP, RAR, 7Z).
"""
import zipfile
import rarfile
import py7zr

from analyzers.file_analyzer import FileAnalyzer


class ZipAnalyzer(FileAnalyzer):
    """
    Class for analyzing compressed files (ZIP, RAR, 7Z).

    This class extends the abstract FileAnalyzer class and provides methods
    for analyzing compressed files including ZIP, RAR, and 7Z.

    Args:
        file_type (str): The type of the compressed file ('zip', 'x-rar', 'x-7z-compressed').
    """
    def __init__(self, file_type):
        self.file_type = file_type
        # TODO: Transfer this argument to analyze method

    def analyze(self, file):
        """
        Analyze the given compressed file.

        This method determines if the compressed file is password-protected
        and provides information about its encryption status.

        Args:
            file (str): The path to the compressed file to be analyzed.

        Returns:
            dict: A dictionary containing information about the compressed file,
                  including its type and encryption status.
        """
        if self.file_type == 'zip':
            return self._check_zip_encryption(file)
        if self.file_type == 'x-rar':
            return self._check_rar_encryption(file)
        if self.file_type == 'x-7z-compressed':
            return self._check_7z_encryption(file)
        return {"file_type": self.file_type, "password_protected": None}

    def _check_zip_encryption(self, file_path):
        """
        Check if the ZIP file is password-protected.

        Args:
            file_path (str): The path to the ZIP file.

        Returns:
            dict: A dictionary containing information about the ZIP file,
                    including its type ('zip') and password protection status.
        """
        try:
            with zipfile.ZipFile(file_path, 'r') as zfile:
                if zfile.namelist():
                    zfile.extractall("/tmp")
            return {"file_type": "zip", "password_protected": False}
        except RuntimeError:
            return {"file_type": "zip", "password_protected": True}

    def _check_rar_encryption(self, file_path):
        """
        Check if the RAR file is password-protected.

        Args:
            file_path (str): The path to the RAR file.

        Returns:
            dict: A dictionary containing information about the RAR file,
                  including its type ('rar') and password protection status.
        """
        with rarfile.RarFile(file_path, 'r') as rfile:
            if rfile.needs_password():
                return {"file_type": "rar", "password_protected": True}
            return {"file_type": "rar", "password_protected": False}

    def _check_7z_encryption(self, file_path):
        """
        Check if the 7Z file is password-protected.

        Args:
            file_path (str): The path to the 7Z file.

        Returns:
            dict: A dictionary containing information about the 7Z file,
                  including its type ('7z') and password protection status.
        """
        with py7zr.SevenZipFile(file_path, mode='r') as zfile:
            if zfile.needs_password():
                return {"file_type": "7z", "password_protected": True}
        return {"file_type": "7z", "password_protected": False}
