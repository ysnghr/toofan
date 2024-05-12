# pylint:disable=too-few-public-methods
"""
This module defines a class for analyzing compressed files (ZIP, RAR, 7Z).
"""
import zipfile
import rarfile
import py7zr

from analyzers import FileAnalyzer
from analyzers.vt_analyzer import VirusTotalAnalyzer


class ZipAnalyzer(VirusTotalAnalyzer, FileAnalyzer):
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

    def analyze(self, file, file_type):
        """
        Analyze the given compressed file.

        This method determines if the compressed file is password-protected
        and provides information about its encryption status.

        Args:
            file (str): The path to the compressed file to be analyzed.
            file_type (str): The type of the compressed file

        Returns:
            dict: A dictionary containing information about the compressed file,
                  including its type and encryption status.
        """
        vt_results = self.analyze_vt_report(file)
        results = {
            'file_true_type': self.file_type
        }
        if 'zip' in self.file_type:
            results = self._check_zip_encryption(file)
        elif 'x-rar' in self.file_type:
            results = self._check_rar_encryption(file)
        elif 'x-7z-compressed' in self.file_type:
            results = self._check_7z_encryption(file)
        results.update(vt_results)
        return results

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
