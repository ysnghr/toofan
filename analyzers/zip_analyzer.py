import zipfile
import rarfile
import py7zr

from analyzers.file_analyzer import FileAnalyzer


class ZipAnalyzer(FileAnalyzer):
    def __init__(self, file_type):
        self.file_type = file_type

    def analyze(self, file_path):
        if self.file_type == 'zip':
            return self._check_zip_encryption(file_path)
        elif self.file_type == 'x-rar':
            return self._check_rar_encryption(file_path)
        elif self.file_type == 'x-7z-compressed':
            return self._check_7z_encryption(file_path)
        return {"file_type": self.file_type, "password_protected": None}

    def _check_zip_encryption(self, file_path):
        try:
            with zipfile.ZipFile(file_path, 'r') as zfile:
                if zfile.namelist():
                    zfile.extractall("/tmp")
            return {"file_type": "zip", "password_protected": False}
        except RuntimeError:
            return {"file_type": "zip", "password_protected": True}

    def _check_rar_encryption(self, file_path):
        with rarfile.RarFile(file_path, 'r') as rfile:
            if rfile.needs_password():
                return {"file_type": "rar", "password_protected": True}
            else:
                return {"file_type": "rar", "password_protected": False}

    def _check_7z_encryption(self, file_path):
        with py7zr.SevenZipFile(file_path, mode='r') as zfile:
            if zfile.needs_password():
                return {"file_type": "7z", "password_protected": True}
        return {"file_type": "7z", "password_protected": False}
