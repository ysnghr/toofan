import pytest
from file_management.file_manager import FileManager
from analyzers.zip_analyzer import ZipAnalyzer


class TestZipAnalyzer:
    @pytest.fixture
    def file_manager(self):
        return FileManager()

    @pytest.mark.parametrize("file_name, expected_result", [
        ("encrypted.rar", True),
        ("encrypted.zip", True),
        ("encrypted-legacy-zip.zip", True),
        ("encrypted.7z", True),
        ("not-encrypted.rar", False),
        ("not-encrypted.7z", False),
        ("not-encrypted.zip", False),
    ])
    def test_password_protection(self, file_manager, file_name, expected_result):
        file_path = f"tests/resources/compressed-files/{file_name}"
        file_type = file_manager.identify_file_type(file_path).split('/')[1]
        analyzer = ZipAnalyzer(file_type)
        result = analyzer.analyze(file_path)
        assert result["password_protected"] == expected_result, f"Failed for {file_name}"
