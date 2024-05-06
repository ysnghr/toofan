"""
This module contains tests for the ZipAnalyzer class.
"""
import pytest
from file_management.file_manager import FileManager
from analyzers.zip_analyzer import ZipAnalyzer


class TestZipAnalyzer:
    """Test class for the ZipAnalyzer class."""
    @pytest.fixture
    def file_manager(self):
        """Fixture for creating a FileManager instance."""
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
        """
        Test password protection detection for compressed files.

        This test verifies that the ZipAnalyzer correctly detects password protection
        for various compressed file formats.

        Args:
            file_manager (FileManager): An instance of the FileManager class.
            file_name (str): The name of the compressed file to test.
            expected_result (bool): The expected result of password protection detection.
        """
        file_path = f"tests/resources/compressed-files/{file_name}"
        file_type = file_manager.identify_file_type(file_path).split('/')[1]
        analyzer = ZipAnalyzer(file_type)
        result = analyzer.analyze(file_path)
        assert result["password_protected"] == expected_result, f"Failed for {file_name}"
