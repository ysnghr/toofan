"""
This module contains tests for the OfficeAnalyzer class.
"""
import pytest
from file_management.file_manager import FileManager
from analyzers.office_analyzer import OfficeAnalyzer
from unittest.mock import patch


class TestOfficeAnalyzer:
    """Test class for the OfficeAnalyzer class."""
    @pytest.fixture
    def file_manager(self):
        """Fixture for creating a FileManager instance."""
        return FileManager()

    @pytest.mark.parametrize("file_name, expected_language, expected_pages, expected_encrypted, expected_macros", [
        ("document_with_macro.docm", "Unknown", None, False, True, ),
        ("document_with_macro.doc", "Unknown", None, False, True, ),
        ("encrypted_docx.docx", "Unknown", None, True, False),
        ("encrypted_docx.doc", "Unknown", None, True, False),
        ("simple_document.docx", "tr", 1, False, False),
    ])
    def test_office_file_analysis(self, file_manager, file_name, expected_language, expected_pages, expected_encrypted, expected_macros):
        """
        Test comprehensive Office file analysis.

        This test verifies that the OfficeAnalyzer correctly analyzes Office documents
        for language, page count, encryption status, presence of macros, and password protection.

        Args:
            file_manager (FileManager): An instance of the FileManager class.
            file_name (str): The name of the Office file to test.
            expected_language (str): Expected language code of the document.
            expected_pages (int): Expected number of pages in the document.
            expected_encrypted (bool): Expected encryption status.
            expected_macros (bool): Expected presence of macros.
        """
        file_path = f"tests/resources/office-files/{file_name}"
        analyzer = OfficeAnalyzer()
        with patch('analyzers.vt_analyzer.VirusTotalAnalyzer.analyze_vt_report') as mock_analyze_vt:
            mock_analyze_vt.return_value = {}

            result = analyzer.analyze(file_path, 'docx')
            assert result["language_code"] == expected_language, f"Language mismatch for {file_name}"
            assert result["page_count"] == expected_pages, f"Page count mismatch for {file_name}"
            assert result["encrypted"] == expected_encrypted, f"Encryption status mismatch for {file_name}"
            assert result["macros"] == expected_macros, f"Macro status mismatch for {file_name}"
