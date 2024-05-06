"""
This module contains tests for the FileManager class.
"""
import pytest
from file_management.file_manager import FileManager


class TestFileManager:
    """Test class for the FileManager class."""
    @pytest.fixture
    def file_manager(self):
        """Fixture for creating a FileManager instance."""
        return FileManager()

    @pytest.mark.parametrize("file_name, true_format", [
        ("doc-file.sct", "msword"),
        ("jpg-file.exe", "jpeg"),
        ("pdf-file.jpeg", "pdf"),
        ("powerpoint-file.zip", "pptx"),
        ("x-docexec-file.docx", "inode/x-empty"),
    ])
    def test_true_file_format(self, file_manager, file_name, true_format):
        """
        Test the identification of true file formats.

        This test verifies that the FileManager correctly identifies the true format of files.

        Args:
            file_manager (FileManager): An instance of the FileManager class.
            file_name (str): The name of the file to test.
            true_format (str): The expected true format of the file.
        """
        file_path = f"tests/resources/true-format-files/{file_name}"
        detected_type = file_manager.identify_file_type(file_path)
        assert true_format in detected_type, \
            f"File {file_name} detected as {detected_type}, expected {true_format}"
