import pytest
from file_management.file_manager import FileManager


class TestFileManager:
    @pytest.fixture
    def file_manager(self):
        return FileManager()

    @pytest.mark.parametrize("file_name, true_format", [
        ("doc-file.sct", "msword"),
        ("jpg-file.exe", "jpeg"),
        ("pdf-file.jpeg", "pdf"),
        ("powerpoint-file.zip", "pptx"),
        ("x-docexec-file.docx", "inode/x-empty"),
    ])
    def test_true_file_format(self, file_manager, file_name, true_format):
        file_path = f"tests/resources/true-format-files/{file_name}"
        detected_type = file_manager.identify_file_type(file_path)
        assert true_format in detected_type, f"File {file_name} detected as {detected_type}, expected {true_format}"
