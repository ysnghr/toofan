# pylint:disable=too-few-public-methods
"""
This module provides functionality for managing files, including
identifying file types based on MIME types.
"""
import magic


class FileManager:
    """
    Class for managing files and identifying their types.

    This class provides methods for identifying the type of a file based on its MIME type.
    It uses the `magic` library to determine the MIME type of a file.

    Attributes:
        magic: An instance of the `magic.Magic` class for detecting MIME types.
        mime_to_extension (dict): A mapping of MIME types to their corresponding file extensions.
    """
    def __init__(self):
        self.magic = magic.Magic(mime=True)
        self.mime_to_extension = {
            'application/pdf': 'pdf',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
            # TODO: Add more MIME types and corresponding file extensions as needed
        }

    def identify_file_type(self, file_path):
        """
        Identify the type of the given file.

        This method detects the MIME type of the file using the `magic` library,
        then maps it to a corresponding file extension.

        Args:
            file_path (str): The path to the file to identify.

        Returns:
            str: The file extension corresponding to the detected MIME type,
            or the MIME type itself if no corresponding extension is found.
        """
        mime_type = self.magic.from_file(file_path)
        file_extension = self.mime_to_extension.get(mime_type, '')  # Get corresponding extension
        return file_extension if file_extension else mime_type
