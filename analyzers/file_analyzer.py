# pylint:disable=too-few-public-methods
"""
This module defines an abstract class for file analysis.
"""
from abc import ABC, abstractmethod


class FileAnalyzer(ABC):
    """
    This class defines a blueprint for analyzing files. Subclasses should
    implement the `analyze` method to perform specific analysis on the file.
    """
    @abstractmethod
    def analyze(self, file, file_type):
        """
        Analyze the given file.

        Args:
            file (str): The path to the file to be analyzed.
            file_type (str): The type of file to be analyzed

        Raises:
            NotImplementedError: If the method is not implemented in subclasses.
        """
