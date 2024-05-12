# pylint:disable=too-few-public-methods
"""
This module contains the TooFanAnalyzer class for analyzing
files using different analyzers.
"""
from file_management.file_manager import FileManager
from factories.analyzer_factory import AnalyzerFactory


class TooFanAnalyzer:
    """This class performs analysis on files using different analyzers."""
    def __init__(self, file_manager=FileManager(), analyzer_factory=AnalyzerFactory()):
        self.file_manager = file_manager
        self.analyzer_factory = analyzer_factory

    def analyze_files(self, files):
        """
        Analyze the given files.

        Args:
            files (list): List of file paths to analyze.

        Returns:
            list: List of analysis results for each file.
        """
        results = []
        for file in files:
            file_type = self.file_manager.identify_file_type(file)
            analyzer = self.analyzer_factory.get_analyzer(file_type)
            result = analyzer.analyze(file, file_type)
            results.append(result)
        return results
