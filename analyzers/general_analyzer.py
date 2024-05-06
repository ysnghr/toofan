# pylint:disable=missing-module-docstring, missing-class-docstring, too-few-public-methods
from analyzers.file_analyzer import FileAnalyzer


class GeneralAnalyzer(FileAnalyzer):
    def analyze(self, file):
        pass
