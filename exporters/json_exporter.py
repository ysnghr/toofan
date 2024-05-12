import json
from .base_exporter import ReportExporter


class JsonExporter(ReportExporter):
    def export(self, result, filename, output_path):
        with open(output_path, mode='w') as file:
            json.dump(result, file, indent=4)
