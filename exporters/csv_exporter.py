import csv
from .base_exporter import ReportExporter


class CsvExporter(ReportExporter):
    def export(self, result, filename, output_path):
        with open(output_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Property', 'Analysis'])
            for key, value in result.items():
                writer.writerow([key, value])
