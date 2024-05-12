from jinja2 import Template
from .base_exporter import ReportExporter
from pathlib import Path


class HtmlExporter(ReportExporter):
    def export(self, results, filename, output_path):
        with open('exporters/report.html', "r") as f:
            html_template = Template(f.read())
        output_content = html_template.render(results=results, filename=filename)
        Path(output_path).write_text(output_content)
