import typer
from analyzers.toofan_analyzer import TooFanAnalyzer
from exporters import CsvExporter, HtmlExporter, JsonExporter

app = typer.Typer()


@app.command()
def analyze(file: str, output: str, html: bool = False, csv: bool = False, json: bool = False):
    analyzer = TooFanAnalyzer()
    files_to_analyze = [file]
    results = analyzer.analyze_files(files_to_analyze)

    if html:
        if not output:
            raise typer.Exit("Output path must be provided for export.")
        HtmlExporter().export(results[0], file, output)
        typer.echo(f"Analysis report exported to HTML at {output}")
    elif csv:
        if not output:
            raise typer.Exit("Output path must be provided for export.")
        CsvExporter().export(results[0], file, output)
        typer.echo(f"Analysis report exported to CSV at {output}")
    elif json:
        if not output:
            raise typer.Exit("Output path must be provided for export.")
        JsonExporter().export(results[0], file, output)
    else:
        print(results)


if __name__ == "__main__":
    app()
