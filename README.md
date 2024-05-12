# Toofan - Automated Basic Static Analysis Tool
## Overview
Toofan is a command-line interface (CLI) tool for analyzing files to identify potential malware and other anomalies within different file types. It integrates multiple analysis techniques and can export results in HTML, CSV, or JSON formats. The tool is built on Python and leverages the Typer library for CLI operations.

## Installation
### Prerequisites
* Python 3.6 or higher
* Pip package manager

### Setup
Clone the repository or download the source code:

```
git clone https://github.com/your-username/toofan.git
cd toofan
```

Install the required dependencies:

```
pip install -r requirements.txt
```

## Usage
### Basic Command
To perform an analysis on a file, you can use the following command syntax:

```
python main.py analyze --file [file_path] --output [output_path] --html|--csv|--json
```
* [file_path] is the path to the file you want to analyze.
* [output_path] is the path where the report will be saved.
* Flags --html, --csv, and --json determine the output format. At least one must be specified.

### Examples
Analyze a file and export the results as an HTML report:

```
python main.py analyze --file example.pdf --output report.html --html
```
Export the results as a CSV file:


```
python main.py analyze --file example.zip --output report.csv --csv
```
Generate a JSON report:

```
python main.py analyze --file example.docx --output result.json --json
```

## Features
* Multiple File Support: Supports analysis of various file types including PDFs, Office documents, and executable files.
* Flexible Export Options: Results can be exported in HTML, CSV, or JSON formats.
* Integrated Analysis: Uses a factory pattern to select the appropriate analyzer based on the file type, facilitating extended support for new file types.

## Contributing
Contributions to Toofan are welcome! Please fork the repository and submit a pull request with your proposed changes. Ensure that your code adheres to the project's code style and quality standards.

## License
Toofan is distributed under the MIT License, allowing you to use, modify, and distribute the tool freely.
Feel free to customize the README according to your project's specific needs and repository details!