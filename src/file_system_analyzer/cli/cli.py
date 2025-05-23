import argparse
from file_system_analyzer.models.file_system_analyzer import FileSystemAnalyzer
from rich.console import Console
from .utils import parse_output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", help="directory to be analyzed")
    parser.add_argument("-t", "--threshold", help="size threshold to identify large files", type=int)
    args = parser.parse_args()
    console = Console()
    fsa = FileSystemAnalyzer(args.directory, args.threshold)
    with console.status("[bold]Categorizing files...[/bold]", spinner="dots"):
        fsa.categorize_files()
    parse_output(console, fsa.files_by_category, fsa.large_files)



