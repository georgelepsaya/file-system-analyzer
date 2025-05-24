import argparse
import sys
import os

from file_system_analyzer.models.file_system_analyzer import FileSystemAnalyzer
from rich.console import Console
from .utils import parse_output, convert_to_bytes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", help="directory to be analyzed")
    parser.add_argument("-t", "--threshold", help="size threshold to identify large files", type=str)
    args = parser.parse_args()

    if not (os.path.exists(args.directory)
            and os.path.isdir(args.directory)
            and os.access(args.directory, os.R_OK | os.X_OK)):
        print(f"Invalid directory path provided: {args.directory}")
        sys.exit(1)

    try:
        threshold = convert_to_bytes(args.threshold)
    except ValueError as e:
        print("Error when parsing threshold value:", e)
        sys.exit(1)

    fsa = FileSystemAnalyzer(args.directory, threshold)

    console = Console()
    with console.status("[bold]Categorizing files...[/bold]", spinner="dots"):
        fsa.categorize_files()
    parse_output(console, fsa.get_files_by_category(), fsa.get_large_files(), fsa.get_unusual_permissions_files())



