import argparse
import sys
import os

from file_system_analyzer.models.file_system_analyzer import FileSystemAnalyzer
from rich.console import Console
from .utils import parse_output, convert_to_bytes
from ..logging_config import logger


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", help="directory to be analyzed", required=True)
    parser.add_argument("-t", "--threshold",
                        help="size threshold to identify large files (units: B, KiB, MiB, GiB, TiB, PiB), e.g. 10MiB",
                        type=str, required=True)
    args = parser.parse_args()

    if not (os.path.exists(args.directory)
            and os.path.isdir(args.directory)
            and os.access(args.directory, os.R_OK | os.X_OK)):
        logger.error(f"Invalid directory path provided: {args.directory}")
        sys.exit(1)

    try:
        threshold = convert_to_bytes(args.threshold)
    except ValueError as e:
        logger.error(f"Error when parsing threshold value: {e}")
        sys.exit(1)

    fsa = FileSystemAnalyzer(args.directory, threshold)

    console = Console()
    with console.status("[bold]Categorizing files...[/bold]", spinner="dots"):
        try:
            fsa.categorize_files()
        except Exception as e:
            logger.error(f"Error when categorizing files: {e}")
            sys.exit(1)

    console.print("FILE SYSTEM ANALYSIS REPORT", style="bold italic", justify="center")
    parse_output(console, fsa.files_by_category, fsa.large_files, fsa.unusual_permissions_files)

if __name__ == "__main__":
    main()
