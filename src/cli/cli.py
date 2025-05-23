import argparse
from file_system_analyzer.models.file_system_analyzer import FileSystemAnalyzer
from pprint import pprint
import math
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress


def create_table():
    table = Table()
    table.add_column("Size", justify="left", no_wrap=True, header_style="bold blue")
    table.add_column("File path", justify="left", header_style="bold blue")
    table.add_column("Permissions", justify="left", header_style="bold blue")
    return table


def convert_size(file_size, include_bytes=False):
    if file_size == 0:
        return "0B"
    size_units = ("B", "KB", "MB", "GB")
    i = int(math.floor(math.log(file_size, 1024)))
    p = math.pow(1024, i)
    s = round(file_size / p, 2)
    if include_bytes:
        return f"{s} {size_units[i]} ({file_size} Bytes)"
    else:
        return f"{s} {size_units[i]}"


def parse_permissions(permissions):
    permissions_text = ""
    for cat, rights in permissions.items():
        permissions_text += cat + ":" + "".join([k for k,v in rights.items() if k]) + " "
    return permissions_text


def parse_output(console, output, large_files):
    for file_type, files in output.items():
        size_total = convert_size(files['size'], include_bytes=True)
        category_text = f"{file_type.capitalize()} - {size_total}"
        console.print(Panel(category_text, expand=False), style="medium_turquoise") 
        table = create_table()
        if files['files']:
            for file in files["files"]:
                size_text = f"[dim]{convert_size(file['size'])}[/dim]"
                if file['path'] in large_files:
                    path_text = f"[red]{file['path']} (large file)[/red]"
                else:
                    path_text = f"[blue]{file['path']}[/blue]"
                permissions = parse_permissions(file['permissions'])
                table.add_row(size_text, path_text, permissions)
            console.print(table)
        else:
            console.print("No files for this category")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", help="directory to be analyzed")
    parser.add_argument("-t", "--threshold", help="size threshold to identify large files", type=int)
    args = parser.parse_args()
    console = Console()
    fsa = FileSystemAnalyzer(args.directory, args.threshold)
    with console.status("[bold]Analyzing file system...[/bold]", spinner="dots"):
        fsa.categorize_files()
    # pprint(fsa.files_by_category)
    parse_output(console, fsa.files_by_category, fsa.large_files)
    # pprint(fsa.large_files)
    # pprint(fsa.unusual_permissions_files)



