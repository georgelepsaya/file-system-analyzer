from rich.table import Table
from rich.panel import Panel
import re


SIZE_MULTIPLIERS = {
    "B": 1,
    "KiB": 1024,
    "MiB": 1024 ** 2,
    "GiB": 1024 ** 3,
    "TiB": 1024 ** 4,
    "PiB": 1024 ** 5
}


def create_table():
    table = Table()
    table.add_column("Size", justify="left", no_wrap=True, header_style="bold blue")
    table.add_column("File path", justify="left", header_style="bold blue")
    table.add_column("Permissions", justify="left", header_style="bold blue")
    return table


def parse_permissions(permissions, is_unusual):
    permissions_text = ""
    for cat, rights in permissions.items():
        permissions_text += cat + ":" + "".join([k for k,v in rights.items() if v]) + " "
    permissions_text.format(permissions_text)
    if is_unusual:
        return f"[red]{permissions_text}(unusual permissions)[/red]"
    return permissions_text


def parse_output(console, output, large_files, unusual_permissions_files):
    for file_type, files in output.items():
        if len(files['files']) == 0:
            continue
        category_text = f"{file_type.capitalize()} - {files['converted_size']}"
        console.print(Panel(category_text, expand=True), style="medium_turquoise")
        table = create_table()
        if files['files']:
            for file in files["files"]:
                size_text = f"[dim]{file['size']}[/dim]"
                if file['path'] in large_files:
                    path_text = f"[light_salmon3]{file['path']} (large file)[/light_salmon3]"
                else:
                    path_text = f"{file['path']}"
                permissions = parse_permissions(file['permissions'], file['path'] in unusual_permissions_files)
                table.add_row(size_text, path_text, permissions)
            console.print(table)
        else:
            console.print("No files for this category")
    if large_files:
        console.print(Panel("Large files", expand=True), style="light_salmon3")
        for i, (k, v) in enumerate(large_files.items(), start=1):
            console.print(f"{i}. {k}: [light_salmon3]{v}[/light_salmon3]", highlight=False)
    if unusual_permissions_files:
        console.print(Panel("Files with unusual permissions", expand=True), style="red")
        for i, (k, v) in enumerate(unusual_permissions_files.items(), start=1):
            console.print(f"{i}. {k}: [red]{", ".join(v)}[/red]", highlight=False)


def convert_to_bytes(size_str: str) -> int:
    size_match = re.match(r'^(\d+)(B|KiB|MiB|GiB|TiB|PiB)?$', size_str)
    if not size_match:
        raise ValueError(f"Invalid size format: {size_str}")
    number, unit = size_match.groups()
    unit = unit or 'B'
    return int(number) * SIZE_MULTIPLIERS[unit]
