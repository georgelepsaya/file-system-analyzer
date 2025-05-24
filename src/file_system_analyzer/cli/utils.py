import math
from rich.table import Table
from rich.panel import Panel


def create_table():
    table = Table()
    table.add_column("Size", justify="left", no_wrap=True, header_style="bold blue")
    table.add_column("File path", justify="left", header_style="bold blue")
    table.add_column("Permissions", justify="left", header_style="bold blue")
    return table


def convert_size(file_size: int, include_bytes=False):
    if file_size < 0:
        raise ValueError("file size must not be negative")
    if file_size == 0:
        return "0B"
    base = 1024
    size_units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    unit_index = min(int(math.floor(math.log(file_size, base))), len(size_units) - 1)
    divisor = base ** unit_index
    converted_size = file_size / divisor

    if converted_size.is_integer():
        converted_size = int(converted_size)
    else:
        converted_size = round(converted_size, 2)

    result = f"{converted_size} {size_units[unit_index]}"
    if include_bytes:
        result += f" ({file_size} Bytes)"
    return result


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
        size_total = convert_size(files['size'], include_bytes=True)
        category_text = f"{file_type.capitalize()} - {size_total}"
        console.print(Panel(category_text, expand=True), style="medium_turquoise")
        table = create_table()
        if files['files']:
            for file in files["files"]:
                size_text = f"[dim]{convert_size(file['size'])}[/dim]"
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
        for i, item in enumerate(large_files, start=1):
            console.print(f"{i}. {item}", highlight=False)
    if unusual_permissions_files:
        console.print(Panel("Files with unusual permissions", expand=True), style="red")
        for i, item in enumerate(unusual_permissions_files, start=1):
            console.print(f"{i}. {item}", highlight=False)

