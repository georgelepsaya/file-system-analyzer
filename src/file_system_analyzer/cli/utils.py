from rich.table import Table
from rich.panel import Panel
import re
from typing import Dict

from ..logging_config import logger


SIZE_MULTIPLIERS = {
    "B": 1,
    "KiB": 1024,
    "MiB": 1024 ** 2,
    "GiB": 1024 ** 3,
    "TiB": 1024 ** 4,
    "PiB": 1024 ** 5
}


def validate_permissions(permissions: Dict):
    expected_structure = {
        'usr': {'r': bool, 'w': bool, 'x': bool},
        'grp': {'r': bool, 'w': bool, 'x': bool},
        'oth': {'r': bool, 'w': bool, 'x': bool}
    }

    if set(permissions.keys()) != set(expected_structure.keys()):
        return False

    for category in expected_structure:
        for permission in expected_structure[category]:
            if permission not in permissions[category]:
                return False
            if not isinstance(permissions[category][permission], bool):
                return False

    return True


def create_table() -> Table:
    table = Table()
    table.add_column("Size", justify="left", no_wrap=True, header_style="bold blue")
    table.add_column("File path", justify="left", header_style="bold blue")
    table.add_column("Permissions", justify="left", header_style="bold blue")
    return table


def parse_permissions(permissions: Dict, is_unusual: bool) -> str:
    try:
        if not isinstance(permissions, dict):
            raise ValueError("permissions must be a dictionary")
        if not validate_permissions(permissions):
            raise ValueError("permissions dictionary structure is incorrect")
        permissions_text = ""
        for cat, rights in permissions.items():
            if not isinstance(rights, dict):
                raise ValueError(f"rights for category {cat} must be a dictionary")
            permissions_text += f"{cat}:{''.join([k for k,v in rights.items() if v])} "
        permissions_text.format(permissions_text)
        if is_unusual:
            return f"[red]{permissions_text}(unusual permissions)[/red]"
        return permissions_text
    except ValueError as ve:
        logger.error(f"Value error when parsing permissions: {ve}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error converting size to bytes: {e}")
        raise


def parse_output(console, output: Dict, large_files: Dict, unusual_permissions_files: Dict):
    try:
        if not isinstance(output, dict):
            raise ValueError("output must be a dictionary")

        for file_type, files in output.items():
            if not hasattr(files, 'files') or not hasattr(files, 'converted_size'):
                raise ValueError("files must have 'files' and 'converted_size' attributes")

            if not files.files:
                continue

            category_text = f"{file_type.capitalize()} - {files.converted_size}"
            console.print(Panel(category_text, expand=True), style="medium_turquoise")
            table = create_table()

            for file in files.files:
                if not hasattr(file, 'converted_size') or not hasattr(file, 'path') or not hasattr(file, 'processed_permissions'):
                    raise ValueError("file must have 'converted_size', 'path' and 'processed_permissions' attributes")

                size_text = f"[dim]{file.converted_size}[/dim]"
                path_text = f"[light_salmon3]{file.path} (large file)[/light_salmon3]" if file.path in large_files else file.path
                permissions = parse_permissions(file.processed_permissions, file.path in unusual_permissions_files)
                table.add_row(size_text, path_text, permissions)

            console.print(table)

        if large_files:
            console.print(Panel("Large files", expand=True), style="light_salmon3")
            for i, (k, v) in enumerate(large_files.items(), start=1):
                console.print(f"{i}. {k}: [light_salmon3]{v}[/light_salmon3]", highlight=False)

        if unusual_permissions_files:
            console.print(Panel("Files with unusual permissions", expand=True), style="red")
            for i, (k, v) in enumerate(unusual_permissions_files.items(), start=1):
                console.print(f"{i}. {k}: [red]{', '.join(v)}[/red]", highlight=False)
    except ValueError as ve:
        logger.error(f"Value error when parsing output: {ve}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error when parsing output: {e}")
        raise


def convert_to_bytes(size_str: str) -> int:
    try:
        size_match = re.match(r'^(\d+)(B|KiB|MiB|GiB|TiB|PiB)?$', size_str)
        if not size_match:
            raise ValueError(f"Invalid size format: {size_str}")

        number, unit = size_match.groups()
        unit = unit or 'B'

        if unit not in SIZE_MULTIPLIERS:
            raise ValueError(f"Invalid unit: {unit}")

        return int(number) * SIZE_MULTIPLIERS[unit]
    except ValueError as ve:
        logger.error(f"Value error converting size to bytes: {ve}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error converting size to bytes: {e}")
        raise
