import pytest
from rich.console import Console

from file_system_analyzer.cli.utils import parse_permissions, parse_output, convert_to_bytes
from file_system_analyzer.models.file_system_analyzer import FileMetadata, CategoryFiles


@pytest.fixture
def sample_output():
    file_1 = FileMetadata("path/file_1.txt", 3072, 1)
    file_2 = FileMetadata("path/file_2.txt", 2048, 1)
    category_files = CategoryFiles(5120)
    category_files.files = [file_1, file_2]
    output = {"text": category_files}
    large_files = {"path/file_1.txt": file_1.converted_size}
    unusual_permissions = {"path/file_2.txt": file_2.converted_size}
    return output, large_files, unusual_permissions


def test_parse_permissions_error():
    with pytest.raises(ValueError):
        parse_permissions("not-a-dict", is_unusual=False)

    with pytest.raises(ValueError):
        parse_permissions({"usr": {'r': True}}, is_unusual=False)


def test_parse_permissions_success():
    permissions = {'usr': {'r': True, 'w': True, 'x': False},
                   'grp': {'r': True, 'w': False, 'x': True},
                   'oth':{'r': True, 'w': False, 'x': False}}
    expected = "usr:rw grp:rx oth:r "
    result = parse_permissions(permissions, is_unusual=False)

    assert result == expected


def test_parse_output_error():
    console = Console()
    with pytest.raises(ValueError):
        parse_output(console, "not-a-dict", {}, {})


def test_parse_output_success(sample_output):
    console = Console(record=True, force_interactive=False)
    parse_output(console, sample_output[0], sample_output[1], sample_output[2])
    rendered = console.export_text()

    assert "Text - 5 KiB" in rendered
    assert "Large files" in rendered
    assert "Files with unusual permissions" in rendered


@pytest.mark.parametrize(
    "bad_input",
    [
        "10KB",
        "1.5MiB",
        "abc",
        "10ZiB",
        "",
        "1024 KiB"
    ]
)
def test_convert_to_bytes_error(bad_input):
    with pytest.raises(ValueError):
        convert_to_bytes(bad_input)

@pytest.mark.parametrize(
    "size_str, expected",
    [
        ("42", 42),
        ("10B", 10),
        ("1KiB", 1024),
        ("2MiB", 2 * 1024**2),
        ("3GiB", 3 * 1024**3),
        ("5TiB", 5 * 1024**4)
    ]
)
def test_convert_to_bytes_success(size_str, expected):
    assert convert_to_bytes(size_str) == expected


