import pytest
import base64
import stat

from file_system_analyzer.models.utils import (get_permissions, infer_file_type_magic,
                                               infer_file_type_magic_raw, infer_file_type_extension, convert_size,
                                               detect_unusual_permissions)


@pytest.mark.parametrize(
    "bad_input",
    [
        "755",
        None,
        3.14
    ]
)
def test_get_permissions_error(bad_input):
    with pytest.raises(ValueError):
        get_permissions(bad_input)


@pytest.mark.parametrize(
    "mode, expected",
    [
        (
            0o754,
            {
                "usr": {"r": True, "w": True, "x": True},
                "grp": {"r": True, "w": False, "x": True},
                "oth": {"r": True, "w": False, "x": False},
            },
        ),
        (
            0o640,
            {
                "usr": {"r": True, "w": True, "x": False},
                "grp": {"r": True, "w": False, "x": False},
                "oth": {"r": False, "w": False, "x": False}
            }
        ),
        (
            0o000,
            {
                "usr": {"r": False, "w": False, "x": False},
                "grp": {"r": False, "w": False, "x": False},
                "oth": {"r": False, "w": False, "x": False}
            }
        )
    ]
)
def test_get_permissions_success(mode, expected):
    assert get_permissions(mode) == expected


@pytest.mark.skipif(
    pytest.importorskip("magic", reason="python-magic not installed") is None,
    reason="python-magic not installed",
)
def test_infer_file_type_magic_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        infer_file_type_magic(tmp_path / "missing.txt")


@pytest.mark.skipif(
    pytest.importorskip("magic", reason="python-magic not installed") is None,
    reason="python-magic not installed"
)
def test_infer_file_type_magic_success(tmp_path):
    txt = tmp_path / "example.txt"
    txt.write_text("Hello, world!\n", encoding="utf-8")

    png_data_b64 = (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4DwQA"
        "CfsD/QnYfYoAAAAASUVORK5CYII="
    )
    png = tmp_path / "pixel.png"
    png.write_bytes(base64.b64decode(png_data_b64))

    assert infer_file_type_magic(txt) == "text"
    assert infer_file_type_magic(png) == "image"


@pytest.mark.skipif(
    pytest.importorskip("magic", reason="python-magic not installed") is None,
    reason="python-magic not installed"
)
def test_infer_file_type_magic_raw_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        infer_file_type_magic_raw(tmp_path / "missing.txt")


@pytest.mark.skipif(
    pytest.importorskip("magic", reason="python-magic not installed") is None,
    reason="python-magic not installed"
)
def test_infer_file_type_magic_raw_success(tmp_path):
    txt = tmp_path / "example.txt"
    txt.write_text("Hello, world!\n", encoding="utf-8")
    assert infer_file_type_magic(txt) == "text"


def test_infer_file_type_extension_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        infer_file_type_extension(tmp_path / "missing.txt")


@pytest.mark.parametrize(
    "file_path, expected",
    [
        ("text_file.txt", "text"),
        ("image_file.png", "image"),
        ("document_file.pdf", "document"),
        ("presentation_file.pptx", "presentation"),
        ("spreadsheet_file.xls", "spreadsheet"),
        ("audio_file.mp3", "audio"),
        ("video_file.mp4", "video")
    ]
)
def test_infer_file_type_extension_success(file_path, expected, tmp_path):
    test_file = tmp_path / file_path
    test_file.touch()
    assert infer_file_type_extension(test_file) == expected


@pytest.mark.parametrize(
    "bad_input",
    [
        -1,
        3.14,
        "1000",
        None
    ]
)
def test_convert_size_error(bad_input):
    with pytest.raises(ValueError):
        convert_size(bad_input)


@pytest.mark.parametrize(
    "bytes_in, expected",
    [
        (0, "0 B"),
        (512, "512 B"),
        (1024, "1 KiB"),
        (1536, "1.5 KiB"),
        (5 * 1024**2, "5 MiB"),
        (7 * 1024**4, "7 TiB")
    ]
)
def test_convert_size_success(bytes_in, expected):
    assert convert_size(bytes_in) == expected


@pytest.mark.parametrize(
    "bad_input",
    ["755", 3.14, None, [], {}]
)
def test_detect_unusual_permissions_error(bad_input):
    with pytest.raises(ValueError):
        detect_unusual_permissions(bad_input)


@pytest.mark.parametrize(
    "mode, expected",
    [
        (0o000, []),
        (stat.S_IWOTH, ["world-writable"]),
        (stat.S_IWGRP, ["group-writable"]),
        (stat.S_IXOTH, ["world-executable"]),
        (stat.S_IXGRP, ["group-executable"]),
        (stat.S_ISUID, ["set-uid"]),
        (stat.S_ISGID, ["set-gid"]),
        (stat.S_ISVTX, ["sticky-bit"]),
        (
            stat.S_IWOTH | stat.S_IWGRP | stat.S_IXOTH |
            stat.S_IXGRP | stat.S_ISUID | stat.S_ISGID |
            stat.S_ISVTX,
            [
                "world-writable", "group-writable", "world-executable",
                "group-executable", "set-uid", "set-gid", "sticky-bit"
            ]
        )
    ]
)
def test_detect_unusual_permissions_success(mode, expected):
    assert detect_unusual_permissions(mode) == expected
