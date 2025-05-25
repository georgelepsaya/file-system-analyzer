import os
import stat

import file_system_analyzer.models.file_system_analyzer as fs


def test_file_metadata_dataclass(tmp_path) -> None:
    txt = tmp_path / "hello.txt"
    txt.write_text("hello")
    st = txt.stat()

    meta = fs.FileMetadata(txt, st.st_size, st.st_mode)

    assert meta.path == txt
    assert meta.size == 5
    assert meta.converted_size == "5 B"
    assert meta.processed_permissions == fs.get_permissions(st.st_mode)
    assert meta.unusual_permissions == fs.detect_unusual_permissions(st.st_mode)


def test_category_files_dataclass():
    cat = fs.CategoryFiles(size=2048)
    assert cat.converted_size == "2 KiB"
    assert cat.files == []


def test_file_system_analyzer_class(tmp_path):
    threshold = 4096
    small = tmp_path / "small.txt"
    small.write_text("some content here")

    sub = tmp_path / "sub"
    sub.mkdir()

    big = sub / "big.bin"
    big.write_bytes(b"\x00" * (threshold + 1))
    os.chmod(big, stat.S_IWOTH | stat.S_IRUSR)

    fsa = fs.FileSystemAnalyzer(tmp_path, threshold)
    fsa.categorize_files()

    result = fsa.files_by_category

    assert set(result.keys()) == {"text", "executable"}
    assert len(result["text"].files) == 1
    assert result["text"].files[0].path == str(small)
    assert len(result["executable"].files) == 1
    assert result["executable"].files[0].path == str(big)
    assert result["text"].size == small.stat().st_size
    assert result["executable"].size == big.stat().st_size
    assert fsa.large_files == {str(big): result["executable"].files[0].converted_size}
    assert fsa.unusual_permissions_files == {str(big): ["world-writable"]}
    assert any(f.path == str(big) for f in result["executable"].files)