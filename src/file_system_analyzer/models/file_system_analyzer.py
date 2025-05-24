import os
from collections import defaultdict
from dataclasses import dataclass, field

from .utils import get_permissions, infer_file_type_magic, infer_file_type_extension, detect_unusual_permissions, convert_size

try:
    import magic
except ImportError as e:
    magic = None


@dataclass
class FileMetadata:
    path: os.PathLike
    size: int
    permissions: int

    @property
    def processed_permissions(self) -> dict:
        return get_permissions(self.permissions)

    @property
    def unusual_permissions(self) -> list[str]:
        return detect_unusual_permissions(self.permissions)

    @property
    def converted_size(self) -> str:
        return convert_size(self.size)


@dataclass
class CategoryFiles:
    size: int = 0
    files: list[FileMetadata] = field(default_factory=list)

    @property
    def converted_size(self) -> str:
        return convert_size(self.size)



class FileSystemAnalyzer:
    """
    Class for file system analysis.

    Attributes:
        dir_path : os.PathLike
            Path to the directory to traverse and categorize
        threshold : int
            Threshold which determines which files are large
        _files_by_category : dict[str, dict]
            Map of categories to their files and total size
        _large_files : list[os.PathLike]
            List of paths of the large files
        _unusual_permissions_files : list[os.PathLike]
            List of paths of files with unusual permissions
        _magic_available: bool
            True if magic was imported successfully, otherwise false

    Methods:
        categorize_files():
            Calls directory traversal method on the provided dir_path
        get_files_by_category():
            Getter for _files_by_category
        get_large_files():
            Getter for _large_files
        get_unusual_permissions_files():
            Getter for _unusual_permissions_files
        _traverse_directory(path: os.PathLike):
            Recursively traverses the directory and stored necessary metadata
    """
    def __init__(self, dir_path: os.PathLike, threshold: int) -> None:
        """
        Constructs all necessary attributes for the FileSystemAnalyzer object
        :param dir_path: os.PathLike
            Path to the directory to traverse and categorize
        :param threshold: int
            Threshold which determines which files are large
        """
        self.dir_path: os.PathLike = dir_path
        self.threshold: int = threshold
        self._files_by_category = defaultdict(CategoryFiles)
        self._large_files = defaultdict(str)
        self._unusual_permissions_files = defaultdict(list)
        self._magic_available = magic is not None
        if not self._magic_available:
            print("File type inference by file signatures unavailable due to libmagic missing on the machine."
                        "File extensions will be used to categorize files instead.")

    def categorize_files(self) -> None:
        """
        Calls directory traversal method on the provided dir_path
        :return: None
        """
        self._traverse_directory(self.dir_path)

    @property
    def files_by_category(self):
        return self._files_by_category

    @property
    def large_files(self):
        return self._large_files

    @property
    def unusual_permissions_files(self):
        return self._unusual_permissions_files

    def _traverse_directory(self, path: os.PathLike) -> None:
        """
        Recursively traverses the directory and stored necessary metadata
        :param path: os.PathLike
        :return: None
        """
        for entry in os.scandir(path):
            if entry.is_file():
                if entry.is_symlink():
                    continue

                file_path = entry.path
                file_metadata = entry.stat()
                file_size = file_metadata.st_size
                file_mode = file_metadata.st_mode

                file = FileMetadata(file_path, file_size, file_mode)

                if file.unusual_permissions:
                    self._unusual_permissions_files[file_path] = file.unusual_permissions

                if file.size > self.threshold:
                    self._large_files[file_path] = file.converted_size

                if self._magic_available is not None:
                    inferred_type = infer_file_type_magic(file_path)
                else:
                    inferred_type = infer_file_type_extension(file_path)

                self._files_by_category[inferred_type].files.append(file)
                self._files_by_category[inferred_type].size += file_metadata.st_size
            else:
                self._traverse_directory(entry.path)
