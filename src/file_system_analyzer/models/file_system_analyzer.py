import os
from .utils import get_permissions, infer_file_type_magic, infer_file_type_extension

try:
    import magic
except ImportError as e:
    magic = None


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
        self._files_by_category: dict[str, dict] = {
            "text": {"size": 0, "files": []},
            "image": {"size": 0, "files": []},
            "audio": {"size": 0, "files": []},
            "video": {"size": 0, "files": []},
            "document": {"size": 0, "files": []},
            "presentation": {"size": 0, "files": []},
            "spreadsheet": {"size": 0, "files": []},
            "executable": {"size": 0, "files": []},
            "archive": {"size": 0, "files": []},
            "other": {"size": 0, "files": []}
        }
        self._large_files: list[tuple[os.PathLike, int]] = []
        self._unusual_permissions_files: list[tuple[os.PathLike, str]] = []
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

    def get_files_by_category(self):
        return self._files_by_category

    def get_large_files(self):
        return self._large_files

    def get_unusual_permissions_files(self):
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

                file_metadata = entry.stat()
                file_path = entry.path
                permissions = get_permissions(file_metadata.st_mode)
                file_size = file_metadata.st_size
                
                if permissions['oth']['w']:
                    self._unusual_permissions_files.append(file_path)
                
                if file_size > self.threshold:
                    self._large_files.append(file_path)

                if self._magic_available is not None:
                    inferred_type = infer_file_type_magic(file_path)
                else:
                    inferred_type = infer_file_type_extension(file_path)

                self._files_by_category[inferred_type]["files"].append({
                    "path": file_path,
                    "size": file_size,
                    "permissions": permissions})
                
                self._files_by_category[inferred_type]["size"] += file_size
            else:
                self._traverse_directory(entry.path)
