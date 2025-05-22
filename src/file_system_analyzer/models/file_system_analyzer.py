import os
import stat


class FileSystemAnalyzer:
    
    def __init__(self, dir_path):
        self.dir_path = dir_path
        self.files_by_category = {}
        self.large_files = []
        self.unusual_permissions_files = []
    
    
    def get_files(self):
        for file in self._traverse_directory(self.dir_path):
            print(file)
    
    
    def _traverse_directory(self, path):
        for entry in os.scandir(path):
            if entry.is_file():
                file_metadata = entry.stat()
                yield {"path": entry.path,
                       "size": file_metadata.st_size,
                       "permissions": self._get_permissions(file_metadata.st_mode)}
            else:
                yield from self._traverse_directory(entry.path)
    
    
    def _get_permissions(self, mode):
        permissions = {
            'usr': {
                'r': bool(mode & stat.S_IRUSR),
                'w': bool(mode & stat.S_IWUSR),
                'x': bool(mode & stat.S_IXUSR)
            },
            'grp': {
                'r': bool(mode & stat.S_IRGRP),
                'w': bool(mode & stat.S_IWGRP),
                'x': bool(mode & stat.S_IXGRP)
            },
            'oth': {
                'r': bool(mode & stat.S_IROTH),
                'w': bool(mode & stat.S_IWOTH),
                'x': bool(mode & stat.S_IXOTH)
            }
        }
        return permissions


fsa = FileSystemAnalyzer(".")

fsa.get_files()
