import os
import stat
import magic
from pprint import pprint


class FileSystemAnalyzer:
    
    def __init__(self, dir_path, threshold):
        self.dir_path = dir_path
        self.threshold = threshold
        self.files_by_category = {
            "text": [],
            "image": [],
            "audio": [],
            "video": [],
            "executable": [],
            "document": [],
            "empty": [],
            "unknown": []
        }
        self.large_files = []
        self.unusual_permissions_files = []
    

    def categorize_files(self):
        self._traverse_directory(self.dir_path)
        
    
    def _traverse_directory(self, path):
        for entry in os.scandir(path):
            if entry.is_file():
                file_metadata = entry.stat()
                file_path = entry.path
                permissions = self._get_permissions(file_metadata.st_mode)
                file_size = file_metadata.st_size
                
                if entry.is_symlink():
                    continue
                
                if permissions['oth']['w']:
                    self.unusual_permissions_files.append(file_path)
                
                if file_size > self.threshold:
                    self.large_files.append(file_path)
                
                magic_type = magic.from_file(file_path)

                inferred_type = "unknown"
                if "text" in magic_type:
                    inferred_type = "text"
                elif "image" in magic_type:
                    inferred_type = "image"
                elif "audio" in magic_type:
                    inferred_type = "audio"
                elif "video" in magic_type:
                    inferred_type = "video"
                elif "executable" in magic_type:
                    inferred_type = "executable"
                elif "document" in magic_type:
                    inferred_type = "document"
                elif "empty" in magic_type:
                    inferred_type = "empty"
                
                self.files_by_category[inferred_type].append({
                    "path": file_path,
                    "size": file_size,
                    "permissions": permissions})
            else:
                self._traverse_directory(entry.path)
    
    
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
    

fsa = FileSystemAnalyzer("sandbox", 20000)

fsa.categorize_files()

pprint(fsa.files_by_category)

pprint(fsa.large_files)

pprint(fsa.unusual_permissions_files)
