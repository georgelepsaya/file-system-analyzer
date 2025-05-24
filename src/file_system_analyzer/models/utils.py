import stat
import os

from .file_type_mappings import APPLICATION_MIME_TO_CATEGORY, EXTENSION_TO_CATEGORY, TERM_PATTERN, TERM_TO_CATEGORY


# Handle the case when libmagic is not installed on a Linux machine
try:
    import magic
except ImportError as e:
    magic = None


def get_permissions(mode: int) -> dict[str, dict]:
    """
    Returns a map of rights category to its read/write/execute rights (boolean)
    by performing a bitwise AND with the specific permission codes
    :param mode: int
        stat's st_mode, which represents permissions
    :return: dict[str, dict]
        map of rights category to its read/write/execute rights (boolean)
    """
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


def infer_file_type_magic(file_path: os.PathLike) -> str:
    """
    Uses python-magic (libmagic wrapper for Python) to use file signatures to infer the file type
    :param file_path: os.PathLike
        Path to the file, type of which needs to be inferred
    :return: str
        Type inferred using libmagic
    """
    magic_type = magic.from_file(file_path, mime=True).split('/')
    if magic_type[0] == "text":
        return "text"
    elif magic_type[0] == "image":
        return "image"
    elif magic_type[0] == "audio":
        return "audio"
    elif magic_type[0] == "video":
        return "video"
    elif magic_type[0] == "application":
        mime_type = "/".join(magic_type)
        if mime_type in APPLICATION_MIME_TO_CATEGORY:
            return APPLICATION_MIME_TO_CATEGORY[mime_type]
        else:
            inferred_type = infer_file_type_magic_raw(file_path)
            if inferred_type == "other":
                return infer_file_type_extension(file_path)
            return inferred_type
    return "other"


def infer_file_type_magic_raw(file_path: os.PathLike) -> str:
    magic_type_raw = magic.from_file(file_path)
    matched_term = TERM_PATTERN.search(magic_type_raw)
    if matched_term:
        return MIME_TERM_TO_CATEGORY[matched_term.group(0).lower()]
    return "other"


def infer_file_type_extension(file_path: os.PathLike) -> str:
    file_ext = os.path.splitext(file_path)[1]
    if file_ext in EXTENSION_TO_CATEGORY:
        return EXTENSION_TO_CATEGORY[file_ext]
    return "other"
