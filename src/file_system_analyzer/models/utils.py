import stat
import os
import math
from typing import Dict, List

from .file_type_mappings import APPLICATION_MIME_TO_CATEGORY, EXTENSION_TO_CATEGORY, TERM_PATTERN, TERM_TO_CATEGORY
from ..logging_config import logger


def get_permissions(mode: int) -> Dict[str, Dict]:
    """
    Returns a map of rights category to its read/write/execute rights (boolean)
    by performing a bitwise AND with the specific permission codes
    :param mode: int
        stat's st_mode, which represents permissions
    :return: dict[str, dict]
        map of rights category to its read/write/execute rights (boolean)
    """
    try:
        if not isinstance(mode, int):
            raise ValueError("mode must be integer")
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
    except ValueError as ve:
        logger.error(f"Value error getting permissions: {ve}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error getting permissions: {e}")
        raise


def infer_file_type_magic(file_path: os.PathLike) -> str:
    """
    Uses python-magic (libmagic wrapper for Python) to use file signatures to infer the file type
    :param file_path: os.PathLike
        Path to the file, type of which needs to be inferred
    :return: str
        Type inferred using libmagic
    """
    try:
        import magic
        mime_type = magic.from_file(file_path, mime=True)
        magic_type = mime_type.split('/')

        if len(magic_type) < 1:
            raise ValueError(f"invalid MIME type: {mime_type}")

        if magic_type[0] == "text":
            return "text"
        elif magic_type[0] == "image":
            return "image"
        elif magic_type[0] == "audio":
            return "audio"
        elif magic_type[0] == "video":
            return "video"
        elif magic_type[0] == "application":
            if mime_type in APPLICATION_MIME_TO_CATEGORY:
                return APPLICATION_MIME_TO_CATEGORY[mime_type]
            else:
                inferred_type = infer_file_type_magic_raw(file_path)
                if inferred_type == "other":
                    return infer_file_type_extension(file_path)
                return inferred_type
        return "other"
    except ImportError as ie:
        logger.error(f"Import error inferring type with libmagic: {ie}")
        raise
    except FileNotFoundError as fe:
        logger.error(f"FileNotFoundError inferring type with libmagic: {fe}")
        raise
    except ValueError as ve:
        logger.error(f"Value error inferring type with libmagic: {ve}")
        raise
    except Exception as e:
        logger.error(f"Error when inferring type: {e}")
        raise


def infer_file_type_magic_raw(file_path: os.PathLike) -> str:
    try:
        import magic
        magic_type_raw = magic.from_file(file_path)
        matched_term = TERM_PATTERN.search(magic_type_raw)
        if matched_term:
            return TERM_TO_CATEGORY[matched_term.group(0).lower()]
        return "other"
    except ImportError as ie:
        logger.error(f"Import error inferring file type with libmagic description: {ie}")
    except FileNotFoundError as fe:
        logger.error(f"FileNotFoundError inferring file type with libmagic raw description: {fe}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error inferring file type with libmagic raw description: {e}")
        raise


def infer_file_type_extension(file_path: os.PathLike) -> str:
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"file {file_path} does not exist")
        file_ext = os.path.splitext(file_path)[1]
        if file_ext in EXTENSION_TO_CATEGORY:
            return EXTENSION_TO_CATEGORY[file_ext]
        return "other"
    except FileNotFoundError as fe:
        logger.error(f"FileNotFoundError inferring file type with extension: {fe}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error inferring file type with extension: {e}")
        raise


def convert_size(file_size: int) -> str:
    try:
        if not isinstance(file_size, int):
            raise ValueError("file size must be integer")
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

        return f"{converted_size} {size_units[unit_index]}"
    except ValueError as ve:
        logger.error(f"Value error converting size: {ve}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error converting size: {e}")
        raise


def detect_unusual_permissions(mode: int) -> List[str]:
    try:
        if not isinstance(mode, int):
            raise ValueError("mode must be integer")
        unusual_permissions = []
        if mode & stat.S_IWOTH:
            unusual_permissions.append("world-writable")
        if mode & stat.S_IWGRP:
            unusual_permissions.append("group-writable")
        if mode & stat.S_IXOTH:
            unusual_permissions.append("world-executable")
        if mode & stat.S_IXGRP:
            unusual_permissions.append("group-executable")
        if mode & stat.S_ISUID:
            unusual_permissions.append("set-uid")
        if mode & stat.S_ISGID:
            unusual_permissions.append("set-gid")
        if mode & stat.S_ISVTX:
            unusual_permissions.append("sticky-bit")
        return unusual_permissions
    except ValueError as ve:
        logger.error(f"Value error when detecting unusual permissions: {ve}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error when detecting unusual permissions: {e}")
        raise
