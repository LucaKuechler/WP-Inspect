from __future__ import annotations

import glob
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

import magic


def get_mime_type(filepath: Path) -> str:
    """
    Return the mimetype of a given filepath.

    :param filepath: Filepath to determine the mimetype.
    :return: Returns the mimetype of a given filepath.
    """
    return magic.from_file(filepath, mime=True)


def get_timestamps_from_file(filepath: Path) -> tuple[str, str, str]:
    """
    Get timestamps (last modified time, last accessed time, creation time) of a file.

    :param filepath: Path to the file.
    :return: A tuple containing the last modified time, last accessed time, and creation time of the file.
    """
    if not filepath.is_file():
        return "", "", ""

    frmt = "%Y-%m-%d %H:%M:%S"
    lwt = datetime.fromtimestamp(filepath.stat().st_mtime, tz=timezone.utc).strftime(frmt)
    lat = datetime.fromtimestamp(filepath.stat().st_atime, tz=timezone.utc).strftime(frmt)
    ct = datetime.fromtimestamp(filepath.stat().st_ctime, tz=timezone.utc).strftime(frmt)

    return lwt, lat, ct


def generate_virustotal_url(filepath: Path) -> str:
    """
    Generate a VirusTotal URL for a file.

    :param filepath: Path to the file.
    :return: The VirusTotal URL for the file.
    """
    if not filepath.is_file():
        return ""

    hash_md5 = hashlib.md5()  # noqa: S324
    with filepath.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)

    return f"https://www.virustotal.com/gui/file/{hash_md5.hexdigest()}"


def validate_wordpress_path(path: Path) -> tuple[str, str]:
    """
    Validate a WordPress installation path.

    :param wp_path: Path to the WordPress installation.
    :return: A tuple containing the WordPress version and language.
    """

    # if the given path is not a folder it can not be the wordpress instance
    if not path.is_dir():
        return "", ""

    # find wordpress version to validate that the path contains wordpress files
    version_filepath = path / "wp-includes/version.php"
    if not version_filepath.is_file():
        return "", ""

    # read out version and language
    version = ""
    language = ""
    with version_filepath.open("r") as v_file:
        for line in v_file:
            match_version = re.search(r'\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]', line)
            if match_version:
                version = match_version.group(1)

            match_language = re.search(r'\$wp_local_package\s*=\s*[\'"]([^\'"]+)[\'"]', line)
            if match_language:
                language = match_language.group(1)

    if version == "":
        return "", ""

    return version, language


def get_file_list(wp_dir: Path, *, parse_wp_upload: bool = False) -> list[Path]:
    """
    Get the list of files in a WordPress directory.

    :param wp_dir: Path to the WordPress directory.
    :param parse_wp_upload: Whether to parse WordPress upload directory.
    :return: The list of files in the WordPress directory.
    """
    file_abs_list = glob.glob(str(wp_dir) + "/**", recursive=True)  # noqa: PTH207

    file_list = []
    for file_abs_path in file_abs_list:
        if Path(file_abs_path).is_dir():
            continue

        if "wp-config.php" in file_abs_path:
            continue

        if parse_wp_upload:
            file_list.append(Path(file_abs_path.replace(str(wp_dir) + "/", "", 1)))
            continue

        if "wp-content/" not in file_abs_path:
            file_list.append(Path(file_abs_path.replace(str(wp_dir) + "/", "", 1)))

    return file_list


def is_file_binary(filename: Path) -> bool:
    """
    Check if a file is binary.

    :param filename: Name of the file.
    :return: True if the file is binary, False otherwise.
    """
    if filename.is_file() is False:
        return True

    png_mn = bytearray([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    gif_mn = bytearray([0x47, 0x49, 0x46])
    jpeg_mn = bytearray([0xFF, 0xD8])
    header = bytearray()

    with filename.open("rb") as f:
        for _ in range(8):
            d = f.read(1)
            if len(d) > 0:
                header.append(ord(d))

    if header == png_mn:  # noqa: SIM114
        return True
    elif header[:3] == gif_mn:  # noqa: RET505, SIM114
        return True
    elif header[:2] == jpeg_mn:  # noqa: SIM103
        return True
    else:
        return False


def is_file_ok(wp_backup_dir: Path, wp_relative_filepath: Path) -> tuple[Path, bool]:
    """
    Helper method to check if a file is okay.

    :param wpdir_relative_filepath: The relative filepath of the file.
    :return: A tuple containing the file path and a boolean indicating if the file is okay.
    """

    downloaded_target_file = wp_backup_dir / wp_relative_filepath
    return downloaded_target_file, downloaded_target_file.is_file()
