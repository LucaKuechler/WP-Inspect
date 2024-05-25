from __future__ import annotations

import filecmp
import shutil
import sys
import tarfile
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

import requests

if TYPE_CHECKING:
    from requests.models import Response

from rich import print

from .utils import (
    generate_virustotal_url,
    get_file_list,
    get_mime_type,
    get_timestamps_from_file,
    is_file_odd_looking,
    is_file_ok,
    validate_wordpress_path,
)


class LineEnding(Enum):
    unix = "unix"
    dos = "windows"


class OutputRow(NamedTuple):
    """
    NamedTuple which holds all attributes for a csv output row.
    """

    fp: Path
    lwt: str
    lat: str
    ct: str
    vt: str
    mime: str


class WordPressComperator(ABC):
    """
    Abstract base class for WordPress comparators.
    """

    @abstractmethod
    def compare(self) -> None:
        """
        Compare method holds logik for comparing WordPress installations.
        """

    @abstractmethod
    def validate_paths(self) -> None:
        """
        Validate paths method to validate paths of WordPress installations.
        """

    @abstractmethod
    def export(self, filepath: Path) -> None:
        """
        Export method to export comparison results.

        :param filepath: The filepath to export the results.
        """

    @abstractmethod
    def show(self) -> None:
        """
        Show method to display comparison results.
        """


class WordPressComperatorWeb(WordPressComperator):
    """
    Concrete implementation of WordPressComparator for comparing
    a hacked WordPress installation with the original web files.
    """

    def __init__(self, wp_filepath_hacked: Path, line_ending: LineEnding) -> None:
        """
        Constructor method.

        :param wp_filepath_hacked: The filepath of the hacked WordPress installation.
        """
        self.wp_filepath_hacked = wp_filepath_hacked
        self.tmp_dir: Path = Path()
        self.wp_language: str = ""
        self.wp_version: str = ""
        self.line_ending: LineEnding = line_ending
        self.added: list[OutputRow] = []
        self.modified: list[OutputRow] = []
        self.binary: list[OutputRow] = []

    def export(self, filepath: Path) -> None:
        """
        Export method to export comparison results.

        :param filepath: The filepath to export the results.
        """
        with filepath.open("w") as file:
            file.write(
                "Action,File,CreationTime,LastWriteTime,LastAccessTime,VirusTotal,MimeType\n",
            )

            for added in self.added:
                file.write(
                    f"Added,{added.fp},{added.ct},{added.lwt},{added.lat},{added.vt},{added.mime}\n",
                )

            for modified in self.modified:
                file.write(
                    f"Modified,{modified.fp},{modified.ct},{modified.lwt},{modified.lat},{modified.vt},{modified.mime}\n",
                )

            for binary in self.binary:
                file.write(
                    f"Binary,{binary.fp},{binary.ct},{binary.lwt},{binary.lat},{binary.vt},{binary.mime}\n",
                )

    def show(self) -> None:
        """
        Show method to display comparison results. The following three outputs
        will be produced:
            - Added Files
            - Modified Files
            - Suspicous Files Found In User Upload
        """
        print(":green_square: Added Files:")
        for file in self.added:
            print(f"[white]{file.fp}[/white]")

        print("\n:yellow_square: Modified Files:")
        for file in self.modified:
            print(f"[white]{file.fp}[/white]")

        print("\n:blue_square: Suspicous User Upload Files:")
        for file in self.binary:
            print(f"[white]{file.fp}[/white]")

    def validate_paths(self) -> None:
        """
        Validate paths method to validate paths of WordPress installations.
        """
        self.wp_version, self.wp_language = validate_wordpress_path(self.wp_filepath_hacked)

        if self.wp_version == "":
            print(f"The given WordPress Path [red]({self.wp_filepath_hacked})[/red] is not valid.")
            sys.exit(-1)

        print(f":repeat_button: WP-Version: {self.wp_version} \n\n")

    def _tmp_create(self) -> Path:
        """
        Helper method to create a temporary directory.

        :return: The path of the created temporary directory.
        """
        tmp_path = Path("/tmp")  # noqa: S108

        if not tmp_path.is_dir():
            sys.exit(-1)

        current_timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")

        new_tmp_folder = tmp_path.joinpath(f"wp_forensics__{current_timestamp}")
        new_tmp_folder.mkdir()

        return new_tmp_folder

    def _download_wp(self) -> Response:
        """
        Helper method to download the WordPress installation files.

        :return: The downloaded WordPress installation files.
        """
        if self.wp_language != "":
            wp_url = (
                f"https://{self.wp_language[:2]}.wordpress.org/wordpress-{self.wp_version}-{self.wp_language}.tar.gz"
            )
        else:
            wp_url = f"https://wordpress.org/wordpress-{self.wp_version}.tar.gz"

        return requests.get(wp_url, stream=True, timeout=10)

    def _extract_wp_archive(self, response_data: Response) -> None:
        """
        Helper method to extract the WordPress archive.

        :param response_data: The downloaded WordPress installation files.
        """
        tar_path = self.tmp_dir.joinpath("download.tar.gz")
        with tar_path.open("wb") as fp:
            shutil.copyfileobj(response_data.raw, fp)

        tar = tarfile.open(tar_path)
        tar.extractall(self.tmp_dir)  # noqa: S202
        tar.close()

        tar_path.unlink()

    def _convert_line_ending_of_wp_files(self, wp_list_of_files: list[Path]) -> None:
        """
        Convert the line ending of a given file based on line ending argument provided by the user.

        :param wp_list_of_files: List of relative filepaths for WordPress files.
        """

        windows_line_ending = b"\r\n"
        unix_line_ending = b"\n"

        for file in wp_list_of_files:
            absolute_path = self.tmp_dir / file

            mime = get_mime_type(absolute_path)

            # Windows does not change line endings certain file types for example images or fonts.
            if "image" in mime and "image/svg+xml" not in mime:
                continue

            if "font" in mime:
                continue

            with absolute_path.open("rb") as f1:
                content = f1.read()

            converted_content = content.replace(windows_line_ending, unix_line_ending)
            converted_content = converted_content.replace(unix_line_ending, windows_line_ending)

            with absolute_path.open("wb") as f2:
                f2.write(converted_content)

    def _identify_added_and_modified_files(self, wp_file_list: list[Path]) -> None:
        """
        Filter out Added and Modified files in both WordPress instances.

        :param wp_file_list: List of relative filepaths for WordPress files.
        """

        for filepath in wp_file_list:
            # if file exists in downloaded files
            tmp_fp, exists = is_file_ok(self.tmp_dir / "wordpress", filepath)

            # get absolute path for filename
            absolute_path = self.wp_filepath_hacked / filepath

            # get timestamps
            lwt, lat, ct = get_timestamps_from_file(absolute_path)

            # calculate file hash from hacked file
            vt = generate_virustotal_url(absolute_path)

            # get mimetype for each filepath
            mime = get_mime_type(absolute_path)

            # the file does exist in the hacked wordpress files but
            # does not appear in the orignial ones than it has been
            # added by the owner or the hacker.
            if not exists:
                self.added.append(
                    OutputRow(fp=absolute_path, lwt=lwt, lat=lat, ct=ct, vt=vt, mime=mime),
                )
                continue

            # as we know file exists we should now check if they are equal
            # if they are not equal than the hacked file has been modified
            # by the owner or the hacker.
            if filecmp.cmp(absolute_path, tmp_fp):
                continue

            self.modified.append(
                OutputRow(fp=absolute_path, lwt=lwt, lat=lat, ct=ct, vt=vt, mime=mime),
            )

    def _identify_odd_looking_files(self, wp_upload_dir: Path, upload_file_list: list[Path]) -> None:
        """
        Identify unusual files in the WordPress user upload folder. These files
        might have mismatched MIME types and file extensions, or they could be
        files that are not typically found in the upload folder, such as PHP
        scripts.

        :param wp_upload_dir: Path to the wordpress upload direcoty used to create the absolut path.
        :param upload_file_list: A list of relative filepaths for every file inside the wordpress upload directory.
        """
        for up_file in upload_file_list:
            target_file = wp_upload_dir / up_file

            # get timestamps
            lwt, lat, ct = get_timestamps_from_file(target_file)

            # get mimetype for each filepath
            mime = get_mime_type(target_file)

            # calculate file hash from hacked file
            vt = generate_virustotal_url(Path(target_file))

            if is_file_odd_looking(target_file):
                self.binary.append(
                    OutputRow(fp=target_file, lwt=lwt, lat=lat, ct=ct, vt=vt, mime=mime),
                )

    def compare(self) -> None:
        """
        Compare method to compare WordPress installation and downloaded WordPress files.
        The results are categorized within three categories:
            - Added Files
            - Modified Files
            - Suspicous Files
        """

        # create temporary directory to store downloaded WordPress files.
        self.tmp_dir = self._tmp_create()

        # download WordPress
        wp_archive = self._download_wp()

        # extract WordPress in tmp folder
        self._extract_wp_archive(wp_archive)

        # In case the hacked wordpress files are from a system running Windows
        # the file endings may differ from those on unix based operating
        # systems. The files downloaded from the web are contain always unix
        # line endings. Therefore they need to be converted to line endings
        # matching the given hacked wordpress files.
        if self.line_ending == LineEnding.dos:
            self._convert_line_ending_of_wp_files(get_file_list(self.tmp_dir, parse_wp_upload=True))

        # create a list of all files within the hacked wordpress directory.
        wp_file_list: list[Path] = get_file_list(self.wp_filepath_hacked)

        # Check for each WordPress file in the hacked directory if it is also
        # present in the Version downloaded from the Web. Identifiy if the file
        # has been changed in the live version. Files found in the wp-content folder
        # are excluded.
        self._identify_added_and_modified_files(wp_file_list)

        # define path for upload directory in wordpress
        wp_upload_dir = self.wp_filepath_hacked.joinpath("wp-content/uploads")
        upload_file_list = get_file_list(wp_upload_dir, parse_wp_upload=True)

        # the upload dir is special as the normal behavior is that people add files.
        # because the webfiles do not contain the user uploaded files, we do not check.
        # against the webfiles. This code only checks if odd looking file.
        self._identify_odd_looking_files(Path(wp_upload_dir), upload_file_list)


class WordPressComperatorLocal(WordPressComperator):
    """
    Concrete implementation of WordPress comparator for comparing a hacked WordPress installation with a backup.
    """

    def __init__(self, wp_filepath_hacked: Path, wp_filepath_backup: Path, *, full: bool) -> None:
        """
        Constructor method.

        :param wp_filepath_hacked: The filepath of the hacked WordPress installation.
        :param wp_filepath_backup: The filepath of the backup WordPress installation.
        :param full: If full option is specified no file extension is excluded.
        """
        self.wp_filepath_hacked: Path = wp_filepath_hacked
        self.wp_filepath_backup: Path = wp_filepath_backup
        self.full: bool = full
        self.added: list[OutputRow] = []
        self.modified: list[OutputRow] = []
        self.deleted: list[OutputRow] = []

    def validate_paths(self) -> None:
        """
        Validate paths method to validate paths of WordPress installations.
        """
        v1, l1 = validate_wordpress_path(self.wp_filepath_hacked)
        v2, l2 = validate_wordpress_path(self.wp_filepath_backup)

        if v1 == "":
            print(f"The given WordPress Path [red]({self.wp_filepath_hacked})[/red] is not valid.")
            sys.exit(-1)

        if v2 == "":
            print(f"The given WordPress Path [red]({self.wp_filepath_backup})[/red] is not valid.")
            sys.exit(-1)

        print(f":repeat_button: WP-Version Hacked: {v1}")
        print(f":repeat_button: WP-Version Backup: {v2} \n\n")

        if v1 != v2 or l1 != l2:
            print("Languages do not match.")
            sys.exit(-1)

    def _identify_added_and_modified_files(self, wp_file_list: list[Path]) -> None:
        """
        Filter out Added and Modified files in both WordPress instances.

        :param filepath: The relative wordpress filepath that is compared in
                         both instances.
        """
        for filepath in wp_file_list:
            # get absolute path for filename
            absolute_path = self.wp_filepath_hacked / filepath

            # exclude extensions that are most likly not dangerous
            if not self.full:
                lower_file_extension = absolute_path.suffix.lower()
                if lower_file_extension in [".log", ".pdf"]:
                    continue

            # check if file exists and return filepath for backup
            backup_fp, exists = is_file_ok(self.wp_filepath_backup, filepath)

            # get timestamps
            lwt, lat, ct = get_timestamps_from_file(absolute_path)

            # calculate file hash from hacked file
            vt = generate_virustotal_url(absolute_path)

            mime = get_mime_type(absolute_path)

            # the file does exist in the hacked wordpress files but
            # does not appear in the orignial ones than it has been
            # added by the owner or the hacker.
            if not exists:
                self.added.append(OutputRow(fp=absolute_path, lwt=lwt, lat=lat, ct=ct, vt=vt, mime=mime))
                continue

            # as we know file exists we should now check if they are equal
            # if they are not equal than the hacked file has been modified
            # by the owner or the hacker.
            if filecmp.cmp(absolute_path, backup_fp):
                continue

            self.modified.append(OutputRow(fp=absolute_path, lwt=lwt, lat=lat, ct=ct, vt=vt, mime=mime))

    def _identify_deleted_files(self, hacked_file_list: list[Path], backup_file_list: list[Path]) -> None:
        """
        Filter out files that are represented in the backup but not in the hacked
        version of the program. Those are the deleted files by the attacker.

        :param hacked_file_list: List of WordPress files.
        :param backup_file_list: List of WordPress files.
        """
        s1 = set(hacked_file_list)
        s2 = set(backup_file_list)

        for elem in list(s2 - s1):
            # exclude extensions that are most likly not dangerous
            if not self.full:
                lower_file_extension = elem.suffix.lower()
                if lower_file_extension in [".png", ".jpg", ".log", ".pdf"]:
                    continue

            self.deleted.append(OutputRow(fp=self.wp_filepath_hacked / elem, lwt="", lat="", ct="", vt="", mime=""))

    def compare(self) -> None:
        """
        Compare method to compare WordPress installations.
        The results are categorized within three categories:
            - Added Files
            - Modified Files
            - Deleted Files

        An additonal category for Suspicous files is not necesarray as they are
        mostly covered by the other three groups.
        """

        # get all files from hacked wordpress directory.
        hacked_file_list: list[Path] = get_file_list(self.wp_filepath_hacked, parse_wp_upload=True)

        # get all files from backup wordpress directory.
        backup_file_list: list[Path] = get_file_list(self.wp_filepath_backup, parse_wp_upload=True)

        # Check for each WordPress file in the hacked directory if it is also
        # present in the Backup Version. Identifiy if the file has been changed
        # in the live version. Files found in the wp-content folder are excluded.
        self._identify_added_and_modified_files(hacked_file_list)

        # Check for files that have been deleted.
        self._identify_deleted_files(hacked_file_list, backup_file_list)

    def export(self, filepath: Path) -> None:
        """
        Export method to export comparison results.

        :param filepath: The filepath to export the results.
        """
        with filepath.open("w") as file:
            file.write("Action,File,CreationTime,LastWriteTime,LastAccessTime,VirusTotal\n")

            for added in self.added:
                file.write(f"Added,{added.fp},{added.ct},{added.lwt},{added.lat},{added.vt}\n")

            for modified in self.modified:
                file.write(f"Modified,{modified.fp},{modified.ct},{modified.lwt},{modified.lat},{modified.vt}\n")

            for deleted in self.deleted:
                file.write(f"Deleted,{deleted.fp},{deleted.ct},{deleted.lwt},{deleted.lat},{deleted.vt}\n")

    def show(self) -> None:
        """
        Show method to display comparison results. The following three outputs
        will be produced:
            - Added Files
            - Modified Files
            - Deleted Files
        """
        print(":green_square: Added Files:")
        for file in self.added:
            print(f"[white]{file.fp}[/white]")

        print("\n:yellow_square: Modified Files:")
        for file in self.modified:
            print(f"[white]{file.fp}[/white]")

        print("\n:red_square: Deleted Files:")
        for file in self.deleted:
            print(f"[white]{file.fp}[/white]")
