import filecmp
import os
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any
from .utils import *

import requests
from rich import print


class WordPressComperator(ABC):
    """
    Abstract base class for WordPress comparators.
    """

    @abstractmethod
    def compare(self) -> None:
        """
        Compare method holds logik for comparing WordPress installations.
        """
        pass

    @abstractmethod
    def validate_paths(self) -> None:
        """
        Validate paths method to validate paths of WordPress installations.
        """
        pass

    @abstractmethod
    def export(self, filepath: str) -> None:
        """
        Export method to export comparison results.

        :param filepath: The filepath to export the results.
        """
        pass

    @abstractmethod
    def show(self) -> None:
        """
        Show method to display comparison results.
        """
        pass


class WordPressComperatorWeb(WordPressComperator):
    """
    Concrete implementation of WordPressComparator for comparing
    a hacked WordPress installation with the original web files.
    """

    def __init__(self, wp_filepath_hacked: str) -> None:
        """
        Constructor method.

        :param wp_filepath_hacked: The filepath of the hacked WordPress installation.
        """
        self.wp_filepath_hacked = wp_filepath_hacked
        self.tmp_dir = ""
        self.wp_language = ""
        self.wp_version = ""

    def export(self, filepath: str) -> None:
        """
        Export method to export comparison results.

        :param filepath: The filepath to export the results.
        """
        pass

    def show(self) -> None:
        """
        Show method to display comparison results. The following three outputs
        will be produced:
            - Added Files
            - Modified Files
            - Suspicous Files Found In User Upload
        """
        print(":green_square: Added Files:")
        for file in self.added_dict:
            print(file)

        print("\n:yellow_square: Modified Files:")
        for file in self.modified_dict:
            print(file)

        print("\n:blue_square: Suspicous User Upload Files:")
        for file in self.binary_dict:
            print(file)

    def validate_paths(self) -> None:
        """
        Validate paths method to validate paths of WordPress installations.
        """
        self.wp_version, self.wp_language = validate_wordpress_path(
            self.wp_filepath_hacked
        )

    def _tmp_create(self) -> Path:
        """
        Helper method to create a temporary directory.

        :return: The path of the created temporary directory.
        """
        tmp_path = Path("/tmp")

        if not tmp_path.is_dir():
            exit(-1)

        current_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        new_tmp_folder = tmp_path / f"wp_forensics__{current_timestamp}"

        os.mkdir(new_tmp_folder)

        return new_tmp_folder

    def _download_wp(self) -> Any:
        """
        Helper method to download the WordPress installation files.

        :return: The downloaded WordPress installation files.
        """
        if self.wp_language != "":
            wp_url = f"https://{self.wp_language}.wordpress.org/wordpress-{self.wp_version}-{self.wp_language}.tar.gz"
        else:
            wp_url = f"https://wordpress.org/wordpress-{self.wp_version}.tar.gz"

        response_data = requests.get(wp_url, stream=True)
        return response_data

    def _extract_wp_archive(self, response_data: Any) -> None:
        """
        Helper method to extract the WordPress archive.

        :param response_data: The downloaded WordPress installation files.
        """
        tar_path = self.tmp_dir / "download.tar.gz"
        with open(tar_path, "wb") as fp:
            shutil.copyfileobj(response_data.raw, fp)

        tar = tarfile.open(tar_path)
        tar.extractall(self.tmp_dir)
        tar.close()

        os.remove(tar_path)

    def _is_file_ok(self, wpdir_relative_filepath: str) -> Tuple[Path, bool]:
        """
        Helper method to check if a file is okay.

        :param wpdir_relative_filepath: The relative filepath of the file.
        :return: A tuple containing the file path and a boolean indicating if the file is okay.
        """
        downloaded_target_file = self.tmp_dir / "wordpress" / wpdir_relative_filepath
        return downloaded_target_file, downloaded_target_file.is_file()

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

        # create a list of all files within the hacked wordpress directory.
        wp_file_list = get_file_list(self.wp_filepath_hacked)

        self.added_dict = []
        self.modified_dict = []
        self.binary_dict = []

        for filepath in wp_file_list:
            hacked_fp = Path(filepath)

            # ../test-data/wordpress_hacked/wp-login.php -> wp-login.php
            wpdir_relative_filepath = filepath.replace(self.wp_filepath_hacked, "")

            # if file exists in downloaded files
            tmp_fp, exists = self._is_file_ok(wpdir_relative_filepath)

            # the file does exist in the hacked wordpress files but
            # does not appear in the orignial ones than it has been
            # added by the owner or the hacker.
            if not exists:
                self.added_dict.append(hacked_fp)
                continue

            # as we know file exists we should now check if they are equal
            # if they are not equal than the hacked file has been modified
            # by the owner or the hacker.
            if filecmp.cmp(hacked_fp, tmp_fp):
                continue

            self.modified_dict.append(hacked_fp)

        # the upload dir is special as the normal behavior is that people add files.
        # because the webfiles do not contain the user uploaded files, we do not check.
        # against the webfiles. This code only checks if odd looking file.
        wp_upload_dir = self.wp_filepath_hacked + "wp-content/uploads"
        upload_file_list = get_file_list(wp_upload_dir, True)

        for up_file in upload_file_list:
            target_file = wp_upload_dir + "/" + up_file

            if not is_file_binary(target_file):
                self.binary_dict.append(wp_upload_dir + "/" + up_file)


class WordPressComperatorBackup(WordPressComperator):
    """
    Concrete implementation of WordPress comparator for comparing a hacked WordPress installation with a backup.
    """

    def __init__(self, wp_filepath_hacked: str, wp_filepath_backup: str) -> None:
        """
        Constructor method.

        :param wp_filepath_hacked: The filepath of the hacked WordPress installation.
        :param wp_filepath_backup: The filepath of the backup WordPress installation.
        """
        self.wp_filepath_hacked = wp_filepath_hacked
        self.wp_filepath_backup = wp_filepath_backup

    def validate_paths(self) -> None:
        """
        Validate paths method to validate paths of WordPress installations.
        """
        v1, l1 = validate_wordpress_path(self.wp_filepath_hacked)
        v2, l2 = validate_wordpress_path(self.wp_filepath_backup)

        print(":repeat_button: WP-Version Hacked: {}".format(v1))
        print(":repeat_button: WP-Version Backup: {} \n\n".format(v2))

        if v1 != v2 or l1 != l2:
            exit(-1)

    def _is_file_ok(self, wpdir_relative_filepath) -> Tuple[Path, bool]:
        """
        Helper method to check if a file is okay.

        :param wpdir_relative_filepath: The relative filepath of the file.
        :return: A tuple containing the file path and a boolean indicating if the file is okay.
        """
        downloaded_target_file = Path(self.wp_filepath_backup) / wpdir_relative_filepath
        return downloaded_target_file, downloaded_target_file.is_file()

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
        hacked_file_list = get_file_list(self.wp_filepath_hacked, True)
        backup_file_list = get_file_list(self.wp_filepath_backup, True)

        self.added = []
        self.modified = []
        self.deleted = []
        self.binary = []

        for fp in hacked_file_list:
            hacked_fp = Path(fp)

            # ../test-data/wordpress_hacked/wp-login.php -> wp-login.php
            wpdir_relative_filepath = fp.replace(self.wp_filepath_hacked, "")

            # if file exists in downloaded files
            backup_fp, exists = self._is_file_ok(wpdir_relative_filepath)

            # get timestamps
            lwt, lat, ct = get_timestamps_from_file(hacked_fp)

            # calculate file hash from hacked file
            vt = generate_virustotal_url(hacked_fp)

            # the file does exist in the hacked wordpress files but
            # does not appear in the orignial ones than it has been
            # added by the owner or the hacker.
            if not exists:
                self.added.append(
                    {
                        "filepath": hacked_fp,
                        "LastWriteTime": lwt,
                        "LastAccessTime": lat,
                        "CreationTime": ct,
                        "VirusTotal": vt,
                    },
                )
                continue

            # as we know file exists we should now check if they are equal
            # if they are not equal than the hacked file has been modified
            # by the owner or the hacker.
            if filecmp.cmp(hacked_fp, backup_fp):
                continue

            self.modified.append(
                {
                    "filepath": hacked_fp,
                    "LastWriteTime": lwt,
                    "LastAccessTime": lat,
                    "CreationTime": ct,
                    "VirusTotal": vt,
                },
            )

        s1 = set()
        for fp in hacked_file_list:
            wpdir_relative_filepath = fp.replace(self.wp_filepath_hacked, "")
            s1.add(wpdir_relative_filepath)

        s2 = set()
        for fp in backup_file_list:
            wpdir_relative_filepath = fp.replace(self.wp_filepath_backup, "")
            s2.add(wpdir_relative_filepath)

        for elem in list(s2 - s1):
            self.deleted.append(
                {
                    "filepath": self.wp_filepath_hacked + elem,
                    "LastWriteTime": "",
                    "LastAccessTime": "",
                    "CreationTime": "",
                    "VirusTotal": "",
                },
            )

    def export(self, filepath: str) -> None:
        """
        Export method to export comparison results.

        :param filepath: The filepath to export the results.
        """
        with open(filepath, "w") as file:
            file.write(
                "Action,File,CreationTime,LastWriteTime,LastAccessTime,VirusTotal\n"
            )

            for added in self.added:
                file.write(
                    f"Added,{added.get('filepath')},{added.get('CreationTime')},{added.get('LastWriteTime')},{added.get('LastAccessTime')},{added.get('VirusTotal')}\n"
                )

            for modified in self.modified:
                file.write(
                    f"Modified,{modified.get('filepath')},{modified.get('CreationTime')},{modified.get('LastWriteTime')},{modified.get('LastAccessTime')},{modified.get('VirusTotal')}\n"
                )

            for deleted in self.deleted:
                file.write(
                    f"Deleted,{deleted.get('filepath')},{deleted.get('CreationTime')},{deleted.get('LastWriteTime')},{deleted.get('LastAccessTime')},{deleted.get('VirusTotal')}\n"
                )

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
            print(f"[white]{file.get('filepath')}[/white]")

        print("\n:yellow_square: Modified Files:")
        for file in self.modified:
            print(f"[white]{file.get('filepath')}[/white]")

        print("\n:red_square: Deleted Files:")
        for file in self.deleted:
            print(f"[white]{file.get('filepath')}[/white]")


class WordPressComperatorFactory:
    """
    Factory class for creating WordPress comparators.
    """

    def create_wpc(self, wp_filepath_hacked, wp_filepath_backup) -> WordPressComperator:
        """
        Method to create a WordPress comparator.

        :param wp_filepath_hacked: The filepath of the hacked WordPress installation.
        :param wp_filepath_backup: The filepath of the backup WordPress installation.
        :return: A WordPress comparator instance.
        """

        if wp_filepath_backup:
            return WordPressComperatorBackup(wp_filepath_hacked, wp_filepath_backup)

        return WordPressComperatorWeb(wp_filepath_hacked)
