import hashlib
import unittest
from pathlib import Path, PosixPath
from unittest.mock import mock_open, patch

from wp_inspect.utils import (generate_virustotal_url, get_file_list,
                              get_timestamps_from_file, is_file_ok,
                              validate_wordpress_path)


class TestValidateWordPressPath(unittest.TestCase):

    def test_valid_wordpress_path_with_language(self):

        data = """
        $wp_version = '6.5.2';
        $wp_local_package = 'de_DE';
        """

        wp_path = Path("/path/to/wp")

        # Create a temporary directory with WordPress files
        with patch("builtins.open", mock_open(read_data=data)) as mock_file:
            with patch.object(Path, "is_file", return_value=True):
                with patch.object(Path, "is_dir", return_value=True):
                    # Provide the path to the temporary directory
                    wp_version, wp_language = validate_wordpress_path(wp_path)

        # Asset that the opened path include version.php as read only.
        mock_file.assert_called_with(
            PosixPath("/path/to/wp/wp-includes/version.php"), "r"
        )

        # Assert that the returned values are correct
        self.assertEqual(
            wp_version, "6.5.2"
        )  # Assuming version 5.8 is found in version.php
        self.assertEqual(
            wp_language, "de_DE"
        )  # Assuming language 'en' is found in version.php

    def test_valid_wordpress_path_without_language(self):

        data = """
        $wp_version = '6.5.2';
        """

        wp_path = Path("/path/to/wp")

        # Create a temporary directory with WordPress files
        with patch("builtins.open", mock_open(read_data=data)) as mock_file:
            with patch.object(Path, "is_file", return_value=True):
                with patch.object(Path, "is_dir", return_value=True):
                    # Provide the path to the temporary directory
                    wp_version, wp_language = validate_wordpress_path(wp_path)

        # Asset that the opened path include version.php as read only.
        mock_file.assert_called_with(
            PosixPath("/path/to/wp/wp-includes/version.php"), "r"
        )

        # Assert that the returned values are correct
        self.assertEqual(
            wp_version, "6.5.2"
        )  # Assuming version 5.8 is found in version.php
        self.assertEqual(
            wp_language, ""
        )  # Assuming language 'en' is found in version.php

    def test_invalid_path_not_directory(self):
        invalid_wp_path = Path("/invalid/path")

        # Provide a non-existent path
        with patch.object(Path, "is_dir", return_value=False):
            wp_version, wp_language = validate_wordpress_path(invalid_wp_path)

        # Assert that the returned values are empty strings
        self.assertEqual(wp_version, "")
        self.assertEqual(wp_language, "")

    def test_valid_path_but_no_wordpress_files_in_it(self):
        non_wp_dir = Path("/path/to/non_wordpress_directory")

        # Create a temporary directory without WordPress files
        with patch.object(Path, "is_file", return_value=False):
            with patch.object(Path, "is_dir", return_value=True):
                # Provide the path to the temporary directory
                wp_version, wp_language = validate_wordpress_path(non_wp_dir)

        # Assert that the returned values are empty strings
        self.assertEqual(wp_version, "")
        self.assertEqual(wp_language, "")


class TestGenerateVirusTotalURL(unittest.TestCase):

    @patch("builtins.open", new_callable=mock_open, read_data=b"file_data")
    def test_generate_url_with_existing_file(self, mock_open):

        # Call the function
        with patch.object(Path, "is_file", return_value=True):
            url = generate_virustotal_url(Path("/path/to/existing/file"))

        # Calculate expected hash
        hash_md5 = hashlib.md5()
        hash_md5.update(b"file_data")
        expected_hash = hash_md5.hexdigest()

        # Assert that correct file is opened with right permissions.
        mock_open.assert_called_with(PosixPath("/path/to/existing/file"), "rb")

        # Assert that the URL is generated correctly
        self.assertEqual(url, f"https://www.virustotal.com/gui/file/{expected_hash}")

    def test_generate_url_with_nonexistent_file(self):

        # Call the function
        with patch.object(Path, "is_file", return_value=False):
            url = generate_virustotal_url(Path("/path/to/nonexistent/file"))

        # Assert that the URL is empty
        self.assertEqual(url, "")


class TestGetTimestampsFromFile(unittest.TestCase):

    @patch("os.path.getmtime", return_value=1619739840.0)
    @patch("os.path.getatime", return_value=1619739840.0)
    @patch("os.path.getctime", return_value=1619739840.0)
    def test_get_timestamps_from_existing_file(self, *args):
        # Provide a valid file path
        filepath = Path("/path/to/existing/file")

        # Call the function
        with patch.object(Path, "is_file", return_value=True):
            lwt, lat, ct = get_timestamps_from_file(filepath)

        # Assert that the timestamps are correct
        self.assertEqual(lwt, "2021-04-30 01:44:00")
        self.assertEqual(lat, "2021-04-30 01:44:00")
        self.assertEqual(ct, "2021-04-30 01:44:00")

    def test_get_timestamps_from_nonexistent_file(self):
        # Provide a non-existent file path
        filepath = Path("/path/to/nonexistent/file")

        # Call the function
        with patch.object(Path, "is_file", return_value=False):
            lwt, lat, ct = get_timestamps_from_file(filepath)

        # Assert that all timestamps are empty strings
        self.assertEqual(lwt, "")
        self.assertEqual(lat, "")
        self.assertEqual(ct, "")


class TestGetFileList(unittest.TestCase):

    @patch(
        "glob.glob",
        return_value=[
            "/path/to/wp_dir/file1",
            "/path/to/wp_dir/file2",
            "/path/to/wp_dir/wp-config.php",
            "/path/to/wp_dir/wp-content/file3",
        ],
    )
    def test_get_file_list_normal_directory(self, mock_glob):
        # Provide a valid WordPress directory path
        wp_dir = Path("/path/to/wp_dir")

        # Call the function
        with patch.object(Path, "is_dir", return_value=False):
            file_list = get_file_list(wp_dir)

        # Assert that the file list contains the correct files
        self.assertEqual(file_list, [PosixPath("file1"), PosixPath("file2")])

    @patch(
        "glob.glob",
        return_value=[
            "/path/to/wp_dir/file1",
            "/path/to/wp_dir/file2",
            "/path/to/wp_dir/wp-config.php",
            "/path/to/wp_dir/wp-content/file3",
        ],
    )
    def test_get_file_list_with_parse_wp_upload(self, mock_glob):
        # Provide a valid WordPress directory path
        wp_dir = Path("/path/to/wp_dir")

        # Call the function with parse_wp_upload=True
        with patch.object(Path, "is_dir", return_value=False):
            file_list = get_file_list(wp_dir, parse_wp_upload=True)

        # Assert that the file list contains the correct files
        self.assertEqual(
            file_list,
            [PosixPath("file1"), PosixPath("file2"), PosixPath("wp-content/file3")],
        )

    @patch("glob.glob", return_value=[])
    def test_get_file_list_empty_dir(self, mock_glob):
        # Provide a non-existent directory path
        wp_dir = Path("/path/to/nonexistent/dir")

        # Call the function
        with patch.object(Path, "is_dir", return_value=False):
            file_list = get_file_list(wp_dir)

        # Assert that the file list is empty
        self.assertEqual(file_list, [])


class TestIsFileOk(unittest.TestCase):

    def test_file_exists(self):
        # Define test data
        wp_backup_dir = Path("/tmp/wordpress/")
        wp_relative_filepath = Path("wp-includes/config.php")

        # Call the function
        with patch.object(Path, "is_file", return_value=True):
            file_path, is_ok = is_file_ok(wp_backup_dir, wp_relative_filepath)

        self.assertEqual(PosixPath("/tmp/wordpress/wp-includes/config.php"), file_path)
        self.assertTrue(is_ok)

    def test_file_does_not_exist(self):
        # Define test data
        wp_backup_dir = Path("/tmp/wordpress/")
        wp_relative_filepath = Path("wp-includes/config.php")

        # Call the function
        with patch.object(Path, "is_file", return_value=False):
            file_path, is_ok = is_file_ok(wp_backup_dir, wp_relative_filepath)

        self.assertEqual(PosixPath("/tmp/wordpress/wp-includes/config.php"), file_path)
        self.assertFalse(is_ok)


if __name__ == "__main__":
    unittest.main()
