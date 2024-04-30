import unittest
from unittest.mock import patch, MagicMock
import os
from pathlib import Path
from wp_inspect.wordpress_comperator import (
    WordPressComperatorWeb,
    WordPressComperatorLocal,
)


class TestWordPressComperatorWeb(unittest.TestCase):

    def setUp(self):
        self.obj = WordPressComperatorWeb(Path())

    def tearDown(self):
        # Remove the temporary directory after each test
        if hasattr(self, "tmp_dir"):
            os.rmdir(self.tmp_dir)

    def test_tmp_create(self):
        # Call the method to create the temporary directory
        tmp_dir = self.obj._tmp_create()

        # Ensure the returned value is a Path object
        self.assertIsInstance(tmp_dir, Path)

        # Ensure the directory exists
        self.assertTrue(tmp_dir.exists())

        # Store the created temporary directory for cleanup in tearDown
        self.tmp_dir = tmp_dir

    @patch("wp_inspect.wordpress_comperator.requests.get")
    def test_download_wp_with_language(self, mock_get):
        # Set up the mock response data
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"Fake response data"
        mock_get.return_value = mock_response

        # Set up the class attributes
        self.obj.wp_language = "en"
        self.obj.wp_version = "5.8"

        # Call the method
        result = self.obj._download_wp()

        # Check if requests.get is called with the correct URL
        mock_get.assert_called_once_with(
            "https://en.wordpress.org/wordpress-5.8-en.tar.gz", stream=True
        )

        # Check if the method returns the response data
        self.assertEqual(result, mock_response)

    @patch("wp_inspect.wordpress_comperator.requests.get")
    def test_download_wp_without_language(self, mock_get):
        # Set up the mock response data
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"Fake response data"
        mock_get.return_value = mock_response

        # Set up the class attributes
        self.obj.wp_language = ""
        self.obj.wp_version = "5.8"

        # Call the method
        result = self.obj._download_wp()

        # Check if requests.get is called with the correct URL
        mock_get.assert_called_once_with(
            "https://wordpress.org/wordpress-5.8.tar.gz", stream=True
        )

        # Check if the method returns the response data
        self.assertEqual(result, mock_response)


class TestIsFileOk(unittest.TestCase):

    def setUp(self):
        # Create an instance of your class
        self.obj = WordPressComperatorLocal("", "/path/to/backup/", False)

    def test_is_file_ok_existing_file(self):
        # Provide a valid file path
        wpdir_relative_filepath = "wp-include/config.php"

        # Call the method
        with patch.object(Path, "is_file", return_value=True):
            file_path, is_ok = self.obj._is_file_ok(wpdir_relative_filepath)

        # Assert that the file path is correct and is_ok is True
        self.assertEqual(file_path, Path("/path/to/backup/wp-include/config.php"))
        self.assertTrue(is_ok)

    def test_is_file_ok_nonexistent_file(self):
        # Provide a non-existent file path
        wpdir_relative_filepath = "wp-include/nonexistent_file.php"

        # Call the method
        with patch.object(Path, "is_file", return_value=False):
            file_path, is_ok = self.obj._is_file_ok(wpdir_relative_filepath)

        # Assert that the file path is correct and is_ok is False
        self.assertEqual(
            file_path, Path("/path/to/backup/wp-include/nonexistent_file.php")
        )
        self.assertFalse(is_ok)


if __name__ == "__main__":
    unittest.main()
