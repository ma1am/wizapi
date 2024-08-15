# pylint: disable=protected-access
# pylint: disable=unused-argument
# pylint: disable=missing-docstring

import unittest
import logging
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
from ..wiz import WIZ as API, Config, AccessToken
from .. import wiz


class TestWizBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Configure logging to display logs while running tests
        import sys

        cls.logger = logging.getLogger("wizapi")
        cls.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(stream=sys.stdout)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(formatter)
        cls.logger.addHandler(handler)


class TestWiz2(TestWizBase):
    def setUp(self):
        self.api = API(
            client_id="test_client_id",
            client_secret="test_client_secret",
            api_url="https://wiz.io/graphql",
            auth_url="https://wiz.io/oauth/token",
            stored=True,
            timeout=120,
        )

    def test_initialization(self):

        assert self.api.config.api_url == "https://wiz.io/graphql"
        assert self.api.config.auth_url == "https://wiz.io/oauth/token"
        assert self.api.config.client_id == "test_client_id"
        assert self.api.config.client_secret == "test_client_secret"
        assert self.api.timeout == 120
        assert self.api._session.headers["Content-Type"] == "application/json"

    def test_set_auth_header(self):
        with patch("wiz2.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {"access_token": "test_access_token"}
            mock_post.return_value = mock_response
            self.api._set_auth_header()
            assert (
                self.api._session.headers["Authorization"] == "Bearer test_access_token"
            )

    def test_set_auth_header_force(self):
        with patch("wiz2.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {"access_token": "new_test_access_token"}
            mock_post.return_value = mock_response
            self.api._set_auth_header()
            assert (
                self.api._session.headers["Authorization"]
                == "Bearer new_test_access_token"
            )


class TestConfig(TestWizBase):

    @patch.object(
        Config, "_jsonconfig", return_value={"api_url": "https://jsonurl.com"}
    )
    @patch.object(
        Config,
        "_iniconfig",
        return_value={
            "api_url": "https://iniurl.com",
            "auth_url": "https://iniauth.com",
            "client_id": "iniclientid",
            "client_secret": "iniclientsecret",
            "timeout": 60,
        },
    )
    @patch.object(
        Config,
        "_env",
        return_value={
            "api_url": "https://envurl.com",
            "auth_url": "https://envauth.com",
            "client_id": "envclientid",
            "client_secret": "envclientsecret",
            "timeout": 60,
        },
    )
    def test_load_order(self, mock_env, mock_ini, mock_json):
        """Test that options take precedence over env, JSON, and INI."""
        config = Config(
            options={
                "api_url": "https://optionurl.com",
                "auth_url": "https://optauth.com",
                "client_id": "optclientid",
                "client_secret": "optclientsecret",
                "timeout": 60,
            }
        )
        self.assertEqual(config["api_url"], "https://optionurl.com")

    @patch.object(
        Config,
        "_jsonconfig",
        return_value={
            "api_url": "https://jsonurl.com",
            "auth_url": "https://jsonauth.com",
            "client_id": "jsonclientid",
            "client_secret": "jsonclientsecret",
            "timeout": 60,
        },
    )
    @patch.object(
        Config,
        "_iniconfig",
        return_value={
            "api_url": "https://iniurl.com",
            "auth_url": "https://iniauth.com",
            "client_id": "iniclientid",
            "client_secret": "iniclientsecret",
            "timeout": 60,
        },
    )
    @patch.object(Config, "_env", return_value={})
    def test_json_over_ini(self, mock_env, mock_ini, mock_json):
        """Test that JSON config takes precedence over INI when ENV and options are not provided."""
        config = Config()
        self.assertEqual(config["api_url"], "https://jsonurl.com")

    @patch.object(Config, "_jsonconfig", return_value={})
    @patch.object(
        Config,
        "_iniconfig",
        return_value={
            "api_url": "https://iniurl.com",
            "auth_url": "https://iniauth.com",
            "client_id": "iniclientid",
            "client_secret": "iniclientsecret",
            "timeout": 60,
        },
    )
    @patch.object(Config, "_env", return_value={})
    def test_ini_when_no_json(self, mock_env, mock_ini, mock_json):
        """Test that INI config is used when JSON and ENV are not provided."""
        config = Config()
        self.assertEqual(config["api_url"], "https://iniurl.com")

    @patch.object(Config, "_jsonconfig", return_value={})
    @patch.object(Config, "_iniconfig", return_value={})
    @patch.object(
        Config,
        "_env",
        return_value={
            "api_url": "https://envurl.com",
            "auth_url": "https://envauth.com",
            "client_id": "envclientid",
            "client_secret": "envclientsecret",
            "timeout": 60,
        },
    )
    def test_env_when_no_ini_json(self, mock_env, mock_ini, mock_json):
        """Test that ENV config is used when JSON and INI are not provided."""
        config = Config()
        self.assertEqual(config["api_url"], "https://envurl.com")

    @patch.object(
        Config,
        "_jsonconfig",
        return_value={
            "api_url": "https://jsonurl.com",
            "auth_url": "https://jsonauth.com",
            "client_id": "jsonclientid",
            "client_secret": "jsonclientsecret",
            "timeout": 60,
        },
    )
    @patch.object(
        Config,
        "_iniconfig",
        return_value={
            "api_url": "https://iniurl.com",
            "auth_url": "https://iniauth.com",
            "client_id": "iniclientid",
            "client_secret": "iniclientsecret",
            "timeout": 60,
        },
    )
    @patch.object(
        Config,
        "_env",
        return_value={
            "api_url": "https://envurl.com",
            "auth_url": "https://envauth.com",
            "client_id": "envclientid",
            "client_secret": "envclientsecret",
            "timeout": 60,
        },
    )
    def test_combined_sources(self, mock_env, mock_ini, mock_json):
        """Test that configuration is combined from all sources correctly."""
        config = Config()
        self.assertEqual(config["client_id"], "envclientid")
        self.assertEqual(config["client_secret"], "envclientsecret")
        self.assertEqual(config["api_url"], "https://envurl.com")

    @patch.object(Config, "_jsonconfig", return_value={})
    @patch.object(Config, "_iniconfig", return_value={})
    @patch.object(Config, "_env", return_value={})
    def test_missing_keys(self, mock_env, mock_ini, mock_json):
        """Test that an error is raised if required keys are missing."""
        with self.assertRaises(ValueError) as cm:
            Config(options={})
        self.assertIn("Missing Wiz configuration keys", str(cm.exception))


class TestIniConfig(TestWizBase):
    def setUp(self):
        self.config = Config()
        self.path = Path("/path/to/config.ini")
        self.profile = "default"

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="[default]\nkey1=value1\nkey2=value2",
    )
    def test_iniconfig_with_valid_file_and_profile(self, mock_file):
        expected_config = {"key1": "value1", "key2": "value2"}
        config = self.config._iniconfig(self.path, self.profile)
        self.assertEqual(config, expected_config)

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="[other_profile]\nkey1=value1\nkey2=value2",
    )
    def test_iniconfig_with_valid_file_and_invalid_profile(self, mock_file):
        config = self.config._iniconfig(self.path, self.profile)
        self.assertEqual(config, {})

    @patch("builtins.open", side_effect=FileNotFoundError)
    def test_iniconfig_with_file_not_found(self, mock_open):
        config = self.config._iniconfig(self.path, self.profile)
        self.assertEqual(config, {})


class TestAccessToken(TestWizBase):
    @classmethod
    def setUpClass(cls):
        # Configure logging to display logs while running tests
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
        cls.logger = logging.getLogger("wizapi")

    def setUp(self):
        self.access_token_unstored = AccessToken(
            "test_client_id",
            "test_client_secret",
            "https://wiz.io/token",
            timeout=30,
            stored=True,
        )
        self.access_token_stored = AccessToken(
            "test_client_id",
            "test_client_secret",
            "https://wiz.io/token",
            timeout=30,
            stored=True,
        )

    @patch.object(
        AccessToken, "load_token", return_value={"access_token": "test_access_token"}
    )
    def test_access_token_from_storage_format_error(self, mock_load_token):

        at = AccessToken(
            "test_client_id",
            "test_client_secret",
            "https://wiz.io/token",
            timeout=30,
            stored=True,
        )
        with self.assertRaises(wiz2.WizError) as cm:
            at._load_token_from_storage()
        self.assertIn(
            "Invalid access token format. Expected a JWT token", str(cm.exception)
        )

    @patch.object(AccessToken, "load_token", return_value={"access_token": ""})
    def test_access_token_from_storage_valid_format(self, mock_load_token):

        at = AccessToken(
            "test_client_id",
            "test_client_secret",
            "https://wiz.io/token",
            timeout=30,
            stored=True,
        )
        with self.assertRaises(wiz2.WizError) as cm:
            at._load_token_from_storage()
        self.assertIn(
            "Invalid access token format. Expected a JWT token", str(cm.exception)
        )

    def test_access_token_from_storage_stored_false(self):

        at = AccessToken(
            "test_client_id",
            "test_client_secret",
            "https://wiz.io/token",
            timeout=30,
        )
        with self.assertRaises(wiz2.WizError) as cm:
            at._load_token_from_storage()
        self.assertIn(
            "Cannot load access token from storage as stored parameter is set to False",
            str(cm.exception),
        )

    def test_fetch_token(self):
        with patch("wiz2.requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {"access_token": "test_access_token"}
            mock_post.return_value = mock_response
            token = self.access_token_unstored._fetch_token_and_store()
            self.assertEqual(token, "test_access_token")


if __name__ == "__main__":
    unittest.main()
