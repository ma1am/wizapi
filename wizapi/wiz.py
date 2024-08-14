"""Wiz Api"""

import os
import json
import base64
import logging
import hashlib
import configparser
from pathlib import Path
from typing import Any, Optional, Generator
from dataclasses import dataclass
from datetime import datetime, timezone
import requests

logger = logging.getLogger("wizapi")
logger.setLevel(logging.DEBUG)

DEFAULT_WIZ_DIR = Path.home() / ".wiz"
DEFAULT_TIMEOUT = 300
DEFAULT_CONFIG_PROFILE = "default"
CONFIG_KEYS = {"client_id", "client_secret", "api_url", "auth_url", "timeout"}


@dataclass
class WizErrorCode:
    """Wiz Error Code

    Reference: https://docs.wiz.io/wiz-docs/docs/handling-api-errors
    """

    UNAUTHENTICATED = "Client token is either missing, invalid or expired"
    UNAUTHORIZED = "Client token scopes does not permit this action"
    BAD_USER_INPUT = "A query or mutation was given invalid arguments"
    INTERNAL = "An unexpected internal server error"
    RATE_LIMIT_EXCEEDED = "The client is being rate limited"
    FORBIDDEN_IP = "The client's IP is forbidden accessing this resource"
    NOT_FOUND = "Requested resource not found"


class WizError(Exception):
    """Base exception class for all wiz errors"""

    def __init__(
        self,
        msg: Optional[str] = None,
        status_code: Optional[int] = None,
        url: Optional[str] = None,
        json_data: Optional[dict] = None,
        raw: Optional[Any] = None,
    ) -> None:
        self.msg = msg or ""
        self.status_code = status_code or 0
        self.url = url or ""
        self.raw_data = raw or ""
        self.json_data = json_data or {}
        self._structure = self._structure_error()

    def __str__(self) -> str:
        return str(self._structure)

    def _structure_error(self):
        _structure: dict[str, Any] = {"message": self.msg or self.raw_data}
        if self.url:
            _structure["url"] = self.url
        if self.status_code:
            _structure["status_code"] = self.status_code
        _structure["json_data"] = self.json_data
        _structure["raw_data"] = self.raw_data
        return _structure


class RaiseWizError:
    """Parse Response and raise WizError if any"""

    def __init__(self, response: requests.Response):
        self.response = response
        self._eval()

    def _eval(self):
        if self.response.ok:
            return
        try:
            response = self.response.json()
            if error := response.get("errors"):
                code = error[0]["extensions"]["code"]
                msg = getattr(WizErrorCode, code, error[0]["message"])
                status_code = error[0]["extensions"]["http"]["status"]
                raise WizError(
                    msg=msg,
                    status_code=status_code,
                    raw=error[0],
                    json_data=error[0],
                    url=self.response.url,
                )

        except json.decoder.JSONDecodeError as e:
            msg = f" {self.response.status_code} {self.response.reason} {self.response.text} "

            try:
                self.response.raise_for_status()
            except requests.exceptions.HTTPError as er:
                raise WizError(
                    msg=msg,
                    status_code=self.response.status_code,
                    raw=self.response.text,
                    url=self.response.url,
                ) from er

            raise WizError(
                msg=msg,
                status_code=self.response.status_code,
                raw=self.response.text,
                url=self.response.url,
            ) from e


def http_error_handler():
    """Handle Wiz / HTTP Error"""

    def decorator(func):
        def wrapper(*args, **kwargs):

            try:
                response: requests.Response = func(*args, **kwargs)
                RaiseWizError(response)
            except requests.exceptions.RequestException as e:
                raise WizError(str(e)) from e

            RaiseWizError(response)
            return response

        return wrapper

    return decorator


class TokenStorage:
    """Handles token storage and retrieval."""

    def __init__(self, client_id: str) -> None:
        self._path = self._get_credential_path(client_id)

    def save_token(self, token_data: dict[str, Any]) -> None:
        """Save token data to a file."""
        try:
            self._write_to_file(token_data)
            logger.debug("Token saved to %s", self._path)
        except (FileNotFoundError, PermissionError) as e:
            logger.debug("Error while saving token: %s", e)
            self._handle_save_error(token_data)

    def load_token(self) -> dict[str, Any]:
        """Load token data from a file if it exists."""
        try:
            with open(self._path, "r", encoding="utf-8") as file:
                return json.load(file)
        except FileNotFoundError:
            logger.debug("Token file not found: %s", self._path)
        except json.JSONDecodeError:
            logger.debug("Invalid JSON in the token file: %s", self._path)
        return {}

    def _write_to_file(self, token_data: dict[str, Any]) -> None:
        """Helper method to write token data to a file."""
        with open(self._path, "w", encoding="utf-8") as file:
            json.dump(token_data, file, indent=4, default=self._format_datetime)

    def _handle_save_error(self, token_data: dict[str, Any]) -> None:
        """Handle errors encountered during saving."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._write_to_file(token_data)
        except PermissionError:
            logger.debug("Permission error while saving token to %s", self._path)

    @staticmethod
    def _format_datetime(o: Any) -> str:
        """Convert datetime objects to string."""
        if isinstance(o, datetime):
            return o.isoformat()
        return str(o)

    def _get_credential_path(self, client_id: str) -> Path:
        """Generate and return the path for the credentials file."""
        return (
            DEFAULT_WIZ_DIR
            / "credentials"
            / f"credentials_{self._hash_client_id(client_id)}.json"
        )

    @staticmethod
    def _hash_client_id(client_id: str) -> str:
        """Return the MD5 hash of the client ID."""
        return hashlib.md5(client_id.encode("utf-8")).hexdigest()


class Config:
    """
    Configuration class for loading and managing API configuration settings.
    """

    def __init__(self, **kwargs) -> None:
        """
        Configuration class for loading and managing API configuration settings.

        It creates configuration items by loading them from various sources such as
        environment variables, JSON files, and INI files. It also validates and merges these
        configurations into a single dictionary.

        Attributes:

            - **kwargs: User provided configuration options such as:
                - client_id (Optional[str]): The client ID for authentication.
                - client_secret (Optional[str]): The client secret for authentication.
                - api_url (Optional[str]): The API URL.
                - auth_url (Optional[str]): The authentication URL.
                - timeout (Optional[int]): The timeout value for API requests.
        """
        config = self._create_config(self._options(**kwargs))
        self._validate_config(config)
        self.client_id: str = config.get("client_id", "")
        self.client_secret: str = config.get("client_secret", "")
        self.api_url: str = config.get("api_url", "")
        self.auth_url: str = config.get("auth_url", "")
        self.timeout: int = config.get("timeout", DEFAULT_TIMEOUT)

    def _validate_config(self, conf):
        if missing := CONFIG_KEYS - set(list(conf)):
            raise ValueError(f"Missing Wiz configuration keys: {', '.join(missing)}")

    def _options(self, **kwargs):
        return {k: v for k, v in kwargs.items() if k in CONFIG_KEYS and v}

    def _create_config(self, options: dict[str, str]):
        """Loads config from ENV, Json File, INI config file and the options.

        Returns the config in the prefence of options, env, json & ini

        """
        envconf = {k.split("WIZ_")[-1].lower(): v for k, v in self._env().items()}
        iniconf = self._iniconfig(DEFAULT_WIZ_DIR / "config", DEFAULT_CONFIG_PROFILE)
        jsonconf = self._jsonconfig(DEFAULT_WIZ_DIR / "config.json")
        return {**iniconf, **jsonconf, **envconf, **options}

    def _env(self):
        """Helper function to retrieve environment variables."""
        return {k: v for k, v in os.environ.items() if k.startswith("WIZ_")}

    def _iniconfig(self, path: Path, profile: str):
        """Helper function to retrieve the configuration."""
        try:
            c = configparser.ConfigParser()
            c.read(path)
            return dict(c.items(profile))
        except (FileNotFoundError, configparser.NoSectionError) as e:
            logger.debug(e)
            return {}

    def _jsonconfig(self, path: Path):
        """Helper function to retrieve the configuration from a JSON file."""
        try:
            with open(path, "r", encoding="utf-8") as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError, NotADirectoryError) as e:
            logger.debug(e)
            return {}


class OAuthAccessToken(Config):
    """Manages OAuth access token retrieval and storage."""

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        api_url: Optional[str] = None,
        auth_url: Optional[str] = None,
        timeout: int = 60,
        stored: bool = False,
    ) -> None:
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            api_url=api_url,
            auth_url=auth_url,
            timeout=timeout,
        )
        self._stored = stored
        self._access_token = ""
        self._token_data = {}
        self._storage = TokenStorage(self.client_id) if self._stored else None

    def _retrieve_accesstoken(self, force: bool = False):
        """Load a valid access token, either from storage or by requesting a new one."""

        if force:
            self._access_token = self._fetch_token_and_store()

        else:
            if self._stored and self._storage:
                self._access_token = self._load_token_from_storage()

        if not self._access_token:
            self._access_token = self._fetch_token_and_store()

    def _load_token_from_storage(self) -> Optional[str]:
        """Attempt to load and validate the access token from storage."""
        if self._storage:
            access_token = self._storage.load_token().get("access_token", "")
            return access_token if self._is_valid(access_token) else None

    def _fetch_token_and_store(self) -> str:
        """Request a new access token and _save it to storage."""
        token_data = self._request_access_token()
        if self._storage:
            self._storage.save_token(token_data)
        return token_data["access_token"]

    def _request_access_token(self) -> dict[str, Any]:
        """Request a new access token from the auth server."""

        payload = {
            "grant_type": "client_credentials",
            "audience": "wiz-api",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return self._make_request(self.auth_url, data=payload, headers=headers).json()

    def _is_valid(self, access_token: str) -> bool:
        """Check if the access_token is still valid."""
        exp = self._decode_access_token(access_token).get("exp", "")
        return datetime.now(timezone.utc).replace(tzinfo=None) < datetime.fromtimestamp(
            int(exp)
        )

    def _decode_access_token(self, access_token: str):
        """Pad an OAuth access token, decode, and load into a dictionary"""
        data = access_token.split(".")[1]
        missing_padding = len(data) % 4
        if missing_padding != 0:
            data += "=" * (4 - missing_padding)
        try:
            token_data = json.loads(base64.b64decode(data))
        except Exception as e:
            raise WizError(
                f"Error parsing the Wiz API access token: {e}", raw=str(e)
            ) from e
        return token_data

    @http_error_handler()
    def _make_request(self, url: str, **kwargs) -> requests.Response:
        """Make an HTTP request and returns `Response`"""
        return requests.post(url, timeout=self.timeout, **kwargs)


class Wiz(OAuthAccessToken):
    """Class for making API calls to the Wiz API."""

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        api_url: Optional[str] = None,
        auth_url: Optional[str] = None,
        timeout: int = 60,
        stored: bool = False,
    ) -> None:

        super().__init__(client_id, client_secret, api_url, auth_url, timeout, stored)

        self._session = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})
        self._set_auth_header()
        self._data = {}
        self._has_next_page = False
        self._end_cursor = None
        self._data_key = ""

    def query(self, graph_query: str, variables: dict) -> dict[str, Any]:
        """
        General purpose query() method for Wiz GraphQL endpoint.

        Args:
            - query (str): The GraphQL query to execute.
            - variables (dict): The variables to pass to the GraphQL query.

        Returns:
            dict: The raw data returned by the Wiz API.

        Reference: https://docs.wiz.io/wiz-docs/docs/using-the-wiz-api#communicating-with-graphql
        """
        self._data = {"variables": variables, "query": graph_query}
        result = self._post_with_session().json()
        return result

    def query_all(
        self, graph_query: str, variables: dict
    ) -> Generator[dict[str, Any], Any, None]:
        """
        This method implements pagination to fetch data from Wiz GraphQL endpoint.

        Args:
            - variables (dict): The variables to pass to the GraphQL query.
            - query (str): The GraphQL query to execute.

        Returns:
            Generator[dict]: The raw data returned by the Wiz API.

        Raises:
            WizError: If no data key is found in the response.

        Usage:
            >>> for data in wiz.query_all(query, variables):
            >>>    print(data)
        Reference: https://docs.wiz.io/wiz-docs/docs/using-the-wiz-api#communicating-with-graphql
        """

        self._data = {"variables": variables, "query": graph_query}
        result = self._post_with_session().json()

        yield result

        try:
            self._data_key = list(result["data"])[0]
        except IndexError as e:
            raise WizError("No data key found in the response to paginate") from e
        self._set_pagination(result)

        if self._has_next_page:
            yield from self._paginate()

    def _paginate(self):
        """Yields the paginated data"""
        while self._has_next_page:
            self._data["variables"]["after"] = self._end_cursor
            result = self._post_with_session().json()
            yield result
            self._set_pagination(result)

    def _set_pagination(self, result: dict) -> None:
        """Set the pagination keys"""
        page_info = result["data"][self._data_key].get("pageInfo", {})
        self._has_next_page = page_info.get("hasNextPage", False)
        self._end_cursor = page_info.get("endCursor", None)

    def _set_auth_header(self, force: bool = False) -> None:
        """Update the access token."""
        self._retrieve_accesstoken(force)
        self._session.headers.update({"Authorization": f"Bearer {self._access_token}"})

    @http_error_handler()
    def _post_with_session(self, **kwargs) -> requests.Response:
        """Make an HTTP request and returns json data"""
        response = self._session.post(
            self.api_url, timeout=self.timeout, json=self._data, **kwargs
        )
        if response.status_code == 401:
            self._set_auth_header(True)
            response = self._session.post(
                self.api_url, timeout=self.timeout, json=self._data, **kwargs
            )

        return response
