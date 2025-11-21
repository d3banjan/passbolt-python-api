import configparser
import json
import logging
import urllib.parse
from typing import List, Mapping, Optional, Tuple, Union, Dict, Any, TypeVar

import os
import gnupg
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .cache import Cache, default_cache
from passboltapi.schema import (
    AllPassboltTupleTypes,
    PassboltDateTimeType,
    PassboltFavoriteDetailsType,
    PassboltFolderIdType,
    PassboltFolderTuple,
    PassboltGroupIdType,
    PassboltGroupTuple,
    PassboltOpenPgpKeyIdType,
    PassboltOpenPgpKeyTuple,
    PassboltPermissionIdType,
    PassboltPermissionTuple,
    PassboltResourceIdType,
    PassboltResourceTuple,
    PassboltResourceType,
    PassboltResourceTypeIdType,
    PassboltResourceTypeTuple,
    PassboltRoleIdType,
    PassboltSecretIdType,
    PassboltSecretTuple,
    PassboltTagIdType,
    PassboltTagTuple,
    PassboltUserIdType,
    PassboltUserTuple,
    constructor,
)

# Type variable for generic method returns
T = TypeVar('T')

# Cache timeouts in seconds
CACHE_TTL = {
    'user': 300,        # 5 minutes
    'resource': 60,     # 1 minute
    'folder': 300,      # 5 minutes
    'group': 600,       # 10 minutes
    'tag': 60,          # 1 minute
    'permission': 300,  # 5 minutes
    'gpg': 3600,        # 1 hour
}

LOGIN_URL = "/auth/login.json"
VERIFY_URL = "/auth/verify.json"


class PassboltValidationError(Exception):
    pass


class PassboltError(Exception):
    pass


class APIClient:
    def __init__(
        self,
        config: Optional[str] = None,
        config_path: Optional[str] = None,
        new_keys: bool = False,
        delete_old_keys: bool = False,
        ssl_verify: bool = True,
        cert_auth: bool = False
    ):
        """
        :param config: Config as a dictionary
        :param config_path: Path to the config file.
        :param delete_old_keys: Set true if old keys need to be deleted
        """
        self.ssl_verify = ssl_verify
        self.config = config
        self.cert_auth = cert_auth
        self.cert = None
        if config_path:
            self.config = configparser.ConfigParser()
            self.config.read_file(open(config_path))
        self.requests_session = requests.Session()

        if not self.config:
            raise ValueError("Missing config. Provide config as dictionary or path to configuration file.")
        if not self.config["PASSBOLT"]["SERVER"]:
            raise ValueError("Missing value for SERVER in config.ini")

        self.server_url = self.config["PASSBOLT"]["SERVER"].rstrip("/")

        if self.cert_auth:
            if not (self.config["PASSBOLT"]["SERVER_CERT_AUTH_CRT"] and self.config["PASSBOLT"]["SERVER_CERT_AUTH_KEY"]):
                raise ValueError("Missing certificate and key in config.ini")
            self.cert = (self.config["PASSBOLT"]["SERVER_CERT_AUTH_CRT"], self.config["PASSBOLT"]["SERVER_CERT_AUTH_KEY"])
        
        self.user_fingerprint = self.config["PASSBOLT"]["USER_FINGERPRINT"].upper().replace(" ", "")
        self.gpg = gnupg.GPG()
        if delete_old_keys:
            self._delete_old_keys()
        if new_keys:
            self._import_gpg_keys()
        try:
            self.gpg_fingerprint = [i for i in self.gpg.list_keys() if i["fingerprint"] == self.user_fingerprint][0][
                "fingerprint"
            ]
        except IndexError:
            raise Exception("GPG public key could not be found. Check: gpg --list-keys")

        if self.user_fingerprint not in [i["fingerprint"] for i in self.gpg.list_keys(True)]:
            raise Exception("GPG private key could not be found. Check: gpg --list-secret-keys")
        
        # Initialize current user cache
        self._current_user = None
        self._current_user_id = None
        
        self._login()

    def __enter__(self):
        return self

    def __del__(self):
        self.close_session()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close_session()

    def _delete_old_keys(self):
        for i in self.gpg.list_keys():
            self.gpg.delete_keys(i["fingerprint"], True, passphrase="")
            self.gpg.delete_keys(i["fingerprint"], False)

    def _import_gpg_keys(self):
        if not self.config["PASSBOLT"]["USER_PUBLIC_KEY_FILE"]:
            raise ValueError("Missing value for USER_PUBLIC_KEY_FILE in config.ini")
        if not self.config["PASSBOLT"]["USER_PRIVATE_KEY_FILE"]:
            raise ValueError("Missing value for USER_PRIVATE_KEY_FILE in config.ini")
        self.gpg.import_keys(open(self.config["PASSBOLT"]["USER_PUBLIC_KEY_FILE"]).read())
        self.gpg.import_keys(open(self.config["PASSBOLT"]["USER_PRIVATE_KEY_FILE"]).read())

    def _login(self):
        r = self.requests_session.post(self.server_url + LOGIN_URL, json={"gpg_auth": {"keyid": self.gpg_fingerprint}}, verify=self.ssl_verify, cert=self.cert) # None is the default value in requests
        encrypted_token = r.headers["X-GPGAuth-User-Auth-Token"]
        encrypted_token = urllib.parse.unquote(encrypted_token)
        encrypted_token = encrypted_token.replace(r"\+", " ")
        token = self.decrypt(encrypted_token)
        self.requests_session.post(
            self.server_url + LOGIN_URL,
            json={
                "gpg_auth": {"keyid": self.gpg_fingerprint, "user_token_result": token},
            },
        )
        try:
            self._get_csrf_token()
        except requests.exceptions.HTTPError as e:
            if (
                e.response.status_code != requests.status_codes.codes.forbidden
                or e.response.json()["header"]["message"]
                != "MFA authentication is required."
            ):
                logging.error(r.text)
                raise e
            if not self.config["PASSBOLT"]["OTP"]:
                raise ValueError("Missing value for OTP in config.ini")
            self.post("/mfa/verify/totp.json", {"totp": self.config["PASSBOLT"]["OTP"]})

    def _get_csrf_token(self):
        """Fetches the X-CSRF-Token header for future requests"""
        r = self.requests_session.get(self.server_url + "/users/me.json")
        r.raise_for_status()

    def encrypt(self, text, recipients=None):
        return str(self.gpg.encrypt(data=text, recipients=recipients or self.gpg_fingerprint, always_trust=True))

    def decrypt(self, text):
        if "PASSPHRASE" in self.config["PASSBOLT"]:
            passphrase = str(self.config["PASSBOLT"]["PASSPHRASE"])
        else:
            passphrase = None


        return str(self.gpg.decrypt(text, always_trust=True, passphrase=passphrase))

    def get_headers(self):
        return {
            "X-CSRF-Token": self.requests_session.cookies["csrfToken"]
            if "csrfToken" in self.requests_session.cookies
            else ""
        }

    def get_server_public_key(self):
        r = self.requests_session.get(self.server_url + VERIFY_URL)
        return r.json()["body"]["fingerprint"], r.json()["body"]["keydata"]

    def delete(self, url):
        r = self.requests_session.delete(self.server_url + url, headers=self.get_headers())
        try:
            r.raise_for_status()
            return r.json()
        except requests.exceptions.HTTPError as e:
            logging.error(r.text)
            raise e

    def get(self, url, return_response_object=False, **kwargs):
        r = self.requests_session.get(self.server_url + url, headers=self.get_headers(), **kwargs)
        try:
            r.raise_for_status()
            if return_response_object:
                return r
            return r.json()
        except requests.exceptions.HTTPError as e:
            logging.error(r.text)
            raise e

    def put(self, url, data, return_response_object=False, **kwargs):
        r = self.requests_session.put(self.server_url + url, json=data, headers=self.get_headers(), **kwargs)
        try:
            r.raise_for_status()
            if return_response_object:
                return r
            return r.json()
        except requests.exceptions.HTTPError as e:
            logging.error(r.text)
            raise e

    def post(self, url, data, return_response_object=False, **kwargs):
        r = self.requests_session.post(self.server_url + url, json=data, headers=self.get_headers(), **kwargs)
        try:
            r.raise_for_status()
            if return_response_object:
                return r
            return r.json()
        except requests.exceptions.HTTPError as e:
            logging.error(r.text)
            raise e

    def close_session(self):
        self.requests_session.close()


class PassboltAPI(APIClient):
    """Adding a convenience method for getting resources.

    Design Principle: All passbolt aware public methods must accept or output one of PassboltTupleTypes"""

    def __init__(
        self,
        # --- High-level explicit parameters (preferred modern interface) ---
        server_url: Optional[str] = None,
        private_key_path: Optional[str] = None,
        passphrase: Optional[str] = None,
        verify: Union[bool, str] = True,
        timeout: int = 30,
        enable_caching: bool = True,
        cache_ttl: Optional[Dict[str, int]] = None,
        # --- Back-compat parameters accepted by the base APIClient ---
        config: Optional[str] = None,
        config_path: Optional[str] = None,
        new_keys: bool = False,
        delete_old_keys: bool = False,
        ssl_verify: bool = True,
        cert_auth: bool = False,
    ) -> None:
        """
        Initialize the Passbolt API client.

        Args:
            server_url: Base URL of the Passbolt server (e.g., 'https://passbolt.example.com')
            private_key_path: Path to the private key file
            passphrase: Passphrase for the private key
            verify: Either a boolean, in which case it controls whether we verify
                   the server's TLS certificate, or a string, in which case it must be a path
                   to a CA bundle to use. Defaults to True.
            timeout: Timeout in seconds for API requests. Defaults to 30.
            enable_caching: Whether to enable caching of API responses. Defaults to True.
            cache_ttl: Custom TTL values for different cache types. Defaults to None.
        """
        # ------------------------------------------------------------
        # 1. Initialise the low-level APIClient if a config(_path) is
        #    supplied (legacy / fixtures rely on this). This sets up
        #    self.requests_session, self.server_url, GPG, etc.
        # ------------------------------------------------------------
        if config_path is not None or config is not None:
            super().__init__(
                config=config,
                config_path=config_path,
                new_keys=new_keys,
                delete_old_keys=delete_old_keys,
                ssl_verify=ssl_verify,
                cert_auth=cert_auth,
            )
            # Expose the same Session object under the attribute expected
            # by the newer helper code.
            self.session = self.requests_session
            # Derive passphrase / private key path from config if absent.
            if passphrase is None:
                passphrase = self.config["PASSBOLT"].get("PASSPHRASE", "")
            if private_key_path is None:
                private_key_path = self.config["PASSBOLT"].get("USER_PRIVATE_KEY_FILE", "")
            if server_url is None:
                server_url = self.server_url
        else:
            # New-style initialisation without config file.
            # Ensure server_url doesn't end with a slash
            if server_url is None:
                raise ValueError("server_url must be provided when not using config_path/config")
            self.server_url = server_url.rstrip('/')
            self.session = requests.Session()
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
            # Set up SSL verification
            self.session.verify = verify

        # Common attributes
        self.private_key_path = os.path.expanduser(private_key_path) if private_key_path else None
        self.passphrase = passphrase or ""
        self.timeout = timeout
        self._current_user: Optional[PassboltUserTuple] = None
        self._current_user_id: Optional[PassboltUserIdType] = None
        self._enable_caching = enable_caching
        
        # Set up cache with custom TTLs if provided
        if enable_caching:
            self._cache = Cache()
            # Update cache TTLs if custom values provided
            if cache_ttl:
                for key, ttl in cache_ttl.items():
                    if key in CACHE_TTL:
                        CACHE_TTL[key] = ttl
        else:
            self._cache = None

        # Cache has been set up earlier (self._cache).
        # Set up logging
        self.logger = logging.getLogger(__name__)

        # Get the current user
        self.get_current_user()

    def _json_load_secret(self, secret: PassboltSecretTuple) -> Tuple[str, Optional[str]]:
        try:
            secret_dict = json.loads(self.decrypt(secret.data))
            return secret_dict["password"], secret_dict["description"]
        except (json.decoder.JSONDecodeError, KeyError):
            return self.decrypt(secret.data), None

    def _encrypt_secrets(self, secret_text: str, recipients: List[PassboltUserTuple]) -> List[Mapping]:
        return [
            {"user_id": user.id, "data": self.encrypt(secret_text, user.gpgkey.fingerprint)} for user in recipients
        ]

    def _get_secret(self, resource_id: PassboltResourceIdType) -> PassboltSecretTuple:
        response = self.get(f"/secrets/resource/{resource_id}.json")
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        return PassboltSecretTuple(**response["body"])

    def _update_secret(self, resource_id: PassboltResourceIdType, new_secret):
        return self.put(f"/resources/{resource_id}.json", {"secrets": new_secret}, return_response_object=True)

    def _get_secret_type(self, resource_type_id: PassboltResourceTypeIdType) -> PassboltResourceType:
        resource_type: PassboltResourceTypeTuple = self.read_resource_type(resource_type_id=resource_type_id)
        resource_definition = json.loads(resource_type.definition)
        if resource_definition["secret"]["type"] == "string":
            return PassboltResourceType.PASSWORD
        if resource_definition["secret"]["type"] == "object" and set(
            resource_definition["secret"]["properties"].keys()
        ) == {"password", "description"}:
            return PassboltResourceType.PASSWORD_WITH_DESCRIPTION
        raise PassboltError("The resource type definition is not valid or supported yet. ")

    def get_password_and_description(self, resource_id: PassboltResourceIdType) -> dict:
        resource: PassboltResourceTuple = self.read_resource(resource_id=resource_id)
        secret: PassboltSecretTuple = self._get_secret(resource_id=resource_id)
        secret_type = self._get_secret_type(resource_type_id=resource.resource_type_id)
        if secret_type == PassboltResourceType.PASSWORD:
            return {"password": self.decrypt(secret.data), "description": resource.description}
        elif secret_type == PassboltResourceType.PASSWORD_WITH_DESCRIPTION:
            pwd, desc = self._json_load_secret(secret=secret)
            return {"password": pwd, "description": desc}

    def get_password(self, resource_id: PassboltResourceIdType) -> str:
        return self.get_password_and_description(resource_id=resource_id)["password"]

    def get_description(self, resource_id: PassboltResourceIdType) -> str:
        return self.get_password_and_description(resource_id=resource_id)["description"]

    def iterate_resources(self, params: Optional[dict] = None):
        params = params or {}
        url_params = urllib.parse.urlencode(params)
        if url_params:
            url_params = "?" + url_params
        response = self.get("/resources.json" + url_params)
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        resources = response["body"]
        yield from resources

    def list_resources(
        self,
        folder_id: Optional[PassboltFolderIdType] = None,
        **filters
    ) -> List[PassboltResourceTuple]:
        """
        List resources with optional filtering.

        Args:
            folder_id: (Optional) Filter resources by folder ID (backward compatibility)
            **filters: Additional filters to apply. Common filters include:
                - has_parent: Filter resources by parent folder UUID (string).
                - has_tag: Filter resources by tag name (string or list of strings).
                          For multiple tags, resources matching ANY of the tags will be returned.
                          Example: has_tag="api" or has_tag=["api", "backend"]
                - has_id: Filter by resource ID(s). Can be a single ID or list of IDs.
                - search: Search in name, username, uri, and description.
                - is_shared_with_group: Filter resources shared with a specific group.
                - is_owned_by_me: Filter resources owned by the current user (boolean).
                - is_shared_with_me: Filter resources shared with the current user (boolean).
                - has_access: Filter resources accessible by a specific user ID.

                Example:
                    list_resources(has_parent="d72d75fd-b79b-4fa5-a87e-e15a481524f7")
                    list_resources(has_tag="api", search="production")
                    list_resources(is_shared_with_me=True)
                    list_resources(has_id=["id1", "id2"])

        Returns:
            List[PassboltResourceTuple]: List of resources with tags and permissions included
        """
        # Create a cache key based on the method name and arguments
        cache_key = None
        if self._enable_caching:
            # Create a stable string representation of the filters for the cache key
            filter_str = ",".join(f"{k}={v}" for k, v in sorted(filters.items()))
            cache_key = f"list_resources:folder_id={folder_id}:{filter_str}"
            
            # Try to get from cache first
            cached_result = self._cache.get(cache_key)
            if cached_result is not None:
                return cached_result
        
        # Initialize params with default values
        params = {}
        
        # Handle folder_id for backward compatibility
        if folder_id is not None:
            params["filter[has-id][]"] = folder_id
        
        # Process additional filters
        for key, value in filters.items():
            if value is None:
                continue

            # Convert snake_case to kebab-case for API compatibility
            filter_key = key.replace('_', '-')

            # Handle special cases
            if filter_key == 'has-tag':
                # For tags, we use filter[has-tag]=value format for single tag
                # and multiple filter[has-tag]=value1&filter[has-tag]=value2 for multiple tags
                if isinstance(value, (list, tuple, set)):
                    for tag in value:
                        params["filter[has-tag]"] = tag
                else:
                    params["filter[has-tag]"] = value
            elif filter_key == 'has-parent':
                params["filter[has-parent]"] = value
            elif filter_key == 'search':
                params["filter[search]"] = value
            elif filter_key == 'is-shared-with-group':
                params["filter[is-shared-with-group]"] = value
            elif filter_key == 'is-owned-by-me':
                if value:
                    params["filter[is-owned-by-me]"] = 1
            elif filter_key == 'is-shared-with-me':
                if value:
                    params["filter[is-shared-with-me]"] = 1
            elif filter_key == 'has-access':
                params["filter[has-access]"] = value
            elif filter_key == 'has-id':
                if isinstance(value, (list, tuple, set)):
                    for i, v in enumerate(value):
                        params[f"filter[has-id][{i}]"] = v
                else:
                    params["filter[has-id][]"] = value
            else:
                # For any other filter, pass it through as-is
                params[f"filter[{filter_key}]"] = value

        # Always include favorite information
        params["contain[favorite]"] = 1

        # Include tags and permissions when filtering (more targeted queries)
        # This avoids server errors on some Passbolt versions when listing all resources
        # Note: Some servers don't support contain parameters with search, so exclude them
        has_search_filter = filters.get('search') is not None
        if (folder_id is not None or len(filters) > 0) and not has_search_filter:
            params["contain[tags]"] = 1
            params["contain[permissions]"] = 1

        # Get resources
        response = self.get("/resources.json", params=params)
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        
        # If we're filtering by folder, we need to use the folder endpoint
        if folder_id is not None and len(filters) == 0:
            response = self.get("/folders.json", params={"filter[has-id][]": folder_id, "contain[children_resources]": 1})
            if response["body"] and len(response["body"]) > 0 and "children_resources" in response["body"][0]:
                resources = response["body"][0]["children_resources"]
                result = constructor(
                    PassboltResourceTuple,
                    subconstructors={
                        "permissions": constructor(PassboltPermissionTuple),
                        "tags": constructor(PassboltTagTuple),
                    },
                )(resources)
                if self._enable_caching and cache_key:
                    self._cache.set(cache_key, result, ttl=CACHE_TTL.get("resource", 60))
                return result
            return []

        result = constructor(
            PassboltResourceTuple,
            subconstructors={
                "permissions": constructor(PassboltPermissionTuple),
                "tags": constructor(PassboltTagTuple),
            },
        )(response["body"])

        # Cache the result
        if self._enable_caching and cache_key:
            self._cache.set(cache_key, result, ttl=CACHE_TTL.get("resource", 60))

        return result

    def list_users_with_folder_access(self, folder_id: PassboltFolderIdType) -> List[PassboltUserTuple]:
        folder_tuple = self.describe_folder(folder_id)
        # resolve users
        user_ids = set()
        # resolve users from groups
        for perm in folder_tuple.permissions:
            if perm.aro == "Group":
                group_tuple: PassboltGroupTuple = self.describe_group(perm.aro_foreign_key)
                for group_user in group_tuple.groups_users:
                    user_ids.add(group_user["user_id"])
            elif perm.aro == "User":
                user_ids.add(perm.aro_foreign_key)
        return [user for user in self.list_users() if user.id in user_ids]

    def list_users(
        self, resource_or_folder_id: Union[None, PassboltResourceIdType, PassboltFolderIdType] = None, force_list=True
    ) -> List[PassboltUserTuple]:
        if resource_or_folder_id is None:
            params = {}
        else:
            params = {"filter[has-access]": resource_or_folder_id, "contain[user]": 1}
        params["contain[permission]"] = True
        response = self.get(f"/users.json", params=params)
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        response = response["body"]
        users = constructor(
            PassboltUserTuple,
            subconstructors={
                "gpgkey": constructor(PassboltOpenPgpKeyTuple),
            },
        )(response)
        if isinstance(users, PassboltUserTuple) and force_list:
            return [users]
        return users

    def import_public_keys(self, trustlevel="TRUST_FULLY"):
        # get all users
        users = self.list_users()
        for user in users:
            self.gpg.import_keys(user.gpgkey.armored_key)
            self.gpg.trust_keys(user.gpgkey.fingerprint, trustlevel)

    def read_resource(self, resource_id: PassboltResourceIdType) -> PassboltResourceTuple:
        """
        Read a single resource with its permissions and tags.

        Args:
            resource_id: The UUID of the resource to read

        Returns:
            PassboltResourceTuple: The resource with permissions and tags included
        """
        # Ask for permissions and tags
        params = {
            "contain[permissions]": 1,
            "contain[tags]": 1,
        }
        response_obj = self.get(
            f"/resources/{resource_id}.json",
            params=params,
            return_response_object=True,
        )
        response = response_obj.json()["body"]
        # Normalize key name - ensure we use `permissions` (plural)
        if "permission" in response and "permissions" not in response:
            response["permissions"] = response.pop("permission")
        # If permissions is a single object, wrap it in a list
        if "permissions" in response and not isinstance(response["permissions"], list):
            response["permissions"] = [response["permissions"]]
        return constructor(
            PassboltResourceTuple,
            subconstructors={
                "permissions": constructor(PassboltPermissionTuple),
                "tags": constructor(PassboltTagTuple),
            },
        )(response)

    def read_resource_type(self, resource_type_id: PassboltResourceTypeIdType) -> PassboltResourceTypeTuple:
        response = self.get(f"/resource-types/{resource_type_id}.json", return_response_object=True)
        response = response.json()["body"]
        return constructor(PassboltResourceTypeTuple)(response)

    def read_folder(self, folder_id: PassboltFolderIdType) -> PassboltFolderTuple:
        response = self.get(
            f"/folders/{folder_id}.json", params={"contain[permissions]": True}, return_response_object=True
        )
        response = response.json()
        return constructor(PassboltFolderTuple, subconstructors={"permissions": constructor(PassboltPermissionTuple)})(
            response["body"]
        )

    def create_folder(self, name: str, folder_parent_id: Optional[PassboltFolderIdType] = None) -> PassboltFolderTuple:
        """
        Create a new folder in Passbolt.
        
        Args:
            name: Name of the folder to create
            folder_parent_id: (Optional) ID of the parent folder. If None, creates in root.
            
        Returns:
            PassboltFolderTuple: The created folder
        """
        folder_data = {
            "name": name,
        }
        
        # Only add folder_parent_id if it's provided
        if folder_parent_id:
            folder_data["folder_parent_id"] = folder_parent_id
            
        response = self.post("/folders.json", folder_data)
        assert "body" in response, f"Response missing 'body' key: {response}"
        
        # Return the created folder as a named tuple
        return constructor(PassboltFolderTuple)(response["body"])

    def describe_folder(self, folder_id: PassboltFolderIdType):
        """Shows folder details with permissions that are needed for some downstream task."""
        response = self.get(
            f"/folders/{folder_id}.json",
            params={
                "contain[permissions]": 1,
                "contain[permissions.user.profile]": 1,
                "contain[permissions.group]": 1,
            },
        )
        assert "body" in response.keys(), f"Key 'body' not found in response keys: {response.keys()}"
        assert (
            "permissions" in response["body"].keys()
        ), f"Key 'body.permissions' not found in response: {response['body'].keys()}"
        return constructor(
            PassboltFolderTuple,
            subconstructors={
                "permissions": constructor(PassboltPermissionTuple),
            }
        )(response["body"])

    def move_resource_to_folder(self, resource_id: PassboltResourceIdType, folder_id: PassboltFolderIdType) -> PassboltResourceTuple:
        """Move a resource to a folder.
        
        Args:
            resource_id: ID of the resource to move
            folder_id: ID of the folder to move the resource to
            
        Returns:
            PassboltResourceTuple: The updated resource with the new folder parent ID
        """
        self.post(
            f"/move/resource/{resource_id}.json", 
            {"folder_parent_id": folder_id}, 
            return_response_object=True
        )
        # Return the updated resource to ensure we have the latest state
        return self.read_resource(resource_id=resource_id)

    def get_current_user(self) -> PassboltUserTuple:
        """Return the current authenticated Passbolt user (cached)."""
        if self._current_user is not None:
            return self._current_user
        # Fallback to ID helper which will populate _current_user
        _ = self._get_current_user_id()
        assert self._current_user is not None, "_get_current_user_id did not populate _current_user"
        return self._current_user

    def _get_current_user_id(self) -> str:
        """
        Get the current user ID, using cached value if available.
        
        Returns:
            str: The current user's ID
            
        Raises:
            ValueError: If the current user cannot be found
        """
        if self._current_user_id is None:
            # Get all users and find the one with matching fingerprint
            all_users = {user.id: user for user in self.list_users()}
            for user_id, user in all_users.items():
                if (hasattr(user, 'gpgkey') and 
                    hasattr(user.gpgkey, 'fingerprint') and 
                    user.gpgkey.fingerprint == self.user_fingerprint):
                    self._current_user_id = user_id
                    self._current_user = user
                    break
            
            if self._current_user_id is None:
                raise ValueError("Current user not found in the list of users")
                
        return self._current_user_id

    def share_folder(
        self,
        folder_id: PassboltFolderIdType,
        permissions: List[dict],
        replace: bool = False,
    ) -> bool:
        """
        Share a folder with the specified users/groups.

        Args:
            folder_id: The ID of the folder to share
            permissions: List of permission dictionaries with keys:
                - aro: 'User' or 'Group'
                - aro_foreign_key: ID of the user or group
                - type: Permission type (1 = Read, 7 = Update, 15 = Owner)
            replace: If True, replaces all existing permissions. If False, adds to existing permissions.
            
        Returns:
            bool: True if sharing was successful
            
        Raises:
            PassboltError: If the sharing operation fails
        """
        # Validate permissions
        for perm in permissions:
            if not all(k in perm for k in ["aro", "aro_foreign_key", "type"]):
                raise PassboltError("Each permission must contain 'aro', 'aro_foreign_key', and 'type'")
                
            if perm["type"] not in [1, 7, 15]:
                raise PassboltError("Permission type must be 1 (Read), 7 (Update), or 15 (Owner)")
                
            if perm["aro"] not in ["User", "Group"]:
                raise PassboltError("Permission aro must be either 'User' or 'Group'")
        
        # Prepare the share payload
        share_payload = {
            "permissions": [
                {
                    "aro": perm["aro"],
                    "aro_foreign_key": perm["aro_foreign_key"],
                    "type": perm["type"],
                }
                for perm in permissions
            ]
        }
        
        # If not replacing, get existing permissions and merge them
        if not replace:
            try:
                folder = self.describe_folder(folder_id)
                existing_permissions = [
                    {
                        "aro": perm.aro,
                        "aro_foreign_key": perm.aro_foreign_key,
                        "type": perm.type,
                    }
                    for perm in folder.permissions
                ]
                # Merge with new permissions, giving priority to new ones
                existing_perm_keys = {
                    (p["aro"], p["aro_foreign_key"]): p["type"]
                    for p in existing_permissions
                }
                for perm in permissions:
                    existing_perm_keys[(perm["aro"], perm["aro_foreign_key"])] = perm["type"]
                
                # Rebuild the permissions list
                share_payload["permissions"] = [
                    {
                        "aro": aro,
                        "aro_foreign_key": aro_fk,
                        "type": perm_type,
                    }
                    for (aro, aro_fk), perm_type in existing_perm_keys.items()
                ]
            except Exception as e:
                logging.warning(f"Could not fetch existing permissions: {e}. Proceeding with new permissions only.")
        
        try:
            # Simulate the share first
            self.post(
                f"/share/simulate/folder/{folder_id}.json",
                share_payload,
                return_response_object=True
            )
            
            # Perform the actual share
            self.put(
                f"/share/folder/{folder_id}.json",
                share_payload,
                return_response_object=True
            )
            return True
            
        except Exception as e:
            # 404 likely means endpoint not present on CE
            if "404" in str(e):
                raise PassboltError("Folder sharing is not supported on this Passbolt edition")
            raise PassboltError(f"Failed to share folder: {str(e)}")

    def share_resource(
        self,
        resource_id: PassboltResourceIdType,
        permissions: List[dict],
        replace: bool = False,
    ) -> bool:
        """
        Share a resource with the specified users/groups.

        Args:
            resource_id: The ID of the resource to share
            permissions: List of permission dictionaries with keys:
                - aro: 'User' or 'Group'
                - aro_foreign_key: ID of the user or group
                - type: Permission type (1 = Read, 7 = Update, 15 = Owner)
            replace: If True, replaces all existing permissions. If False, adds to existing permissions.

        Returns:
            bool: True if sharing was successful
        """
        # Get current user ID (will be cached after first call)
        current_user_id = self._get_current_user_id()
        
        # Get all users for key encryption
        all_users = {user.id: user for user in self.list_users()}
        
        # Get the resource secret
        secret = self._get_secret(resource_id)
        
        # Get the secret text
        secret_text = self.decrypt(secret.data)
        
        # Prepare recipients list (all users who should have access after this operation)
        recipient_ids = set()
        
        # Add current user to maintain access
        recipient_ids.add(current_user_id)
        
        # Add all users from the new permissions
        for perm in permissions:
            if perm["aro"] == "User":
                recipient_ids.add(perm["aro_foreign_key"])
            elif perm["aro"] == "Group":
                group_users = self.list_users(resource_or_folder_id=perm["aro_foreign_key"])
                recipient_ids.update(user.id for user in group_users)
        
        # Get user objects for all recipients
        recipients = [all_users[uid] for uid in recipient_ids if uid in all_users]
        
        # Encrypt the secret for all recipients
        encrypted_secrets = self._encrypt_secrets(secret_text, recipients)
        
        # Prepare the share payload
        share_payload = {
            "permissions": permissions,
            "secrets": encrypted_secrets,
        }
        
        # If not replacing, get existing permissions and merge
        if not replace:
            try:
                current_permissions = self.get(f"/share/resource/{resource_id}.json")["body"]
                existing_permissions = [
                    {
                        "aro": perm["aro"],
                        "aro_foreign_key": perm["aro_foreign_key"],
                        "type": perm["type"],
                    }
                    for perm in current_permissions
                    if perm["aro_foreign_key"] != current_user_id  # Don't include current user's permission
                ]
                # Merge with new permissions, giving priority to new ones
                existing_perm_keys = {(p["aro"], p["aro_foreign_key"]): p for p in existing_permissions}
                new_perm_keys = {(p["aro"], p["aro_foreign_key"]): p for p in permissions}
                # Update existing with new permissions (this will overwrite any existing permissions for the same aro)
                existing_perm_keys.update(new_perm_keys)
                # Convert back to list
                share_payload["permissions"] = list(existing_perm_keys.values())
            except Exception as e:
                logging.warning(f"Could not fetch existing permissions: {e}. Proceeding with new permissions only.")
        
        # Simulate the share first
        self.post(
            f"/share/simulate/resource/{resource_id}.json",
            share_payload,
            return_response_object=True
        )
        
        # Perform the actual share
        self.put(
            f"/share/resource/{resource_id}.json",
            share_payload,
            return_response_object=True
        )
        
        return True

    def apply_sharing_rules(
        self,
        permissions: List[dict],
        replace: bool = False,
        **filters
    ) -> dict:
        """
        Apply sharing permissions to multiple resources based on filter criteria.

        This method allows bulk sharing operations by applying permissions to all resources
        that match the specified filters. Errors are collected rather than stopping execution,
        allowing you to see which resources succeeded and which failed.

        Args:
            permissions: List of permission dictionaries with keys:
                - aro: 'User' or 'Group'
                - aro_foreign_key: ID of the user or group
                - type: Permission type (1 = Read, 7 = Update, 15 = Owner)
            replace: If True, replaces all existing permissions. If False, adds to existing permissions.
            **filters: Filter criteria to select resources. Common filters include:
                - folder_id: Filter by folder ID
                - has_parent: Filter by parent folder UUID
                - has_tag: Filter by tag name (string or list)
                - has_id: Filter by resource ID(s)
                - search: Search in name, username, uri, description
                - is_shared_with_group: Filter resources shared with a group
                - is_owned_by_me: Filter resources owned by current user
                - is_shared_with_me: Filter resources shared with current user

        Returns:
            dict: Summary with 'success' and 'failed' lists:
                {
                    "success": [
                        {"resource_id": "...", "name": "..."},
                        ...
                    ],
                    "failed": [
                        {"resource_id": "...", "name": "...", "error": "..."},
                        ...
                    ],
                    "total": <number of resources processed>,
                    "succeeded": <number of successful shares>,
                    "failed_count": <number of failed shares>
                }

        Example:
            # Share all resources in a folder with a group
            result = api.apply_sharing_rules(
                has_parent="d72d75fd-b79b-4fa5-a87e-e15a481524f7",
                permissions=[{
                    "aro": "Group",
                    "aro_foreign_key": "group-uuid",
                    "type": 1  # Read permission
                }]
            )

            # Share all resources with a specific tag
            result = api.apply_sharing_rules(
                has_tag="production",
                permissions=[{
                    "aro": "User",
                    "aro_foreign_key": "user-uuid",
                    "type": 7  # Update permission
                }],
                replace=False
            )
        """
        # Clear cache to ensure we get fresh resource list
        if self._enable_caching and self._cache:
            self._cache.clear()

        # Get all resources matching the filters
        resources = self.list_resources(**filters)

        # Initialize result tracking
        result = {
            "success": [],
            "failed": [],
            "total": len(resources),
            "succeeded": 0,
            "failed_count": 0,
        }

        # Apply sharing to each resource
        for resource in resources:
            try:
                self.share_resource(
                    resource_id=resource.id,
                    permissions=permissions,
                    replace=replace,
                )
                result["success"].append({
                    "resource_id": resource.id,
                    "name": resource.name,
                })
                result["succeeded"] += 1
            except Exception as e:
                result["failed"].append({
                    "resource_id": resource.id,
                    "name": resource.name,
                    "error": str(e),
                })
                result["failed_count"] += 1
                logging.error(f"Failed to share resource {resource.id} ({resource.name}): {e}")

        return result

    def create_resource(
        self,
        name: str,
        password: str,
        username: str = "",
        description: str = "",
        uri: str = "",
        resource_type_id: Optional[PassboltResourceTypeIdType] = None,
        folder_id: Optional[PassboltFolderIdType] = None,
    ):
        """Creates a new resource on passbolt and shares it with the provided folder recipients"""
        if not name:
            raise PassboltValidationError(f"Name cannot be None or empty -- {name}!")
        if not password:
            raise PassboltValidationError(f"Password cannot be None or empty -- {password}!")

        r_create = self.post(
            "/resources.json",
            {
                "name": name,
                "username": username,
                "description": description,
                "uri": uri,
                **({"resource_type_id": resource_type_id} if resource_type_id else {}),
                "secrets": [{"data": self.encrypt(password)}],
            },
            return_response_object=True,
        )
        resource = constructor(PassboltResourceTuple)(r_create.json()["body"])
        if folder_id:
            folder = self.read_folder(folder_id)
            # Get current user ID (will be cached after first call)
            current_user_id = self._get_current_user_id()
            
            # Prepare permissions for sharing with folder users
            permissions = [
                {
                    "aro": perm.aro,
                    "aro_foreign_key": perm.aro_foreign_key,
                    "type": perm.type,
                    "is_new": True
                }
                for perm in folder.permissions
                if (perm.aro_foreign_key != current_user_id)
            ]
            
            # Share the resource with folder users using the share_resource utility
            self.share_resource(
                resource_id=resource.id,
                permissions=permissions,
                replace=True  # Replace any existing permissions
            )
            
            # Move the resource to the folder and update the resource with the latest state
            resource = self.move_resource_to_folder(resource_id=resource.id, folder_id=folder_id)
        return resource

    def update_resource(
    self,
        resource_id: PassboltResourceIdType,
        name: Optional[str] = None,
        username: Optional[str] = None,
        description: Optional[str] = None,
        uri: Optional[str] = None,
        resource_type_id: Optional[PassboltResourceTypeIdType] = None,
        password: Optional[str] = None,
    ):
        resource: PassboltResourceTuple = self.read_resource(resource_id=resource_id)
        secret = self._get_secret(resource_id=resource_id)
        secret_type = self._get_secret_type(resource_type_id=resource.resource_type_id)
        resource_type_id = resource_type_id if resource_type_id else resource.resource_type_id
        payload = {
            "name": name,
            "username": username,
            "description": description,
            "uri": uri,
            "resource_type_id": resource_type_id,
        }
        if name is None:
            payload.pop("name")
        if username is None:
            payload.pop("username")
        if description is None:
            payload.pop("description")
        if uri is None:
            payload.pop("uri")

        recipients = self.list_users(resource_or_folder_id=resource_id)
        if secret_type == PassboltResourceType.PASSWORD:
            if password is not None:
                assert isinstance(password, str), f"password has to be a string object -- {password}"
                payload["secrets"] = self._encrypt_secrets(secret_text=password, recipients=recipients)
        elif secret_type == PassboltResourceType.PASSWORD_WITH_DESCRIPTION:
            pwd, desc = self._json_load_secret(secret=secret)
            secret_dict = {}
            if description is not None or password is not None:
                secret_dict["description"] = description if description else desc
                secret_dict["password"] = password if password else pwd
            if secret_dict:
                secret_text = json.dumps(secret_dict)
                payload["secrets"] = self._encrypt_secrets(secret_text=secret_text, recipients=recipients)

        if payload:
            r = self.put(f"/resources/{resource_id}.json", payload, return_response_object=True)
            return r

    def describe_group(self, group_id: PassboltGroupIdType):
        response = self.get(f"/groups/{group_id}.json", params={"contain[groups_users]": 1})
        return constructor(PassboltGroupTuple)(response["body"])

    def get_resource_tags(self, resource_id: PassboltResourceIdType) -> List[PassboltTagTuple]:
        """
        Get all tags for a resource.
        
        Args:
            resource_id: The ID of the resource
            
        Returns:
            List[PassboltTagTuple]: List of tags associated with the resource
        """
        response = self.get(f"/resources/{resource_id}.json", params={"contain[tags]": 1})
        tags_data = response["body"].get("tags", [])
        return constructor(PassboltTagTuple)(tags_data) if tags_data else []

    def add_tag_to_resource(self, tag_name: str, resource_id: PassboltResourceIdType) -> dict:
        """
        Add a tag to a resource. If the tag doesn't exist, it will be created.
        
        In Passbolt, tags are created when they are first applied to a resource.
        To create a shared tag, prefix the tag name with '#'.
        
        Args:
            tag_name: The name of the tag to add. Prefix with '#' to create a shared tag.
            resource_id: The ID of the resource to tag
            
        Returns:
            dict: The API response
            
        Example:
            # Add a personal tag
            add_tag_to_resource("personal-tag", "resource-id")
            
            # Add a shared tag (prefix with #)
            add_tag_to_resource("#shared-tag", "resource-id")
        """
        # Passbolt does not provide a dedicated tag endpoint; tagging is done by
        # updating the resource with a `tags` array. Each tag must be an object
        # with a `tag` key (string). A tag prefixed with '#' becomes shared.
        payload = {"tags": [{"tag": tag_name}] }
        return self.put(
            f"/resources/{resource_id}.json",
            payload,
        )
        

        
    def search_tags(self, search_term: str) -> List[PassboltTagTuple]:
        """
        Search for tags by name.
        
        Args:
            search_term: The term to search for in tag names
            
        Returns:
            List[PassboltTagTuple]: List of matching tags
            
        Note:
            This method might not be supported in all Passbolt versions.
            If not supported, it will return an empty list.
        """
        try:
            response = self.get("/tags.json", params={"filter[search]": search_term})
            return constructor(PassboltTagTuple)(response["body"])
        except Exception as e:
            logging.warning(f"Tag search not supported: {e}")
            return []
        
    def get_tag(self, tag_id: PassboltTagIdType) -> PassboltTagTuple:
        """
        Get a tag by ID.
        
        Args:
            tag_id: The ID of the tag to retrieve
            
        Returns:
            PassboltTagTuple: The requested tag
        """
        response = self.get(f"/tags/{tag_id}.json")
        return constructor(PassboltTagTuple)(response["body"])
