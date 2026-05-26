"""Async Vaultwarden API client with connection pooling and optional crypto.

Provides :class:`VaultwardenClient`, which manages OAuth token refresh,
persistent HTTP connections, and optional field-level decryption using the
Bitwarden key chain.

Typical usage example:

  async with VaultwardenClient(url, client_id, client_secret) as client:
      await client.setup_crypto(master_password, email)
      ciphers = await client.list_ciphers()
"""

import time
import uuid
from typing import Any

import httpx

from .crypto import (
    decrypt_profile_key,
    decrypt_string,
    derive_master_key,
    encrypt_string,
    stretch_master_key,
)


class VaultwardenError(Exception):
    """Raised when the Vaultwarden API returns an HTTP error response.

    Attributes:
        status: The HTTP status code returned by the server.
    """

    def __init__(self, status: int, message: str) -> None:
        """Initialises the error with an HTTP status and message.

        Args:
            status: The HTTP status code.
            message: A human-readable description of the error.
        """
        self.status = status
        super().__init__(f"HTTP {status}: {message}")


class VaultwardenClient:
    """Async client for the Vaultwarden / Bitwarden REST API.

    Uses a persistent :class:`httpx.AsyncClient` for connection pooling.
    Use as an async context manager, or call :meth:`aclose` explicitly:

    .. code-block:: python

        async with VaultwardenClient(url, cid, secret) as client:
            ciphers = await client.list_ciphers()

    When ``VAULTWARDEN_MASTER_PASSWORD`` and ``VAULTWARDEN_EMAIL`` are
    available, call :meth:`setup_crypto` after construction to enable
    field-level decryption and write operations.
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        device_id: str | None = None,
    ) -> None:
        """Initialises the client.

        Args:
            base_url: Base URL of the Vaultwarden instance, e.g.
                ``"https://vault.example.com"``.
            client_id: OAuth client ID in the form ``user.<UUID>``.
            client_secret: OAuth client secret.
            device_id: Stable UUID identifying this client to the server.
                Auto-generated if not provided.
        """
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.device_id = device_id or str(uuid.uuid4())
        self._http: httpx.AsyncClient = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30.0,
            follow_redirects=True,
        )
        self._token: str | None = None
        self._token_expires: float = 0.0
        self._enc_key: bytes | None = None
        self._mac_key: bytes | None = None

    async def aclose(self) -> None:
        """Closes the underlying HTTP connection pool."""
        await self._http.aclose()

    async def __aenter__(self) -> "VaultwardenClient":
        """Returns self for use as an async context manager."""
        return self

    async def __aexit__(self, *_: Any) -> None:
        """Closes the client when exiting the async context manager."""
        await self.aclose()

    # ------------------------------------------------------------------ #
    # Crypto setup
    # ------------------------------------------------------------------ #

    @property
    def has_crypto(self) -> bool:
        """True if encryption keys have been derived and are available."""
        return self._enc_key is not None and self._mac_key is not None

    async def setup_crypto(self, master_password: str, email: str) -> None:
        """Derives and caches encryption keys from the master password.

        Fetches the encrypted profile key from ``GET /api/sync``,
        derives the stretched master key locally, and uses it to decrypt
        the 64-byte user symmetric key. After this call :attr:`has_crypto`
        is ``True`` and write operations become available.

        Args:
            master_password: The user's Vaultwarden master password.
            email: The account email address (used as the KDF salt).

        Raises:
            VaultwardenError: If the sync request fails.
            ValueError: If the profile key cannot be decrypted.
        """
        master_key = derive_master_key(master_password, email)
        stretched_enc, stretched_mac = stretch_master_key(master_key)
        sync_data = await self.sync()
        profile_key_enc = sync_data["Profile"]["Key"]
        self._enc_key, self._mac_key = decrypt_profile_key(
            profile_key_enc, stretched_enc, stretched_mac
        )

    def _require_crypto(self) -> tuple[bytes, bytes]:
        """Returns the cached (enc_key, mac_key) or raises RuntimeError.

        Returns:
            A ``(enc_key, mac_key)`` tuple.

        Raises:
            RuntimeError: If :meth:`setup_crypto` has not been called.
        """
        if not self.has_crypto:
            raise RuntimeError(
                "This operation requires decryption keys. "
                "Set VAULTWARDEN_MASTER_PASSWORD and VAULTWARDEN_EMAIL."
            )
        return self._enc_key, self._mac_key  # type: ignore[return-value]

    def _try_decrypt(self, value: str | None) -> str | None:
        """Attempts to decrypt an EncString, returning the raw value on failure.

        When crypto keys are not loaded, returns the value unchanged.
        Decryption errors are silently swallowed so a single bad field
        does not prevent the rest of a cipher from being displayed.

        Args:
            value: An EncString or ``None``.

        Returns:
            The decrypted plaintext, the original EncString (if decryption
            fails or keys are unavailable), or ``None``.
        """
        if value is None or not self.has_crypto:
            return value
        try:
            return decrypt_string(value, *self._require_crypto())
        except Exception:  # pylint: disable=broad-except
            return value

    def _encrypt(self, value: str) -> str:
        """Encrypts a string into Bitwarden EncString format.

        Args:
            value: Plaintext string to encrypt.

        Returns:
            A Bitwarden EncString.

        Raises:
            RuntimeError: If crypto keys have not been loaded.
        """
        return encrypt_string(value, *self._require_crypto())

    def _encrypt_optional(self, value: str | None) -> str | None:
        """Encrypts a string if non-None, otherwise returns None.

        Args:
            value: Plaintext string or ``None``.

        Returns:
            An EncString, or ``None`` if ``value`` is ``None``.

        Raises:
            RuntimeError: If crypto keys have not been loaded and
                ``value`` is not ``None``.
        """
        return None if value is None else self._encrypt(value)

    # ------------------------------------------------------------------ #
    # HTTP helpers
    # ------------------------------------------------------------------ #

    async def _ensure_token(self) -> str:
        """Returns a valid OAuth bearer token, refreshing if near expiry.

        Caches the token and refreshes it 60 seconds before expiry to
        avoid requests being rejected mid-flight.

        Returns:
            A valid bearer token string.

        Raises:
            VaultwardenError: If authentication fails.
        """
        if self._token and time.time() < self._token_expires - 60:
            return self._token
        resp = await self._http.post(
            "/identity/connect/token",
            data={
                "grant_type": "client_credentials",
                "scope": "api",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "device_identifier": self.device_id,
                "device_name": "Vaultwarden MCP",
                "device_type": 14,
            },
        )
        self._raise_for_status(resp)
        data = resp.json()
        self._token = data["access_token"]
        self._token_expires = time.time() + data.get("expires_in", 3600)
        return self._token

    async def _auth_headers(self) -> dict[str, str]:
        """Returns Authorization headers with a fresh bearer token.

        Returns:
            A dict suitable for use as HTTP request headers.

        Raises:
            VaultwardenError: If token refresh fails.
        """
        return {"Authorization": f"Bearer {await self._ensure_token()}"}

    def _raise_for_status(self, resp: httpx.Response) -> None:
        """Raises VaultwardenError for any 4xx or 5xx response.

        Attempts to extract a human-readable message from the JSON body
        before falling back to the raw response text.

        Args:
            resp: The HTTP response to check.

        Raises:
            VaultwardenError: If the response status code indicates an error.
        """
        if resp.is_error:
            try:
                body = resp.json()
                msg = (
                    body.get("message")
                    or body.get("error_description")
                    or str(body)
                )
            except Exception:  # pylint: disable=broad-except
                msg = resp.text
            raise VaultwardenError(resp.status_code, msg)

    async def _get(self, path: str) -> Any:
        """Sends an authenticated GET request and returns parsed JSON.

        Args:
            path: API path relative to the base URL.

        Returns:
            Parsed JSON response body.

        Raises:
            VaultwardenError: If the server returns an error status.
        """
        resp = await self._http.get(
            path, headers=await self._auth_headers()
        )
        self._raise_for_status(resp)
        return resp.json()

    async def _post(
        self,
        path: str,
        json: Any = None,
        data: dict[str, Any] | None = None,
    ) -> Any:
        """Sends an authenticated POST request and returns parsed JSON.

        Args:
            path: API path relative to the base URL.
            json: JSON-serialisable body to send.
            data: Form-encoded body to send.

        Returns:
            Parsed JSON response body, or ``None`` if the response has
            no content.

        Raises:
            VaultwardenError: If the server returns an error status.
        """
        resp = await self._http.post(
            path,
            headers=await self._auth_headers(),
            json=json,
            data=data,
        )
        self._raise_for_status(resp)
        return resp.json() if resp.content else None

    async def _put(self, path: str, json: Any) -> Any:
        """Sends an authenticated PUT request and returns parsed JSON.

        Args:
            path: API path relative to the base URL.
            json: JSON-serialisable body to send.

        Returns:
            Parsed JSON response body, or ``None`` if the response has
            no content.

        Raises:
            VaultwardenError: If the server returns an error status.
        """
        resp = await self._http.put(
            path, headers=await self._auth_headers(), json=json
        )
        self._raise_for_status(resp)
        return resp.json() if resp.content else None

    async def _delete(self, path: str) -> None:
        """Sends an authenticated DELETE request.

        Args:
            path: API path relative to the base URL.

        Raises:
            VaultwardenError: If the server returns an error status.
        """
        resp = await self._http.delete(
            path, headers=await self._auth_headers()
        )
        self._raise_for_status(resp)

    # ------------------------------------------------------------------ #
    # Sync
    # ------------------------------------------------------------------ #

    async def sync(self) -> dict[str, Any]:
        """Performs a full vault sync and returns the raw response.

        Returns:
            The parsed JSON from ``GET /api/sync``, including
            ``Profile``, ``Ciphers``, ``Folders``, and ``Sends``.

        Raises:
            VaultwardenError: If the server returns an error status.
        """
        resp = await self._http.get(
            "/api/sync", headers=await self._auth_headers()
        )
        self._raise_for_status(resp)
        return resp.json()

    async def get_revision_date(self) -> str:
        """Returns the vault's last-modified timestamp.

        Returns:
            An ISO 8601 timestamp string from
            ``GET /api/accounts/revision-date``.

        Raises:
            VaultwardenError: If the server returns an error status.
        """
        resp = await self._http.get(
            "/api/accounts/revision-date",
            headers=await self._auth_headers(),
        )
        self._raise_for_status(resp)
        return resp.text.strip().strip('"')

    # ------------------------------------------------------------------ #
    # Cipher helpers
    # ------------------------------------------------------------------ #

    def _decrypt_cipher(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Augments a raw cipher dict with decrypted ``_``-prefixed fields.

        Adds ``_name``, ``_notes``, and type-specific ``_login``,
        ``_card``, or ``_identity`` keys containing decrypted values.
        If crypto keys are not loaded the original EncStrings are kept.

        Args:
            raw: A raw cipher object as returned by the API.

        Returns:
            The same dict with additional ``_``-prefixed decrypted fields.
        """
        out: dict[str, Any] = dict(raw)
        out["_name"] = self._try_decrypt(raw.get("Name"))
        out["_notes"] = self._try_decrypt(raw.get("Notes"))

        login = raw.get("Login")
        if login:
            out["_login"] = {
                "username": self._try_decrypt(login.get("Username")),
                "password": self._try_decrypt(login.get("Password")),
                "totp": self._try_decrypt(login.get("Totp")),
                "uris": [
                    {
                        "uri": self._try_decrypt(u.get("Uri")),
                        "match": u.get("Match"),
                    }
                    for u in (login.get("Uris") or [])
                ],
            }

        card = raw.get("Card")
        if card:
            out["_card"] = {
                "cardholder_name": self._try_decrypt(
                    card.get("CardholderName")
                ),
                "brand": self._try_decrypt(card.get("Brand")),
                "number": self._try_decrypt(card.get("Number")),
                "exp_month": self._try_decrypt(card.get("ExpMonth")),
                "exp_year": self._try_decrypt(card.get("ExpYear")),
                "code": self._try_decrypt(card.get("Code")),
            }

        identity = raw.get("Identity")
        if identity:
            out["_identity"] = {
                k: self._try_decrypt(v)
                for k, v in identity.items()
                if isinstance(v, str)
            }

        return out

    # ------------------------------------------------------------------ #
    # Ciphers API
    # ------------------------------------------------------------------ #

    async def list_ciphers(self) -> list[dict[str, Any]]:
        """Lists all ciphers in the personal vault.

        Returns:
            A list of augmented cipher dicts (see :meth:`_decrypt_cipher`).

        Raises:
            VaultwardenError: If the server returns an error status.
        """
        data = await self._get("/api/ciphers")
        return [self._decrypt_cipher(c) for c in data.get("Data", [])]

    async def get_cipher(self, cipher_id: str) -> dict[str, Any]:
        """Fetches a single cipher by UUID.

        Args:
            cipher_id: The cipher's UUID.

        Returns:
            An augmented cipher dict (see :meth:`_decrypt_cipher`).

        Raises:
            VaultwardenError: If the cipher is not found or the server
                returns an error.
        """
        raw = await self._get(f"/api/ciphers/{cipher_id}")
        return self._decrypt_cipher(raw)

    async def create_cipher(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Creates a new cipher.

        Args:
            payload: A fully formed, encrypted cipher object ready to
                POST to ``/api/ciphers``.

        Returns:
            The created cipher as returned by the server.

        Raises:
            VaultwardenError: If creation fails.
        """
        return await self._post("/api/ciphers", json=payload)

    async def update_cipher(
        self,
        cipher_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Replaces a cipher in full.

        Args:
            cipher_id: The UUID of the cipher to update.
            payload: A fully formed, encrypted cipher object to PUT.

        Returns:
            The updated cipher as returned by the server.

        Raises:
            VaultwardenError: If the update fails.
        """
        return await self._put(f"/api/ciphers/{cipher_id}", json=payload)

    async def move_cipher(
        self,
        cipher_id: str,
        folder_id: str | None,
    ) -> None:
        """Moves a cipher to a folder or to the vault root.

        Does not require encryption keys — folder UUIDs are not encrypted.

        Args:
            cipher_id: The UUID of the cipher to move.
            folder_id: Target folder UUID, or ``None`` to place the cipher
                in the vault root.

        Raises:
            VaultwardenError: If the move fails.
        """
        await self._put(
            f"/api/ciphers/{cipher_id}/move",
            json={"folderId": folder_id},
        )

    async def restore_cipher(self, cipher_id: str) -> dict[str, Any]:
        """Restores a trashed cipher to the active vault.

        Args:
            cipher_id: The UUID of the cipher to restore.

        Returns:
            The restored cipher as returned by the server.

        Raises:
            VaultwardenError: If the restore fails.
        """
        return await self._put(
            f"/api/ciphers/{cipher_id}/restore", json={}
        )

    async def delete_cipher(
        self,
        cipher_id: str,
        permanent: bool = False,
    ) -> None:
        """Deletes or soft-deletes a cipher.

        Args:
            cipher_id: The UUID of the cipher to delete.
            permanent: If ``True``, permanently deletes the cipher via
                the admin endpoint. If ``False`` (default), moves it to
                the trash.

        Raises:
            VaultwardenError: If deletion fails.
        """
        if permanent:
            path = f"/api/ciphers/{cipher_id}/admin"
        else:
            path = f"/api/ciphers/{cipher_id}"
        await self._delete(path)

    # ------------------------------------------------------------------ #
    # Folders API
    # ------------------------------------------------------------------ #

    async def list_folders(self) -> list[dict[str, Any]]:
        """Lists all folders.

        Returns:
            A list of folder dicts, each augmented with a ``_name`` key
            containing the decrypted folder name.

        Raises:
            VaultwardenError: If the server returns an error status.
        """
        data = await self._get("/api/folders")
        folders: list[dict[str, Any]] = data.get("Data", [])
        for folder in folders:
            folder["_name"] = self._try_decrypt(folder.get("Name"))
        return folders

    async def get_folder(self, folder_id: str) -> dict[str, Any]:
        """Fetches a single folder by UUID.

        Args:
            folder_id: The folder's UUID.

        Returns:
            A folder dict augmented with a ``_name`` key.

        Raises:
            VaultwardenError: If the folder is not found.
        """
        folder = await self._get(f"/api/folders/{folder_id}")
        folder["_name"] = self._try_decrypt(folder.get("Name"))
        return folder

    async def create_folder(self, name: str) -> dict[str, Any]:
        """Creates a new folder.

        Args:
            name: The plaintext folder name to encrypt and create.

        Returns:
            The created folder as returned by the server.

        Raises:
            RuntimeError: If crypto keys have not been loaded.
            VaultwardenError: If creation fails.
        """
        return await self._post(
            "/api/folders", json={"name": self._encrypt(name)}
        )

    async def update_folder(
        self,
        folder_id: str,
        name: str,
    ) -> dict[str, Any]:
        """Renames a folder.

        Args:
            folder_id: The UUID of the folder to rename.
            name: The new plaintext folder name.

        Returns:
            The updated folder as returned by the server.

        Raises:
            RuntimeError: If crypto keys have not been loaded.
            VaultwardenError: If the update fails.
        """
        return await self._put(
            f"/api/folders/{folder_id}",
            json={"name": self._encrypt(name)},
        )

    async def delete_folder(self, folder_id: str) -> None:
        """Deletes a folder.

        Items inside the folder are moved to the vault root.

        Args:
            folder_id: The UUID of the folder to delete.

        Raises:
            VaultwardenError: If deletion fails.
        """
        await self._delete(f"/api/folders/{folder_id}")

    # ------------------------------------------------------------------ #
    # Sends API
    # ------------------------------------------------------------------ #

    async def list_sends(self) -> list[dict[str, Any]]:
        """Lists all Bitwarden Send items.

        Returns:
            A list of Send dicts, each augmented with ``_name``,
            ``_notes``, and ``_text`` decrypted keys where present.

        Raises:
            VaultwardenError: If the server returns an error status.
        """
        data = await self._get("/api/sends")
        sends: list[dict[str, Any]] = data.get("Data", [])
        for send in sends:
            send["_name"] = self._try_decrypt(send.get("Name"))
            send["_notes"] = self._try_decrypt(send.get("Notes"))
            text_block = send.get("Text")
            if text_block:
                send["_text"] = self._try_decrypt(text_block.get("Text"))
        return sends

    async def delete_send(self, send_id: str) -> None:
        """Deletes a Bitwarden Send item.

        Args:
            send_id: The UUID of the Send to delete.

        Raises:
            VaultwardenError: If deletion fails.
        """
        await self._delete(f"/api/sends/{send_id}")

    # ------------------------------------------------------------------ #
    # Cipher payload builders
    # ------------------------------------------------------------------ #

    def build_login_payload(
        self,
        name: str,
        username: str | None = None,
        password: str | None = None,
        uris: list[str] | None = None,
        notes: str | None = None,
        folder_id: str | None = None,
        favorite: bool = False,
    ) -> dict[str, Any]:
        """Builds an encrypted login cipher payload for POST/PUT.

        Args:
            name: Item name.
            username: Login username.
            password: Login password.
            uris: Associated URLs.
            notes: Optional notes.
            folder_id: Target folder UUID, or ``None`` for vault root.
            favorite: Whether to mark the item as a favourite.

        Returns:
            An encrypted cipher dict ready to send to the API.

        Raises:
            RuntimeError: If crypto keys have not been loaded.
        """
        self._require_crypto()
        return {
            "type": 1,
            "name": self._encrypt(name),
            "notes": self._encrypt_optional(notes),
            "login": {
                "username": self._encrypt_optional(username),
                "password": self._encrypt_optional(password),
                "uris": [
                    {"uri": self._encrypt(u), "match": None}
                    for u in (uris or [])
                ],
                "totp": None,
            },
            "organizationId": None,
            "folderId": folder_id,
            "favorite": favorite,
            "reprompt": 0,
        }

    def build_note_payload(
        self,
        name: str,
        notes: str,
        folder_id: str | None = None,
        favorite: bool = False,
    ) -> dict[str, Any]:
        """Builds an encrypted secure note cipher payload for POST/PUT.

        Args:
            name: Note title.
            notes: Note content.
            folder_id: Target folder UUID, or ``None`` for vault root.
            favorite: Whether to mark the item as a favourite.

        Returns:
            An encrypted cipher dict ready to send to the API.

        Raises:
            RuntimeError: If crypto keys have not been loaded.
        """
        self._require_crypto()
        return {
            "type": 2,
            "name": self._encrypt(name),
            "notes": self._encrypt(notes),
            "secureNote": {"type": 0},
            "organizationId": None,
            "folderId": folder_id,
            "favorite": favorite,
            "reprompt": 0,
        }

    def build_card_payload(
        self,
        name: str,
        cardholder_name: str | None = None,
        number: str | None = None,
        brand: str | None = None,
        exp_month: str | None = None,
        exp_year: str | None = None,
        cvv: str | None = None,
        notes: str | None = None,
        folder_id: str | None = None,
        favorite: bool = False,
    ) -> dict[str, Any]:
        """Builds an encrypted card cipher payload for POST/PUT.

        Args:
            name: Item label, e.g. ``"Visa ending 4242"``.
            cardholder_name: Name as it appears on the card.
            number: Full card number.
            brand: Card brand (Visa, Mastercard, Amex, etc.).
            exp_month: Expiry month as a string (``"1"``–``"12"``).
            exp_year: Four-digit expiry year as a string.
            cvv: Card security code.
            notes: Optional notes.
            folder_id: Target folder UUID, or ``None`` for vault root.
            favorite: Whether to mark the item as a favourite.

        Returns:
            An encrypted cipher dict ready to send to the API.

        Raises:
            RuntimeError: If crypto keys have not been loaded.
        """
        self._require_crypto()
        return {
            "type": 3,
            "name": self._encrypt(name),
            "notes": self._encrypt_optional(notes),
            "card": {
                "cardholderName": self._encrypt_optional(cardholder_name),
                "brand": self._encrypt_optional(brand),
                "number": self._encrypt_optional(number),
                "expMonth": self._encrypt_optional(exp_month),
                "expYear": self._encrypt_optional(exp_year),
                "code": self._encrypt_optional(cvv),
            },
            "organizationId": None,
            "folderId": folder_id,
            "favorite": favorite,
            "reprompt": 0,
        }

    def build_identity_payload(
        self,
        name: str,
        title: str | None = None,
        first_name: str | None = None,
        middle_name: str | None = None,
        last_name: str | None = None,
        company: str | None = None,
        email: str | None = None,
        phone: str | None = None,
        address1: str | None = None,
        address2: str | None = None,
        city: str | None = None,
        state: str | None = None,
        postal_code: str | None = None,
        country: str | None = None,
        notes: str | None = None,
        folder_id: str | None = None,
        favorite: bool = False,
    ) -> dict[str, Any]:
        """Builds an encrypted identity cipher payload for POST/PUT.

        Args:
            name: Item label.
            title: Honorific title (Mr., Ms., Dr., etc.).
            first_name: First name.
            middle_name: Middle name.
            last_name: Last name.
            company: Company or organisation.
            email: Email address.
            phone: Phone number.
            address1: Street address line 1.
            address2: Street address line 2.
            city: City.
            state: State or province.
            postal_code: Postcode or ZIP code.
            country: Country.
            notes: Optional notes.
            folder_id: Target folder UUID, or ``None`` for vault root.
            favorite: Whether to mark the item as a favourite.

        Returns:
            An encrypted cipher dict ready to send to the API.

        Raises:
            RuntimeError: If crypto keys have not been loaded.
        """
        self._require_crypto()
        return {
            "type": 4,
            "name": self._encrypt(name),
            "notes": self._encrypt_optional(notes),
            "identity": {
                "title": self._encrypt_optional(title),
                "firstName": self._encrypt_optional(first_name),
                "middleName": self._encrypt_optional(middle_name),
                "lastName": self._encrypt_optional(last_name),
                "company": self._encrypt_optional(company),
                "email": self._encrypt_optional(email),
                "phone": self._encrypt_optional(phone),
                "address1": self._encrypt_optional(address1),
                "address2": self._encrypt_optional(address2),
                "city": self._encrypt_optional(city),
                "state": self._encrypt_optional(state),
                "postalCode": self._encrypt_optional(postal_code),
                "country": self._encrypt_optional(country),
                "username": None,
                "passportNumber": None,
                "licenseNumber": None,
                "ssn": None,
            },
            "organizationId": None,
            "folderId": folder_id,
            "favorite": favorite,
            "reprompt": 0,
        }

    def patch_cipher_payload(
        self,
        existing_raw: dict[str, Any],
        updates: dict[str, Any],
    ) -> dict[str, Any]:
        """Merges plaintext field updates into a raw cipher dict for PUT.

        ``existing_raw`` is the unmodified API response (all fields still
        encrypted). Only fields present in ``updates`` are re-encrypted and
        replaced; all other fields are carried over verbatim.

        Args:
            existing_raw: The raw cipher dict as returned by the API.
            updates: A mapping of plaintext field names to new values.
                Supported keys: ``name``, ``notes``, ``favorite``,
                ``folderId``, ``username``, ``password``, ``uris``.

        Returns:
            A merged cipher dict suitable for sending to
            ``PUT /api/ciphers/{id}``.

        Raises:
            RuntimeError: If crypto keys have not been loaded.
        """
        self._require_crypto()
        payload: dict[str, Any] = dict(existing_raw)

        if "name" in updates:
            payload["Name"] = self._encrypt(updates["name"])
        if "notes" in updates:
            payload["Notes"] = self._encrypt_optional(updates["notes"])
        if "favorite" in updates:
            payload["Favorite"] = updates["favorite"]
        if "folderId" in updates:
            payload["FolderId"] = updates["folderId"]

        login = existing_raw.get("Login")
        if login and ({"username", "password", "uris"} & updates.keys()):
            updated_login: dict[str, Any] = dict(login)
            if "username" in updates:
                updated_login["Username"] = self._encrypt_optional(
                    updates["username"]
                )
            if "password" in updates:
                updated_login["Password"] = self._encrypt_optional(
                    updates["password"]
                )
            if "uris" in updates:
                updated_login["Uris"] = [
                    {"Uri": self._encrypt(u), "Match": None}
                    for u in (updates["uris"] or [])
                ]
            payload["Login"] = updated_login

        return payload
