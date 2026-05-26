"""Async Vaultwarden API client with connection pooling and optional crypto."""
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

CIPHER_TYPE_NAMES = {1: "Login", 2: "Secure Note", 3: "Card", 4: "Identity"}


class VaultwardenError(Exception):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        super().__init__(f"HTTP {status}: {message}")


class VaultwardenClient:
    """
    Async client for the Vaultwarden / Bitwarden REST API.

    Uses a persistent httpx.AsyncClient for connection pooling. Call
    ``async with VaultwardenClient(...) as client:`` or call ``await client.aclose()``
    when done.
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        device_id: str | None = None,
    ) -> None:
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
        await self._http.aclose()

    async def __aenter__(self) -> "VaultwardenClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    # -------------------------------------------------------------------------
    # Crypto setup
    # -------------------------------------------------------------------------

    @property
    def has_crypto(self) -> bool:
        return self._enc_key is not None and self._mac_key is not None

    async def setup_crypto(self, master_password: str, email: str) -> None:
        """Derive and cache encryption keys from the user's master password."""
        master_key = derive_master_key(master_password, email)
        stretched_enc, stretched_mac = stretch_master_key(master_key)
        sync_data = await self.sync()
        profile_key_enc = sync_data["Profile"]["Key"]
        self._enc_key, self._mac_key = decrypt_profile_key(profile_key_enc, stretched_enc, stretched_mac)

    def _require_crypto(self) -> tuple[bytes, bytes]:
        if not self.has_crypto:
            raise RuntimeError(
                "This operation requires decryption keys. "
                "Set VAULTWARDEN_MASTER_PASSWORD and VAULTWARDEN_EMAIL."
            )
        return self._enc_key, self._mac_key  # type: ignore[return-value]

    def _try_decrypt(self, value: str | None) -> str | None:
        if value is None or not self.has_crypto:
            return value
        try:
            return decrypt_string(value, *self._require_crypto())
        except Exception:
            return value

    def _enc(self, value: str) -> str:
        return encrypt_string(value, *self._require_crypto())

    def _enc_opt(self, value: str | None) -> str | None:
        return None if value is None else self._enc(value)

    # -------------------------------------------------------------------------
    # HTTP helpers
    # -------------------------------------------------------------------------

    async def _ensure_token(self) -> str:
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
        return {"Authorization": f"Bearer {await self._ensure_token()}"}

    def _raise_for_status(self, resp: httpx.Response) -> None:
        if resp.is_error:
            try:
                body = resp.json()
                msg = body.get("message") or body.get("error_description") or str(body)
            except Exception:
                msg = resp.text
            raise VaultwardenError(resp.status_code, msg)

    async def _get(self, path: str) -> Any:
        resp = await self._http.get(path, headers=await self._auth_headers())
        self._raise_for_status(resp)
        return resp.json()

    async def _post(self, path: str, json: Any = None, data: dict | None = None) -> Any:
        resp = await self._http.post(path, headers=await self._auth_headers(), json=json, data=data)
        self._raise_for_status(resp)
        return resp.json() if resp.content else None

    async def _put(self, path: str, json: Any) -> Any:
        resp = await self._http.put(path, headers=await self._auth_headers(), json=json)
        self._raise_for_status(resp)
        return resp.json() if resp.content else None

    async def _delete(self, path: str) -> None:
        resp = await self._http.delete(path, headers=await self._auth_headers())
        self._raise_for_status(resp)

    # -------------------------------------------------------------------------
    # Sync
    # -------------------------------------------------------------------------

    async def sync(self) -> dict:
        resp = await self._http.get("/api/sync", headers=await self._auth_headers())
        self._raise_for_status(resp)
        return resp.json()

    async def get_revision_date(self) -> str:
        """Return the vault's last-modified timestamp (ISO 8601)."""
        resp = await self._http.get("/api/accounts/revision-date", headers=await self._auth_headers())
        self._raise_for_status(resp)
        return resp.text.strip().strip('"')

    # -------------------------------------------------------------------------
    # Cipher helpers
    # -------------------------------------------------------------------------

    def _decrypt_cipher(self, raw: dict) -> dict:
        out = dict(raw)
        out["_name"] = self._try_decrypt(raw.get("Name"))
        out["_notes"] = self._try_decrypt(raw.get("Notes"))
        login = raw.get("Login")
        if login:
            out["_login"] = {
                "username": self._try_decrypt(login.get("Username")),
                "password": self._try_decrypt(login.get("Password")),
                "totp": self._try_decrypt(login.get("Totp")),
                "uris": [
                    {"uri": self._try_decrypt(u.get("Uri")), "match": u.get("Match")}
                    for u in (login.get("Uris") or [])
                ],
            }
        card = raw.get("Card")
        if card:
            out["_card"] = {
                "cardholder_name": self._try_decrypt(card.get("CardholderName")),
                "brand": self._try_decrypt(card.get("Brand")),
                "number": self._try_decrypt(card.get("Number")),
                "exp_month": self._try_decrypt(card.get("ExpMonth")),
                "exp_year": self._try_decrypt(card.get("ExpYear")),
                "code": self._try_decrypt(card.get("Code")),
            }
        identity = raw.get("Identity")
        if identity:
            out["_identity"] = {k: self._try_decrypt(v) for k, v in identity.items() if isinstance(v, str)}
        return out

    # -------------------------------------------------------------------------
    # Ciphers API
    # -------------------------------------------------------------------------

    async def list_ciphers(self) -> list[dict]:
        data = await self._get("/api/ciphers")
        return [self._decrypt_cipher(c) for c in data.get("Data", [])]

    async def get_cipher(self, cipher_id: str) -> dict:
        raw = await self._get(f"/api/ciphers/{cipher_id}")
        return self._decrypt_cipher(raw)

    async def create_cipher(self, payload: dict) -> dict:
        return await self._post("/api/ciphers", json=payload)

    async def update_cipher(self, cipher_id: str, payload: dict) -> dict:
        return await self._put(f"/api/ciphers/{cipher_id}", json=payload)

    async def move_cipher(self, cipher_id: str, folder_id: str | None) -> None:
        await self._put(f"/api/ciphers/{cipher_id}/move", json={"folderId": folder_id})

    async def restore_cipher(self, cipher_id: str) -> dict:
        return await self._put(f"/api/ciphers/{cipher_id}/restore", json={})

    async def delete_cipher(self, cipher_id: str, permanent: bool = False) -> None:
        path = f"/api/ciphers/{cipher_id}/admin" if permanent else f"/api/ciphers/{cipher_id}"
        await self._delete(path)

    # -------------------------------------------------------------------------
    # Folders API
    # -------------------------------------------------------------------------

    async def list_folders(self) -> list[dict]:
        data = await self._get("/api/folders")
        folders = data.get("Data", [])
        for f in folders:
            f["_name"] = self._try_decrypt(f.get("Name"))
        return folders

    async def get_folder(self, folder_id: str) -> dict:
        f = await self._get(f"/api/folders/{folder_id}")
        f["_name"] = self._try_decrypt(f.get("Name"))
        return f

    async def create_folder(self, name: str) -> dict:
        return await self._post("/api/folders", json={"name": self._enc(name)})

    async def update_folder(self, folder_id: str, name: str) -> dict:
        return await self._put(f"/api/folders/{folder_id}", json={"name": self._enc(name)})

    async def delete_folder(self, folder_id: str) -> None:
        await self._delete(f"/api/folders/{folder_id}")

    # -------------------------------------------------------------------------
    # Sends API
    # -------------------------------------------------------------------------

    async def list_sends(self) -> list[dict]:
        data = await self._get("/api/sends")
        sends = data.get("Data", [])
        for s in sends:
            s["_name"] = self._try_decrypt(s.get("Name"))
            s["_notes"] = self._try_decrypt(s.get("Notes"))
            text = s.get("Text")
            if text:
                s["_text"] = self._try_decrypt(text.get("Text"))
        return sends

    async def delete_send(self, send_id: str) -> None:
        await self._delete(f"/api/sends/{send_id}")

    # -------------------------------------------------------------------------
    # Cipher payload builders
    # -------------------------------------------------------------------------

    def build_login_payload(
        self,
        name: str,
        username: str | None = None,
        password: str | None = None,
        uris: list[str] | None = None,
        notes: str | None = None,
        folder_id: str | None = None,
        favorite: bool = False,
    ) -> dict:
        self._require_crypto()
        return {
            "type": 1,
            "name": self._enc(name),
            "notes": self._enc_opt(notes),
            "login": {
                "username": self._enc_opt(username),
                "password": self._enc_opt(password),
                "uris": [{"uri": self._enc(u), "match": None} for u in (uris or [])],
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
    ) -> dict:
        self._require_crypto()
        return {
            "type": 2,
            "name": self._enc(name),
            "notes": self._enc(notes),
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
    ) -> dict:
        self._require_crypto()
        return {
            "type": 3,
            "name": self._enc(name),
            "notes": self._enc_opt(notes),
            "card": {
                "cardholderName": self._enc_opt(cardholder_name),
                "brand": self._enc_opt(brand),
                "number": self._enc_opt(number),
                "expMonth": self._enc_opt(exp_month),
                "expYear": self._enc_opt(exp_year),
                "code": self._enc_opt(cvv),
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
    ) -> dict:
        self._require_crypto()
        return {
            "type": 4,
            "name": self._enc(name),
            "notes": self._enc_opt(notes),
            "identity": {
                "title": self._enc_opt(title),
                "firstName": self._enc_opt(first_name),
                "middleName": self._enc_opt(middle_name),
                "lastName": self._enc_opt(last_name),
                "company": self._enc_opt(company),
                "email": self._enc_opt(email),
                "phone": self._enc_opt(phone),
                "address1": self._enc_opt(address1),
                "address2": self._enc_opt(address2),
                "city": self._enc_opt(city),
                "state": self._enc_opt(state),
                "postalCode": self._enc_opt(postal_code),
                "country": self._enc_opt(country),
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

    def patch_cipher_payload(self, existing_raw: dict, updates: dict) -> dict:
        """
        Merge field updates into an existing raw cipher payload for PUT.

        ``existing_raw`` is the raw API response (encrypted). ``updates`` maps
        plain-text field names to new values. Fields not in ``updates`` are
        carried over verbatim (still encrypted).
        """
        self._require_crypto()
        payload = dict(existing_raw)

        if "name" in updates:
            payload["Name"] = self._enc(updates["name"])
        if "notes" in updates:
            payload["Notes"] = self._enc_opt(updates["notes"])
        if "favorite" in updates:
            payload["Favorite"] = updates["favorite"]
        if "folderId" in updates:
            payload["FolderId"] = updates["folderId"]

        login = existing_raw.get("Login")
        if login and ({"username", "password", "uris"} & updates.keys()):
            updated_login = dict(login)
            if "username" in updates:
                updated_login["Username"] = self._enc_opt(updates["username"])
            if "password" in updates:
                updated_login["Password"] = self._enc_opt(updates["password"])
            if "uris" in updates:
                updated_login["Uris"] = [
                    {"Uri": self._enc(u), "Match": None} for u in (updates["uris"] or [])
                ]
            payload["Login"] = updated_login

        return payload
