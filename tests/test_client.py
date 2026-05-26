"""Unit tests for VaultwardenClient — mocked HTTP, no live server required."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_httpx

from vaultwarden_mcp.client import VaultwardenClient, VaultwardenError
from vaultwarden_mcp.crypto import encrypt_bytes, stretch_master_key

BASE_URL = "https://vault.example.com"
CLIENT_ID = "user.test-id"
CLIENT_SECRET = "test-secret"
DEVICE_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

TOKEN_RESPONSE = {
    "access_token": "test-token-abc123",
    "expires_in": 3600,
    "token_type": "Bearer",
    "scope": "api",
}


@pytest.fixture
def client():
    return VaultwardenClient(
        base_url=BASE_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        device_id=DEVICE_ID,
    )


@pytest.fixture
def crypto_client():
    """Client pre-loaded with known crypto keys."""
    c = VaultwardenClient(base_url=BASE_URL, client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
    c._enc_key = b"\x01" * 32
    c._mac_key = b"\x02" * 32
    return c


class TestAuthentication:
    @pytest.mark.asyncio
    async def test_token_fetched_on_first_request(self, httpx_mock, client):
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE_URL}/identity/connect/token",
            json=TOKEN_RESPONSE,
        )
        httpx_mock.add_response(
            method="GET",
            url=f"{BASE_URL}/api/ciphers",
            json={"Data": []},
        )
        result = await client.list_ciphers()
        assert result == []

    @pytest.mark.asyncio
    async def test_token_cached_across_calls(self, httpx_mock, client):
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE_URL}/identity/connect/token",
            json=TOKEN_RESPONSE,
        )
        httpx_mock.add_response(
            method="GET",
            url=f"{BASE_URL}/api/ciphers",
            json={"Data": []},
        )
        httpx_mock.add_response(
            method="GET",
            url=f"{BASE_URL}/api/ciphers",
            json={"Data": []},
        )
        await client.list_ciphers()
        await client.list_ciphers()
        # Only one POST to /identity/connect/token
        token_requests = [r for r in httpx_mock.get_requests() if "token" in str(r.url)]
        assert len(token_requests) == 1

    @pytest.mark.asyncio
    async def test_http_error_raises_vaultwarden_error(self, httpx_mock, client):
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE_URL}/identity/connect/token",
            status_code=401,
            json={"error": "invalid_client", "error_description": "Bad credentials"},
        )
        with pytest.raises(VaultwardenError) as exc_info:
            await client._ensure_token()
        assert exc_info.value.status == 401


class TestCipherOperations:
    @pytest.mark.asyncio
    async def test_list_ciphers_empty(self, httpx_mock, crypto_client):
        httpx_mock.add_response(method="POST", url=f"{BASE_URL}/identity/connect/token", json=TOKEN_RESPONSE)
        httpx_mock.add_response(method="GET", url=f"{BASE_URL}/api/ciphers", json={"Data": []})
        assert await crypto_client.list_ciphers() == []

    @pytest.mark.asyncio
    async def test_list_ciphers_decrypts_names(self, httpx_mock, crypto_client):
        from vaultwarden_mcp.crypto import encrypt_string
        enc_name = encrypt_string("My Login", crypto_client._enc_key, crypto_client._mac_key)
        httpx_mock.add_response(method="POST", url=f"{BASE_URL}/identity/connect/token", json=TOKEN_RESPONSE)
        httpx_mock.add_response(
            method="GET",
            url=f"{BASE_URL}/api/ciphers",
            json={"Data": [{"Id": "abc123", "Type": 1, "Name": enc_name, "Login": None}]},
        )
        ciphers = await crypto_client.list_ciphers()
        assert len(ciphers) == 1
        assert ciphers[0]["_name"] == "My Login"

    @pytest.mark.asyncio
    async def test_list_ciphers_no_crypto_returns_raw(self, httpx_mock, client):
        httpx_mock.add_response(method="POST", url=f"{BASE_URL}/identity/connect/token", json=TOKEN_RESPONSE)
        httpx_mock.add_response(
            method="GET",
            url=f"{BASE_URL}/api/ciphers",
            json={"Data": [{"Id": "abc123", "Type": 1, "Name": "2.abc|def|ghi"}]},
        )
        ciphers = await client.list_ciphers()
        # Without crypto, _name is the raw EncString (decrypt fails silently)
        assert ciphers[0]["_name"] == "2.abc|def|ghi"

    @pytest.mark.asyncio
    async def test_delete_cipher_soft(self, httpx_mock, client):
        httpx_mock.add_response(method="POST", url=f"{BASE_URL}/identity/connect/token", json=TOKEN_RESPONSE)
        httpx_mock.add_response(method="DELETE", url=f"{BASE_URL}/api/ciphers/abc123", status_code=200)
        await client.delete_cipher("abc123", permanent=False)

    @pytest.mark.asyncio
    async def test_delete_cipher_permanent(self, httpx_mock, client):
        httpx_mock.add_response(method="POST", url=f"{BASE_URL}/identity/connect/token", json=TOKEN_RESPONSE)
        httpx_mock.add_response(method="DELETE", url=f"{BASE_URL}/api/ciphers/abc123/admin", status_code=200)
        await client.delete_cipher("abc123", permanent=True)

    @pytest.mark.asyncio
    async def test_move_cipher(self, httpx_mock, client):
        httpx_mock.add_response(method="POST", url=f"{BASE_URL}/identity/connect/token", json=TOKEN_RESPONSE)
        httpx_mock.add_response(method="PUT", url=f"{BASE_URL}/api/ciphers/abc123/move", status_code=200, json={})
        await client.move_cipher("abc123", "folder-uuid")

    @pytest.mark.asyncio
    async def test_restore_cipher(self, httpx_mock, client):
        httpx_mock.add_response(method="POST", url=f"{BASE_URL}/identity/connect/token", json=TOKEN_RESPONSE)
        httpx_mock.add_response(
            method="PUT",
            url=f"{BASE_URL}/api/ciphers/abc123/restore",
            json={"Id": "abc123", "Type": 1, "Name": "2.x|y|z"},
        )
        result = await client.restore_cipher("abc123")
        assert result["Id"] == "abc123"


class TestCipherBuilders:
    def test_build_login_requires_crypto(self, client):
        with pytest.raises(RuntimeError, match="decryption keys"):
            client.build_login_payload(name="test")

    def test_build_login_all_fields(self, crypto_client):
        from vaultwarden_mcp.crypto import decrypt_string
        payload = crypto_client.build_login_payload(
            name="GitHub",
            username="alice",
            password="s3cr3t",
            uris=["https://github.com"],
            notes="work account",
            folder_id="folder-1",
            favorite=True,
        )
        assert payload["type"] == 1
        assert payload["folderId"] == "folder-1"
        assert payload["favorite"] is True

        enc, mac = crypto_client._enc_key, crypto_client._mac_key
        assert decrypt_string(payload["name"], enc, mac) == "GitHub"
        assert decrypt_string(payload["login"]["username"], enc, mac) == "alice"
        assert decrypt_string(payload["login"]["password"], enc, mac) == "s3cr3t"
        assert decrypt_string(payload["notes"], enc, mac) == "work account"
        assert decrypt_string(payload["login"]["uris"][0]["uri"], enc, mac) == "https://github.com"

    def test_build_note_payload(self, crypto_client):
        from vaultwarden_mcp.crypto import decrypt_string
        payload = crypto_client.build_note_payload(name="My Note", notes="Secret content")
        assert payload["type"] == 2
        enc, mac = crypto_client._enc_key, crypto_client._mac_key
        assert decrypt_string(payload["name"], enc, mac) == "My Note"
        assert decrypt_string(payload["notes"], enc, mac) == "Secret content"

    def test_build_card_payload(self, crypto_client):
        from vaultwarden_mcp.crypto import decrypt_string
        payload = crypto_client.build_card_payload(
            name="Visa 4242",
            cardholder_name="Alice Smith",
            number="4242424242424242",
            brand="Visa",
            exp_month="12",
            exp_year="2028",
            cvv="123",
        )
        assert payload["type"] == 3
        enc, mac = crypto_client._enc_key, crypto_client._mac_key
        assert decrypt_string(payload["card"]["number"], enc, mac) == "4242424242424242"
        assert decrypt_string(payload["card"]["code"], enc, mac) == "123"

    def test_build_identity_payload(self, crypto_client):
        from vaultwarden_mcp.crypto import decrypt_string
        payload = crypto_client.build_identity_payload(
            name="Alice",
            first_name="Alice",
            last_name="Smith",
            email="alice@example.com",
        )
        assert payload["type"] == 4
        enc, mac = crypto_client._enc_key, crypto_client._mac_key
        assert decrypt_string(payload["identity"]["firstName"], enc, mac) == "Alice"
        assert decrypt_string(payload["identity"]["email"], enc, mac) == "alice@example.com"

    def test_optional_none_fields_are_none(self, crypto_client):
        payload = crypto_client.build_login_payload(name="Test")
        assert payload["login"]["username"] is None
        assert payload["login"]["password"] is None
        assert payload["notes"] is None

    def test_patch_cipher_payload_merges(self, crypto_client):
        from vaultwarden_mcp.crypto import encrypt_string
        enc, mac = crypto_client._enc_key, crypto_client._mac_key
        existing = {
            "Id": "abc",
            "Type": 1,
            "Name": encrypt_string("OldName", enc, mac),
            "Notes": None,
            "Login": {
                "Username": encrypt_string("alice", enc, mac),
                "Password": encrypt_string("old-pass", enc, mac),
                "Uris": [],
                "Totp": None,
            },
            "Favorite": False,
        }
        from vaultwarden_mcp.crypto import decrypt_string
        patched = crypto_client.patch_cipher_payload(existing, {"name": "NewName", "password": "new-pass"})
        assert decrypt_string(patched["Name"], enc, mac) == "NewName"
        assert decrypt_string(patched["Login"]["Password"], enc, mac) == "new-pass"
        # username unchanged
        assert decrypt_string(patched["Login"]["Username"], enc, mac) == "alice"


class TestFolderOperations:
    @pytest.mark.asyncio
    async def test_list_folders(self, httpx_mock, client):
        httpx_mock.add_response(method="POST", url=f"{BASE_URL}/identity/connect/token", json=TOKEN_RESPONSE)
        httpx_mock.add_response(
            method="GET",
            url=f"{BASE_URL}/api/folders",
            json={"Data": [{"Id": "f1", "Name": "2.abc|def|ghi", "RevisionDate": "2026-01-01"}]},
        )
        folders = await client.list_folders()
        assert len(folders) == 1
        assert folders[0]["Id"] == "f1"

    @pytest.mark.asyncio
    async def test_create_folder_requires_crypto(self, client):
        with pytest.raises(RuntimeError):
            await client.create_folder("My Folder")

    @pytest.mark.asyncio
    async def test_create_folder_encrypts_name(self, httpx_mock, crypto_client):
        httpx_mock.add_response(method="POST", url=f"{BASE_URL}/identity/connect/token", json=TOKEN_RESPONSE)
        httpx_mock.add_response(
            method="POST",
            url=f"{BASE_URL}/api/folders",
            json={"Id": "folder-new", "Name": "2.x|y|z"},
        )
        result = await crypto_client.create_folder("Work")
        assert result["Id"] == "folder-new"
        # Verify the request body had an EncString name
        post_requests = [r for r in httpx_mock.get_requests() if r.method == "POST" and "folders" in str(r.url)]
        assert len(post_requests) == 1
        body = json.loads(post_requests[0].content)
        assert body["name"].startswith("2.")

    @pytest.mark.asyncio
    async def test_delete_folder(self, httpx_mock, client):
        httpx_mock.add_response(method="POST", url=f"{BASE_URL}/identity/connect/token", json=TOKEN_RESPONSE)
        httpx_mock.add_response(method="DELETE", url=f"{BASE_URL}/api/folders/f1", status_code=200)
        await client.delete_folder("f1")


class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_404_raises_vaultwarden_error(self, httpx_mock, client):
        httpx_mock.add_response(method="POST", url=f"{BASE_URL}/identity/connect/token", json=TOKEN_RESPONSE)
        httpx_mock.add_response(
            method="GET",
            url=f"{BASE_URL}/api/ciphers/nonexistent",
            status_code=404,
            json={"message": "Cipher not found"},
        )
        with pytest.raises(VaultwardenError) as exc_info:
            await client.get_cipher("nonexistent")
        assert exc_info.value.status == 404

    @pytest.mark.asyncio
    async def test_500_raises_vaultwarden_error(self, httpx_mock, client):
        httpx_mock.add_response(method="POST", url=f"{BASE_URL}/identity/connect/token", json=TOKEN_RESPONSE)
        httpx_mock.add_response(method="GET", url=f"{BASE_URL}/api/ciphers", status_code=500, text="Internal error")
        with pytest.raises(VaultwardenError) as exc_info:
            await client.list_ciphers()
        assert exc_info.value.status == 500
