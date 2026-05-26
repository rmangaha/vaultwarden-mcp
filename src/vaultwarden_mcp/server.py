"""Vaultwarden MCP server — FastMCP implementation."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import FastMCP

from .client import VaultwardenClient, VaultwardenError

# ---------------------------------------------------------------------------
# Lifespan — initialise / teardown the shared Vaultwarden client
# ---------------------------------------------------------------------------

_client: VaultwardenClient | None = None


@asynccontextmanager
async def _lifespan(server: Any):  # noqa: ANN001
    global _client

    vault_url = os.environ.get("VAULTWARDEN_URL", "").strip()
    client_id = os.environ.get("VAULTWARDEN_CLIENT_ID", "").strip()
    client_secret = os.environ.get("VAULTWARDEN_CLIENT_SECRET", "").strip()

    missing = [k for k, v in {
        "VAULTWARDEN_URL": vault_url,
        "VAULTWARDEN_CLIENT_ID": client_id,
        "VAULTWARDEN_CLIENT_SECRET": client_secret,
    }.items() if not v]
    if missing:
        raise SystemExit(f"Missing required environment variables: {', '.join(missing)}")

    _client = VaultwardenClient(
        base_url=vault_url,
        client_id=client_id,
        client_secret=client_secret,
        device_id=os.environ.get("VAULTWARDEN_DEVICE_ID") or None,
    )

    master_password = os.environ.get("VAULTWARDEN_MASTER_PASSWORD", "")
    email = os.environ.get("VAULTWARDEN_EMAIL", "")
    if master_password and email:
        await _client.setup_crypto(master_password, email)

    try:
        yield
    finally:
        await _client.aclose()
        _client = None


mcp = FastMCP("vaultwarden-mcp", lifespan=_lifespan)


def _c() -> VaultwardenClient:
    if _client is None:
        raise RuntimeError("Vaultwarden client not ready")
    return _client


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _fmt_cipher(c: dict) -> str:
    ctype = c.get("Type", "?")
    cid = c.get("Id", "?")
    lines = [
        f"ID:   {cid}",
        f"Type: {ctype} ({['', 'Login', 'Secure Note', 'Card', 'Identity'][ctype] if isinstance(ctype, int) and 1 <= ctype <= 4 else ctype})",
        f"Name: {c.get('_name') or c.get('Name', '[encrypted]')}",
    ]
    if c.get("FolderId"):
        lines.append(f"Folder: {c['FolderId']}")
    if c.get("Favorite"):
        lines.append("Favorite: yes")
    if c.get("DeletedDate"):
        lines.append(f"Deleted: {c['DeletedDate']}")

    login = c.get("_login")
    if login:
        if login.get("username"):
            lines.append(f"Username: {login['username']}")
        if login.get("password"):
            lines.append(f"Password: {login['password']}")
        if login.get("totp"):
            lines.append(f"TOTP: {login['totp']}")
        for u in login.get("uris") or []:
            if u.get("uri"):
                lines.append(f"URL: {u['uri']}")

    card = c.get("_card")
    if card:
        for label, key in [
            ("Cardholder", "cardholder_name"),
            ("Brand", "brand"),
            ("Number", "number"),
            ("Expires", "exp_month"),
            ("Exp Year", "exp_year"),
            ("CVV", "code"),
        ]:
            if card.get(key):
                lines.append(f"{label}: {card[key]}")

    identity = c.get("_identity")
    if identity:
        for k, v in identity.items():
            if v:
                lines.append(f"{k}: {v}")

    notes = c.get("_notes") or c.get("Notes")
    if notes:
        lines.append(f"Notes: {notes}")

    return "\n".join(lines)


def _fmt_folder(f: dict) -> str:
    return f"{f.get('_name') or f.get('Name', '[encrypted]')}  (id: {f.get('Id', '?')})"


def _handle_error(e: Exception) -> str:
    if isinstance(e, VaultwardenError):
        return f"Vaultwarden API error {e.status}: {e}"
    if isinstance(e, RuntimeError):
        return f"Configuration error: {e}"
    return f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# Tools — read
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_ciphers() -> str:
    """
    List all vault items (ciphers).

    Returns ID, type, and name for each item. Names are decrypted when
    VAULTWARDEN_MASTER_PASSWORD is configured; otherwise shown as raw EncStrings.
    """
    try:
        ciphers = await _c().list_ciphers()
    except Exception as e:
        return _handle_error(e)

    if not ciphers:
        return "Vault is empty."

    type_labels = {1: "Login", 2: "Note", 3: "Card", 4: "Identity"}
    lines = []
    for c in ciphers:
        t = c.get("Type", "?")
        label = type_labels.get(t, str(t))
        name = c.get("_name") or c.get("Name", "[encrypted]")
        deleted = " [TRASHED]" if c.get("DeletedDate") else ""
        lines.append(f"[{label}] {name}{deleted}  (id: {c.get('Id', '?')})")

    return "\n".join(lines)


@mcp.tool()
async def get_cipher(id: str) -> str:
    """
    Get full details of a vault item by its UUID.

    All fields are decrypted when VAULTWARDEN_MASTER_PASSWORD is configured.
    """
    try:
        return _fmt_cipher(await _c().get_cipher(id))
    except Exception as e:
        return _handle_error(e)


@mcp.tool()
async def search_ciphers(query: str) -> str:
    """
    Search vault items by name (case-insensitive substring match).

    Requires VAULTWARDEN_MASTER_PASSWORD to be set for decryption.
    Returns all matching items with their full details.
    """
    try:
        ciphers = await _c().list_ciphers()
    except Exception as e:
        return _handle_error(e)

    q = query.lower()
    results = [c for c in ciphers if q in (c.get("_name") or "").lower()]
    if not results:
        return f"No vault items match '{query}'."
    return "\n\n---\n\n".join(_fmt_cipher(c) for c in results)


@mcp.tool()
async def list_folders() -> str:
    """List all folders in the vault. Names are decrypted when master password is configured."""
    try:
        folders = await _c().list_folders()
    except Exception as e:
        return _handle_error(e)

    if not folders:
        return "No folders found."
    return "\n".join(_fmt_folder(f) for f in folders)


@mcp.tool()
async def get_vault_status() -> str:
    """
    Return vault health: last-modified timestamp and encryption key status.
    Useful for confirming the server is connected and authenticated.
    """
    try:
        client = _c()
        revision = await client.get_revision_date()
        crypto = "enabled (read/write)" if client.has_crypto else "disabled (read-only)"
        return f"Connected: yes\nLast modified: {revision}\nEncryption: {crypto}"
    except Exception as e:
        return _handle_error(e)


@mcp.tool()
async def list_sends() -> str:
    """
    List Bitwarden Send items (shared links).

    Shows name, type, expiry, and access count.
    """
    try:
        sends = await _c().list_sends()
    except Exception as e:
        return _handle_error(e)

    if not sends:
        return "No Send items found."

    lines = []
    for s in sends:
        name = s.get("_name") or s.get("Name", "[encrypted]")
        sid = s.get("Id", "?")
        stype = "Text" if s.get("Type") == 0 else "File"
        expires = s.get("ExpirationDate") or "never"
        accesses = s.get("AccessCount", 0)
        lines.append(f"[{stype}] {name}  (id: {sid}, expires: {expires}, accesses: {accesses})")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tools — cipher writes
# ---------------------------------------------------------------------------

@mcp.tool()
async def create_login(
    name: str,
    username: str | None = None,
    password: str | None = None,
    uris: list[str] | None = None,
    notes: str | None = None,
    folder_id: str | None = None,
    favorite: bool = False,
) -> str:
    """
    Create a new login item in the vault.

    Requires VAULTWARDEN_MASTER_PASSWORD. All fields are encrypted before
    being sent to the server.

    Args:
        name: Item name (required).
        username: Login username.
        password: Login password.
        uris: List of associated URLs.
        notes: Optional free-text notes.
        folder_id: UUID of the folder to place this item in.
        favorite: Whether to mark as favourite.
    """
    try:
        client = _c()
        payload = client.build_login_payload(
            name=name, username=username, password=password,
            uris=uris, notes=notes, folder_id=folder_id, favorite=favorite,
        )
        result = await client.create_cipher(payload)
        return f"Created login '{name}'. ID: {result.get('Id', result.get('id'))}"
    except Exception as e:
        return _handle_error(e)


@mcp.tool()
async def create_note(
    name: str,
    notes: str,
    folder_id: str | None = None,
    favorite: bool = False,
) -> str:
    """
    Create a secure note in the vault.

    Requires VAULTWARDEN_MASTER_PASSWORD.

    Args:
        name: Note title.
        notes: Note content.
        folder_id: UUID of the folder to place this item in.
        favorite: Whether to mark as favourite.
    """
    try:
        client = _c()
        payload = client.build_note_payload(name=name, notes=notes, folder_id=folder_id, favorite=favorite)
        result = await client.create_cipher(payload)
        return f"Created secure note '{name}'. ID: {result.get('Id', result.get('id'))}"
    except Exception as e:
        return _handle_error(e)


@mcp.tool()
async def create_card(
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
) -> str:
    """
    Create a credit/debit card item in the vault.

    Requires VAULTWARDEN_MASTER_PASSWORD. All sensitive fields are encrypted.

    Args:
        name: Item label (e.g. 'Visa ending 4242').
        cardholder_name: Name on the card.
        number: Full card number.
        brand: Card brand (Visa, Mastercard, Amex, etc.).
        exp_month: Expiry month (1–12).
        exp_year: Expiry year (4-digit).
        cvv: Card security code.
        notes: Optional notes.
        folder_id: UUID of the folder to place this item in.
        favorite: Whether to mark as favourite.
    """
    try:
        client = _c()
        payload = client.build_card_payload(
            name=name, cardholder_name=cardholder_name, number=number,
            brand=brand, exp_month=exp_month, exp_year=exp_year, cvv=cvv,
            notes=notes, folder_id=folder_id, favorite=favorite,
        )
        result = await client.create_cipher(payload)
        return f"Created card '{name}'. ID: {result.get('Id', result.get('id'))}"
    except Exception as e:
        return _handle_error(e)


@mcp.tool()
async def create_identity(
    name: str,
    first_name: str | None = None,
    last_name: str | None = None,
    company: str | None = None,
    email: str | None = None,
    phone: str | None = None,
    address1: str | None = None,
    city: str | None = None,
    state: str | None = None,
    postal_code: str | None = None,
    country: str | None = None,
    notes: str | None = None,
    folder_id: str | None = None,
    favorite: bool = False,
) -> str:
    """
    Create an identity item in the vault (personal information record).

    Requires VAULTWARDEN_MASTER_PASSWORD. All fields are encrypted.

    Args:
        name: Item label.
        first_name: First name.
        last_name: Last name.
        company: Company or organisation.
        email: Email address.
        phone: Phone number.
        address1: Street address line 1.
        city: City.
        state: State or province.
        postal_code: Postcode or ZIP.
        country: Country.
        notes: Optional notes.
        folder_id: UUID of the folder to place this item in.
        favorite: Whether to mark as favourite.
    """
    try:
        client = _c()
        payload = client.build_identity_payload(
            name=name, first_name=first_name, last_name=last_name,
            company=company, email=email, phone=phone,
            address1=address1, city=city, state=state,
            postal_code=postal_code, country=country,
            notes=notes, folder_id=folder_id, favorite=favorite,
        )
        result = await client.create_cipher(payload)
        return f"Created identity '{name}'. ID: {result.get('Id', result.get('id'))}"
    except Exception as e:
        return _handle_error(e)


@mcp.tool()
async def update_cipher(
    id: str,
    name: str | None = None,
    username: str | None = None,
    password: str | None = None,
    uris: list[str] | None = None,
    notes: str | None = None,
    folder_id: str | None = None,
    favorite: bool | None = None,
) -> str:
    """
    Update fields on an existing vault item.

    Requires VAULTWARDEN_MASTER_PASSWORD. Only supply the fields you want to
    change — existing values are preserved for fields not included.

    Args:
        id: Cipher UUID.
        name: New item name.
        username: New username (login items only).
        password: New password (login items only).
        uris: Replacement URL list (login items only).
        notes: New notes content.
        folder_id: Move to this folder UUID (or null string to remove from folder).
        favorite: Set/unset favourite status.
    """
    try:
        client = _c()
        raw = await client.get_cipher(id)
        updates: dict = {}
        if name is not None:
            updates["name"] = name
        if username is not None:
            updates["username"] = username
        if password is not None:
            updates["password"] = password
        if uris is not None:
            updates["uris"] = uris
        if notes is not None:
            updates["notes"] = notes
        if folder_id is not None:
            updates["folderId"] = folder_id if folder_id.strip() else None
        if favorite is not None:
            updates["favorite"] = favorite

        if not updates:
            return "No fields to update — provide at least one optional argument."

        payload = client.patch_cipher_payload(raw, updates)
        await client.update_cipher(id, payload)
        changed = ", ".join(updates.keys())
        return f"Updated cipher {id}. Changed: {changed}"
    except Exception as e:
        return _handle_error(e)


@mcp.tool()
async def move_cipher(id: str, folder_id: str | None = None) -> str:
    """
    Move a vault item to a different folder (or to the vault root).

    Does not require master password — folder UUID is not encrypted.

    Args:
        id: Cipher UUID.
        folder_id: Target folder UUID, or omit/null to move to vault root.
    """
    try:
        await _c().move_cipher(id, folder_id or None)
        dest = f"folder {folder_id}" if folder_id else "vault root"
        return f"Cipher {id} moved to {dest}."
    except Exception as e:
        return _handle_error(e)


@mcp.tool()
async def restore_cipher(id: str) -> str:
    """
    Restore a trashed vault item back to the active vault.

    Args:
        id: Cipher UUID.
    """
    try:
        await _c().restore_cipher(id)
        return f"Cipher {id} restored from trash."
    except Exception as e:
        return _handle_error(e)


@mcp.tool()
async def delete_cipher(id: str, permanent: bool = False) -> str:
    """
    Delete a vault item.

    By default moves to trash (soft delete). Set permanent=true to
    irreversibly remove the item.

    Args:
        id: Cipher UUID.
        permanent: If true, permanently delete instead of moving to trash.
    """
    try:
        await _c().delete_cipher(id, permanent=permanent)
        verb = "permanently deleted" if permanent else "moved to trash"
        return f"Cipher {id} {verb}."
    except Exception as e:
        return _handle_error(e)


# ---------------------------------------------------------------------------
# Tools — folder writes
# ---------------------------------------------------------------------------

@mcp.tool()
async def create_folder(name: str) -> str:
    """
    Create a new folder in the vault.

    Requires VAULTWARDEN_MASTER_PASSWORD (folder names are encrypted).

    Args:
        name: Folder name.
    """
    try:
        result = await _c().create_folder(name)
        return f"Created folder '{name}'. ID: {result.get('Id', '?')}"
    except Exception as e:
        return _handle_error(e)


@mcp.tool()
async def update_folder(id: str, name: str) -> str:
    """
    Rename a folder.

    Requires VAULTWARDEN_MASTER_PASSWORD.

    Args:
        id: Folder UUID.
        name: New folder name.
    """
    try:
        await _c().update_folder(id, name)
        return f"Folder {id} renamed to '{name}'."
    except Exception as e:
        return _handle_error(e)


@mcp.tool()
async def delete_folder(id: str) -> str:
    """
    Delete a folder. Items inside the folder are moved to the vault root.

    Args:
        id: Folder UUID.
    """
    try:
        await _c().delete_folder(id)
        return f"Folder {id} deleted."
    except Exception as e:
        return _handle_error(e)


# ---------------------------------------------------------------------------
# Tools — sends
# ---------------------------------------------------------------------------

@mcp.tool()
async def delete_send(id: str) -> str:
    """
    Delete a Bitwarden Send item.

    Args:
        id: Send UUID.
    """
    try:
        await _c().delete_send(id)
        return f"Send {id} deleted."
    except Exception as e:
        return _handle_error(e)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run() -> None:
    mcp.run(transport="stdio")
