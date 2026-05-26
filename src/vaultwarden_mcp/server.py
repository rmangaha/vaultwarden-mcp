"""Vaultwarden MCP server — FastMCP implementation.

Exposes 16 MCP tools covering the full Vaultwarden REST API: reading and
writing ciphers (login, note, card, identity), folder management, Bitwarden
Send listing, and vault status. All field-level encryption is handled by
:mod:`vaultwarden_mcp.crypto` using keys derived from the user's master
password at startup.

Typical usage example:

  $ vaultwarden-mcp   # transport: stdio, reads env vars at startup
"""

import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from mcp.server.fastmcp import FastMCP

from .client import VaultwardenClient, VaultwardenError

# Type label map used when formatting cipher output.
_CIPHER_TYPE_LABELS: dict[int, str] = {
    1: "Login",
    2: "Secure Note",
    3: "Card",
    4: "Identity",
}

_client: VaultwardenClient | None = None


@asynccontextmanager
async def _lifespan(server: FastMCP) -> AsyncIterator[None]:
    """Initialises and tears down the shared Vaultwarden client.

    Reads configuration from environment variables, creates the HTTP
    client, and optionally derives encryption keys from the master
    password. Yields control to FastMCP for the lifetime of the server,
    then closes the HTTP connection pool on exit.

    Args:
        server: The FastMCP server instance (unused; required by the
            lifespan protocol).

    Raises:
        SystemExit: If any required environment variable is missing.
    """
    global _client  # pylint: disable=global-statement

    vault_url = os.environ.get("VAULTWARDEN_URL", "").strip()
    client_id = os.environ.get("VAULTWARDEN_CLIENT_ID", "").strip()
    client_secret = os.environ.get("VAULTWARDEN_CLIENT_SECRET", "").strip()

    missing = [
        key
        for key, val in {
            "VAULTWARDEN_URL": vault_url,
            "VAULTWARDEN_CLIENT_ID": client_id,
            "VAULTWARDEN_CLIENT_SECRET": client_secret,
        }.items()
        if not val
    ]
    if missing:
        raise SystemExit(
            f"Missing required environment variables: {', '.join(missing)}"
        )

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


def _get_client() -> VaultwardenClient:
    """Returns the active Vaultwarden client.

    Returns:
        The shared :class:`~vaultwarden_mcp.client.VaultwardenClient`.

    Raises:
        RuntimeError: If called before the lifespan context is active.
    """
    if _client is None:
        raise RuntimeError("Vaultwarden client not ready.")
    return _client


# ------------------------------------------------------------------ #
# Formatting helpers
# ------------------------------------------------------------------ #


def _fmt_cipher(cipher: dict[str, Any]) -> str:
    """Formats a cipher dict as a human-readable string.

    Args:
        cipher: An augmented cipher dict from
            :meth:`~vaultwarden_mcp.client.VaultwardenClient.get_cipher`.

    Returns:
        A multi-line string suitable for display.
    """
    ctype = cipher.get("Type", "?")
    type_label = _CIPHER_TYPE_LABELS.get(ctype, str(ctype))
    lines = [
        f"ID:   {cipher.get('Id', '?')}",
        f"Type: {ctype} ({type_label})",
        f"Name: {cipher.get('_name') or cipher.get('Name', '[encrypted]')}",
    ]

    if cipher.get("FolderId"):
        lines.append(f"Folder: {cipher['FolderId']}")
    if cipher.get("Favorite"):
        lines.append("Favorite: yes")
    if cipher.get("DeletedDate"):
        lines.append(f"Deleted: {cipher['DeletedDate']}")

    login = cipher.get("_login")
    if login:
        if login.get("username"):
            lines.append(f"Username: {login['username']}")
        if login.get("password"):
            lines.append(f"Password: {login['password']}")
        if login.get("totp"):
            lines.append(f"TOTP: {login['totp']}")
        for uri_entry in login.get("uris") or []:
            if uri_entry.get("uri"):
                lines.append(f"URL: {uri_entry['uri']}")

    card = cipher.get("_card")
    if card:
        card_fields = [
            ("Cardholder", "cardholder_name"),
            ("Brand", "brand"),
            ("Number", "number"),
            ("Exp Month", "exp_month"),
            ("Exp Year", "exp_year"),
            ("CVV", "code"),
        ]
        for label, key in card_fields:
            if card.get(key):
                lines.append(f"{label}: {card[key]}")

    identity = cipher.get("_identity")
    if identity:
        for key, value in identity.items():
            if value:
                lines.append(f"{key}: {value}")

    notes = cipher.get("_notes") or cipher.get("Notes")
    if notes:
        lines.append(f"Notes: {notes}")

    return "\n".join(lines)


def _fmt_folder(folder: dict[str, Any]) -> str:
    """Formats a folder dict as a single summary line.

    Args:
        folder: A folder dict from
            :meth:`~vaultwarden_mcp.client.VaultwardenClient.list_folders`.

    Returns:
        A string of the form ``"<name>  (id: <uuid>)"``.
    """
    name = folder.get("_name") or folder.get("Name", "[encrypted]")
    return f"{name}  (id: {folder.get('Id', '?')})"


def _handle_error(exc: Exception) -> str:
    """Converts an exception into a user-facing error string.

    Args:
        exc: The exception to format.

    Returns:
        A descriptive error message string.
    """
    if isinstance(exc, VaultwardenError):
        return f"Vaultwarden API error {exc.status}: {exc}"
    if isinstance(exc, RuntimeError):
        return f"Configuration error: {exc}"
    return f"{type(exc).__name__}: {exc}"


# ------------------------------------------------------------------ #
# Tools — read
# ------------------------------------------------------------------ #


@mcp.tool()
async def list_ciphers() -> str:
    """Lists all vault items (ciphers).

    Returns ID, type, and name for each item. Names are decrypted when
    VAULTWARDEN_MASTER_PASSWORD is configured; otherwise shown as raw
    EncStrings.

    Returns:
        A newline-separated list of vault items, or an error message.
    """
    try:
        ciphers = await _get_client().list_ciphers()
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)

    if not ciphers:
        return "Vault is empty."

    lines = []
    for cipher in ciphers:
        cipher_type = cipher.get("Type", "?")
        label = _CIPHER_TYPE_LABELS.get(cipher_type, str(cipher_type))
        name = cipher.get("_name") or cipher.get("Name", "[encrypted]")
        deleted = " [TRASHED]" if cipher.get("DeletedDate") else ""
        lines.append(
            f"[{label}] {name}{deleted}  (id: {cipher.get('Id', '?')})"
        )

    return "\n".join(lines)


@mcp.tool()
async def get_cipher(cipher_id: str) -> str:
    """Gets full details of a vault item by its UUID.

    All fields are decrypted when VAULTWARDEN_MASTER_PASSWORD is
    configured.

    Args:
        cipher_id: The UUID of the vault item to retrieve.

    Returns:
        A multi-line string with all cipher fields, or an error message.
    """
    try:
        return _fmt_cipher(await _get_client().get_cipher(cipher_id))
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)


@mcp.tool()
async def search_ciphers(query: str) -> str:
    """Searches vault items by name (case-insensitive substring match).

    Requires VAULTWARDEN_MASTER_PASSWORD to be set for meaningful results,
    since names are stored encrypted. Returns all matching items with their
    full details.

    Args:
        query: The search term to match against decrypted item names.

    Returns:
        Matching cipher details separated by ``---``, or a not-found
        message.
    """
    try:
        ciphers = await _get_client().list_ciphers()
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)

    query_lower = query.lower()
    results = [
        c for c in ciphers
        if query_lower in (c.get("_name") or "").lower()
    ]
    if not results:
        return f"No vault items match '{query}'."
    return "\n\n---\n\n".join(_fmt_cipher(c) for c in results)


@mcp.tool()
async def list_folders() -> str:
    """Lists all folders in the vault.

    Folder names are decrypted when VAULTWARDEN_MASTER_PASSWORD is
    configured.

    Returns:
        A newline-separated list of folders with their UUIDs, or an
        error message.
    """
    try:
        folders = await _get_client().list_folders()
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)

    if not folders:
        return "No folders found."
    return "\n".join(_fmt_folder(f) for f in folders)


@mcp.tool()
async def get_vault_status() -> str:
    """Returns vault connectivity and encryption status.

    Useful for confirming the server is connected and authenticated, and
    for checking whether read/write operations are available.

    Returns:
        A multi-line status string, or an error message.
    """
    try:
        client = _get_client()
        revision = await client.get_revision_date()
        crypto = (
            "enabled (read/write)" if client.has_crypto
            else "disabled (read-only)"
        )
        return (
            f"Connected: yes\n"
            f"Last modified: {revision}\n"
            f"Encryption: {crypto}"
        )
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)


@mcp.tool()
async def list_sends() -> str:
    """Lists Bitwarden Send items (shared links).

    Shows name, type (Text or File), expiry date, and access count.

    Returns:
        A newline-separated list of Send items, or an error message.
    """
    try:
        sends = await _get_client().list_sends()
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)

    if not sends:
        return "No Send items found."

    lines = []
    for send in sends:
        name = send.get("_name") or send.get("Name", "[encrypted]")
        send_id = send.get("Id", "?")
        send_type = "Text" if send.get("Type") == 0 else "File"
        expires = send.get("ExpirationDate") or "never"
        accesses = send.get("AccessCount", 0)
        lines.append(
            f"[{send_type}] {name}"
            f"  (id: {send_id}, expires: {expires}, accesses: {accesses})"
        )
    return "\n".join(lines)


# ------------------------------------------------------------------ #
# Tools — cipher writes
# ------------------------------------------------------------------ #


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
    """Creates a new login item in the vault.

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

    Returns:
        A confirmation string with the new cipher UUID, or an error
        message.
    """
    try:
        client = _get_client()
        payload = client.build_login_payload(
            name=name,
            username=username,
            password=password,
            uris=uris,
            notes=notes,
            folder_id=folder_id,
            favorite=favorite,
        )
        result = await client.create_cipher(payload)
        new_id = result.get("Id") or result.get("id")
        return f"Created login '{name}'. ID: {new_id}"
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)


@mcp.tool()
async def create_note(
    name: str,
    notes: str,
    folder_id: str | None = None,
    favorite: bool = False,
) -> str:
    """Creates a secure note in the vault.

    Requires VAULTWARDEN_MASTER_PASSWORD.

    Args:
        name: Note title.
        notes: Note content.
        folder_id: UUID of the folder to place this item in.
        favorite: Whether to mark as favourite.

    Returns:
        A confirmation string with the new cipher UUID, or an error
        message.
    """
    try:
        client = _get_client()
        payload = client.build_note_payload(
            name=name,
            notes=notes,
            folder_id=folder_id,
            favorite=favorite,
        )
        result = await client.create_cipher(payload)
        new_id = result.get("Id") or result.get("id")
        return f"Created secure note '{name}'. ID: {new_id}"
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)


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
    """Creates a credit or debit card item in the vault.

    Requires VAULTWARDEN_MASTER_PASSWORD. All sensitive fields are
    encrypted before being sent to the server.

    Args:
        name: Item label (e.g. ``"Visa ending 4242"``).
        cardholder_name: Name as it appears on the card.
        number: Full card number.
        brand: Card brand (Visa, Mastercard, Amex, etc.).
        exp_month: Expiry month (``"1"``–``"12"``).
        exp_year: Four-digit expiry year.
        cvv: Card security code.
        notes: Optional notes.
        folder_id: UUID of the folder to place this item in.
        favorite: Whether to mark as favourite.

    Returns:
        A confirmation string with the new cipher UUID, or an error
        message.
    """
    try:
        client = _get_client()
        payload = client.build_card_payload(
            name=name,
            cardholder_name=cardholder_name,
            number=number,
            brand=brand,
            exp_month=exp_month,
            exp_year=exp_year,
            cvv=cvv,
            notes=notes,
            folder_id=folder_id,
            favorite=favorite,
        )
        result = await client.create_cipher(payload)
        new_id = result.get("Id") or result.get("id")
        return f"Created card '{name}'. ID: {new_id}"
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)


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
    """Creates an identity item in the vault (personal information record).

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
        postal_code: Postcode or ZIP code.
        country: Country.
        notes: Optional notes.
        folder_id: UUID of the folder to place this item in.
        favorite: Whether to mark as favourite.

    Returns:
        A confirmation string with the new cipher UUID, or an error
        message.
    """
    try:
        client = _get_client()
        payload = client.build_identity_payload(
            name=name,
            first_name=first_name,
            last_name=last_name,
            company=company,
            email=email,
            phone=phone,
            address1=address1,
            city=city,
            state=state,
            postal_code=postal_code,
            country=country,
            notes=notes,
            folder_id=folder_id,
            favorite=favorite,
        )
        result = await client.create_cipher(payload)
        new_id = result.get("Id") or result.get("id")
        return f"Created identity '{name}'. ID: {new_id}"
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)


@mcp.tool()
async def update_cipher(
    cipher_id: str,
    name: str | None = None,
    username: str | None = None,
    password: str | None = None,
    uris: list[str] | None = None,
    notes: str | None = None,
    folder_id: str | None = None,
    favorite: bool | None = None,
) -> str:
    """Updates fields on an existing vault item.

    Requires VAULTWARDEN_MASTER_PASSWORD. Only supply the fields you want
    to change — existing values are preserved for omitted fields.

    Args:
        cipher_id: UUID of the vault item to update.
        name: New item name.
        username: New username (login items only).
        password: New password (login items only).
        uris: Replacement URL list (login items only).
        notes: New notes content.
        folder_id: Move to this folder UUID, or an empty string to
            remove from any folder.
        favorite: Set or unset favourite status.

    Returns:
        A confirmation string listing changed fields, or an error message.
    """
    try:
        client = _get_client()
        raw = await client.get_cipher(cipher_id)
        updates: dict[str, Any] = {}
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
            updates["folderId"] = folder_id.strip() or None
        if favorite is not None:
            updates["favorite"] = favorite

        if not updates:
            return (
                "No fields to update — provide at least one optional argument."
            )

        payload = client.patch_cipher_payload(raw, updates)
        await client.update_cipher(cipher_id, payload)
        changed = ", ".join(updates.keys())
        return f"Updated cipher {cipher_id}. Changed: {changed}"
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)


@mcp.tool()
async def move_cipher(
    cipher_id: str,
    folder_id: str | None = None,
) -> str:
    """Moves a vault item to a different folder (or to the vault root).

    Does not require master password — folder UUIDs are not encrypted.

    Args:
        cipher_id: UUID of the vault item to move.
        folder_id: Target folder UUID, or omit to move to the vault root.

    Returns:
        A confirmation string, or an error message.
    """
    try:
        await _get_client().move_cipher(cipher_id, folder_id or None)
        dest = f"folder {folder_id}" if folder_id else "vault root"
        return f"Cipher {cipher_id} moved to {dest}."
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)


@mcp.tool()
async def restore_cipher(cipher_id: str) -> str:
    """Restores a trashed vault item back to the active vault.

    Args:
        cipher_id: UUID of the vault item to restore.

    Returns:
        A confirmation string, or an error message.
    """
    try:
        await _get_client().restore_cipher(cipher_id)
        return f"Cipher {cipher_id} restored from trash."
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)


@mcp.tool()
async def delete_cipher(cipher_id: str, permanent: bool = False) -> str:
    """Deletes a vault item.

    By default moves to trash (soft delete). Set ``permanent=True`` to
    irreversibly remove the item.

    Args:
        cipher_id: UUID of the vault item to delete.
        permanent: If ``True``, permanently deletes instead of trashing.

    Returns:
        A confirmation string, or an error message.
    """
    try:
        await _get_client().delete_cipher(cipher_id, permanent=permanent)
        verb = "permanently deleted" if permanent else "moved to trash"
        return f"Cipher {cipher_id} {verb}."
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)


# ------------------------------------------------------------------ #
# Tools — folder writes
# ------------------------------------------------------------------ #


@mcp.tool()
async def create_folder(name: str) -> str:
    """Creates a new folder in the vault.

    Requires VAULTWARDEN_MASTER_PASSWORD (folder names are encrypted).

    Args:
        name: Folder name.

    Returns:
        A confirmation string with the new folder UUID, or an error
        message.
    """
    try:
        result = await _get_client().create_folder(name)
        return f"Created folder '{name}'. ID: {result.get('Id', '?')}"
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)


@mcp.tool()
async def update_folder(folder_id: str, name: str) -> str:
    """Renames a folder.

    Requires VAULTWARDEN_MASTER_PASSWORD.

    Args:
        folder_id: UUID of the folder to rename.
        name: New folder name.

    Returns:
        A confirmation string, or an error message.
    """
    try:
        await _get_client().update_folder(folder_id, name)
        return f"Folder {folder_id} renamed to '{name}'."
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)


@mcp.tool()
async def delete_folder(folder_id: str) -> str:
    """Deletes a folder.

    Items inside the folder are moved to the vault root before the folder
    is removed.

    Args:
        folder_id: UUID of the folder to delete.

    Returns:
        A confirmation string, or an error message.
    """
    try:
        await _get_client().delete_folder(folder_id)
        return f"Folder {folder_id} deleted."
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)


# ------------------------------------------------------------------ #
# Tools — sends
# ------------------------------------------------------------------ #


@mcp.tool()
async def delete_send(send_id: str) -> str:
    """Deletes a Bitwarden Send item.

    Args:
        send_id: UUID of the Send to delete.

    Returns:
        A confirmation string, or an error message.
    """
    try:
        await _get_client().delete_send(send_id)
        return f"Send {send_id} deleted."
    except Exception as exc:  # pylint: disable=broad-except
        return _handle_error(exc)


# ------------------------------------------------------------------ #
# Entry point
# ------------------------------------------------------------------ #


def run() -> None:
    """Starts the MCP server using the stdio transport."""
    mcp.run(transport="stdio")
