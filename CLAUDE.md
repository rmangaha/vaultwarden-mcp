# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

An MCP (Model Context Protocol) server that bridges Claude to a self-hosted
Vaultwarden / Bitwarden instance. It handles OAuth authentication, the full
Bitwarden key derivation chain, and field-level AES-256-CBC encryption —
exposing 16 MCP tools covering ciphers, folders, and Bitwarden Send.

## Commands

```bash
# Install (editable, with dev deps)
pip install -e ".[dev]"

# Run all tests
pytest

# Run a single test file
pytest tests/test_crypto.py

# Run a single test by name
pytest tests/test_client.py::TestCipherBuilders::test_build_login_all_fields

# Run the server manually (reads env vars; stdio transport for Claude Code)
vaultwarden-mcp

# Lint
ruff check src/ tests/
```

Tests require no live server — HTTP is mocked via `pytest-httpx`. Integration
testing against a live instance requires the env vars in `.env.example`.

## Architecture

Three modules with a strict dependency order:

```
server.py  →  client.py  →  crypto.py
(MCP tools)   (HTTP + keys)  (pure crypto, no I/O)
```

**`crypto.py`** — Stateless crypto primitives only. No network, no state.

**`client.py`** — `VaultwardenClient` owns the `httpx.AsyncClient` singleton
(connection pooling), OAuth token cache, and the derived encryption keys. All
Vaultwarden API calls go through `_get()`, `_post()`, `_put()`, `_delete()`.

**`server.py`** — FastMCP server. The `_lifespan` context manager creates and
tears down the `VaultwardenClient` singleton stored in `_client`. Tools
retrieve it via `_get_client()`. Error handling converts exceptions to
user-facing strings — tools never raise.

## Bitwarden Key Chain

This is the most non-obvious part of the codebase. Two distinct levels of keys:

```
master_password + email
    │
    ▼  PBKDF2-SHA256 (600,000 iterations)
master_key (32 bytes)
    │
    ▼  HKDF-Expand × 2 (info=b"enc", info=b"mac")
stretched_enc (32 bytes) + stretched_mac (32 bytes)
    │
    ▼  decrypt Profile.Key from GET /api/sync
user_enc_key (32 bytes) + user_mac_key (32 bytes)
    │
    ▼  used for every cipher field
EncString: "2.<ct_b64>|<iv_b64>|<mac_b64>"
```

`setup_crypto()` performs this entire chain and stores the final keys in
`_enc_key` / `_mac_key`. Without it, `has_crypto` is `False` and the server
runs in read-only mode — cipher names are shown as raw EncStrings.

## Cipher Response Convention

Vaultwarden API responses use PascalCase keys (`Name`, `Login`, `Password`).
`_decrypt_cipher()` augments each dict with underscore-prefixed decrypted
counterparts: `_name`, `_notes`, `_login`, `_card`, `_identity`. Tools always
read the `_`-prefixed keys for display; raw keys are preserved for re-encrypting
on update (`patch_cipher_payload()`).

## Two-Mode Operation

| Mode | Condition | Read | Write |
|------|-----------|------|-------|
| Read-only | No master password | Names shown as EncStrings | Not available |
| Read/write | `VAULTWARDEN_MASTER_PASSWORD` + `VAULTWARDEN_EMAIL` set | Fully decrypted | All tools |

## Style

Google Python Style Guide. 80-char line limit. All public and private
functions/methods carry Google-style docstrings with `Args`, `Returns`, and
`Raises` sections. Enforced via `ruff` (see `pyproject.toml`).
