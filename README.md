# vaultwarden-mcp

An MCP (Model Context Protocol) server that connects Claude to a self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden) / Bitwarden instance.

## Features

- **List, search, and retrieve** vault items (ciphers) and folders
- **Full decryption** of vault items when master password is provided
- **Create** login items and secure notes with proper AES-256-CBC encryption
- **Delete** ciphers and folders
- Token caching with automatic refresh (tokens valid 1 hour)
- Read-only safe mode when no master password is configured

## Requirements

- Python 3.11+
- A running Vaultwarden or Bitwarden-compatible instance
- API credentials from the vault web UI

## Installation

### With `uv` (recommended for Claude Code)

```bash
uv tool install git+https://github.com/rmangaha/vaultwarden-mcp
```

### From source

```bash
git clone https://github.com/rmangaha/vaultwarden-mcp
cd vaultwarden-mcp
pip install -e .
```

## Configuration

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

| Variable | Required | Description |
|---|---|---|
| `VAULTWARDEN_URL` | Yes | Base URL of your Vaultwarden instance |
| `VAULTWARDEN_CLIENT_ID` | Yes | API client ID (`user.UUID`) |
| `VAULTWARDEN_CLIENT_SECRET` | Yes | API client secret |
| `VAULTWARDEN_DEVICE_ID` | No | Stable UUID to identify this client |
| `VAULTWARDEN_EMAIL` | For writes | Account email — used for key derivation |
| `VAULTWARDEN_MASTER_PASSWORD` | For writes | Master password — used for key derivation |

**Get API credentials**: Vaultwarden web UI → Account Settings → Security → API Key

## Claude Code Integration

Add to your `~/.claude/settings.json` (or project `.claude/settings.json`):

```json
{
  "mcpServers": {
    "vaultwarden": {
      "command": "vaultwarden-mcp",
      "env": {
        "VAULTWARDEN_URL": "https://vault.yourdomain.com",
        "VAULTWARDEN_CLIENT_ID": "user.YOUR-UUID",
        "VAULTWARDEN_CLIENT_SECRET": "your-secret",
        "VAULTWARDEN_EMAIL": "you@example.com",
        "VAULTWARDEN_MASTER_PASSWORD": "your-master-password"
      }
    }
  }
}
```

Or via `claude mcp add`:

```bash
claude mcp add vaultwarden -- vaultwarden-mcp
```

Then set environment variables as needed.

## Available Tools

| Tool | Description | Requires Key |
|---|---|---|
| `list_ciphers` | List all vault items | No (shows encrypted names without) |
| `get_cipher` | Get full cipher details | No (fields encrypted without) |
| `search_ciphers` | Search by name | Yes |
| `create_login` | Create a login item | Yes |
| `create_note` | Create a secure note | Yes |
| `delete_cipher` | Move to trash or permanently delete | No |
| `list_folders` | List all folders | No |
| `create_folder` | Create a new folder | Yes |
| `delete_folder` | Delete a folder | No |

## Security Notes

- **Master password** is used only locally to derive encryption keys; it is never transmitted to the Vaultwarden server
- Keys are held in process memory for the session duration
- Use environment variables or a secrets manager — never hardcode credentials in config files
- The server validates TLS certificates by default

## Encryption

All vault data is encrypted end-to-end using Bitwarden's standard:
- Key derivation: PBKDF2-SHA256 (600,000 iterations) + HKDF-Expand
- Encryption: AES-256-CBC with a random 16-byte IV per field
- Integrity: HMAC-SHA256 over IV + ciphertext
- Format: `2.<ciphertext_b64>|<iv_b64>|<mac_b64>`

## Development

```bash
git clone https://github.com/rmangaha/vaultwarden-mcp
cd vaultwarden-mcp
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/
```

## License

MIT
