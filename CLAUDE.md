# Vaultwarden MCP Server Development

This folder contains documentation for building an MCP (Model Context Protocol) server for Vaultwarden.

## Project Goal

Create an MCP server that allows Claude (and other AI assistants) to:
- Authenticate with a self-hosted Vaultwarden instance
- Create, read, update, delete vault items (ciphers)
- Manage folders and organizations
- Perform programmatic vault operations via standard MCP protocol

## What is Vaultwarden?

Vaultwarden is a Rust-based, self-hosted alternative server for Bitwarden. It is fully compatible with all official Bitwarden clients but runs on your own infrastructure. Key facts:

- **Open source** (AGPL-3.0): https://github.com/dani-garcia/vaultwarden
- **API-compatible** with official Bitwarden API
- **Lightweight**: Rust-based, minimal resource usage
- **Supports** all Bitwarden features: login items, secure notes, cards, identities, folders, organizations
- **Encryption**: End-to-end encrypted using AES-256-CBC with HMAC-SHA256

## Architecture for MCP Server

The MCP server will act as a bridge between Claude and Vaultwarden:

```
Claude (via MCP protocol)
    ↓
MCP Server (this project)
    ↓
Vaultwarden API (REST)
    ↓
Self-hosted Vaultwarden Instance
```

## Implementation Notes

### Authentication Flow
1. Accept Vaultwarden instance URL + API credentials (client_id, client_secret)
2. Obtain access token via OAuth 2.0 client_credentials grant
3. Maintain token and refresh as needed
4. Include token in Authorization header for API calls

### Encryption Requirement
**Critical**: Vaultwarden requires all vault item fields to be encrypted before sending to the API.

Format: `2.base64_ciphertext|base64_iv|base64_mac`

Where:
- `2` = encryption type (AES-256-CBC with HMAC)
- Ciphertext = AES-256-CBC encrypted data (base64)
- IV = random 16-byte initialization vector (base64)
- MAC = HMAC-SHA256 of IV + ciphertext (base64)

**Challenge**: The encryption key is derived from the user's master password, which the MCP server does NOT have access to (and should NOT have for security). 

**Solution**: Two approaches:
1. **User-provided encryption key** - User derives and provides key separately
2. **Read-only operations** - MCP server can retrieve and decrypt (user's key cached), but cannot create/modify items requiring new encryption
3. **Hybrid** - Use Vaultwarden's unencrypted export/import features (if available) for structured operations

### Cipher Types
- `1` = Login (username, password, URIs)
- `2` = Secure Note
- `3` = Card (credit card details)
- `4` = Identity (personal information)

### API Endpoints

**Authentication:**
- `POST /identity/connect/token` - Get access token

**Vault Items (Ciphers):**
- `GET /api/ciphers` - List all ciphers
- `GET /api/ciphers/{id}` - Get single cipher
- `POST /api/ciphers` - Create cipher
- `PUT /api/ciphers/{id}` - Update cipher
- `DELETE /api/ciphers/{id}` - Delete cipher (soft)
- `DELETE /api/ciphers/{id}/admin` - Delete cipher (permanent)

**Folders:**
- `GET /api/folders` - List folders
- `POST /api/folders` - Create folder
- `PUT /api/folders/{id}` - Update folder
- `DELETE /api/folders/{id}` - Delete folder

**Organizations:**
- `GET /api/organizations` - List organizations
- `GET /api/organizations/{id}` - Get organization details
- `POST /api/organizations` - Create organization

## Testing Environment

Point the server at your own Vaultwarden instance for integration testing.
Set the environment variables from `.env.example` and run:

```bash
pytest tests/          # unit tests (no live server needed)
```

For end-to-end testing against a live instance, set all five environment
variables including `VAULTWARDEN_MASTER_PASSWORD` and run the server manually:

```bash
VAULTWARDEN_URL=https://vault.yourdomain.com \
  VAULTWARDEN_CLIENT_ID=user.YOUR-UUID \
  VAULTWARDEN_CLIENT_SECRET=your-secret \
  VAULTWARDEN_EMAIL=you@example.com \
  VAULTWARDEN_MASTER_PASSWORD=yourpassword \
  vaultwarden-mcp
```

## Development Workflow

1. **Phase 1**: Implement basic OAuth authentication
2. **Phase 2**: Implement GET operations (read-only vault access)
3. **Phase 3**: Implement encryption and PUT/POST operations (write access)
4. **Phase 4**: Add MCP protocol wrapper and tools
5. **Phase 5**: Testing and documentation

## Security Considerations

- **Never log credentials** in MCP server output
- **Encrypt keys in transit** (use HTTPS only)
- **Validate SSL certificates** (no self-signed bypass in production)
- **Scope API access** - Use minimal required permissions
- **Handle errors gracefully** - Don't expose sensitive data in error messages
- **Sanitize user input** - Validate all parameters before API calls

## Resources

- Vaultwarden GitHub: https://github.com/dani-garcia/vaultwarden
- Bitwarden Server API docs: See REFERENCES.md
- Vaultwarden Wiki: https://github.com/dani-garcia/vaultwarden/wiki
- MCP Protocol docs: https://modelcontextprotocol.io/

## Key Files in This Project

- `CLAUDE.md` - This file; project guidelines
- `README.md` - Installation, configuration, and tool reference
- `pyproject.toml` - Package and dependency definition
- `.env.example` - Environment variable template (copy to `.env`, never commit `.env`)
- `src/vaultwarden_mcp/` - MCP server source code
- `tests/` - Unit tests (pytest + pytest-httpx, no live server required)

## Notes for Next Session

When resuming development:
1. Run `pytest tests/` to confirm baseline
2. Check `README.md` for the full tool inventory and configuration reference
3. Integration tests require a live Vaultwarden instance and env vars from `.env.example`
4. Credentials must never be committed — use `.env` locally, env vars in CI
