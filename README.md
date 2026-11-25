# Family Keys

A shared credential vault for a trusted home network. Register secrets in the browser or through an encrypted CLI, search by purpose through MCP, and deliver selected credentials directly to a project.

**[Project website](https://prog-sha.github.io/family-keys/)**

## Run locally

Use a **gd 0.9.0** build with `GD.data.to_json` and `mcp.add_tool(fn)`, plus a POSIX shell, curl, and OpenSSL. Put gd on your PATH or set `KEYS_GD` to its executable. See the [gd repository](https://github.com/prog-sha/gd) for runtime availability.

```sh
./keys check
./keys init
./keys serve
```

Initialization prompts for a shared web password. The server starts on [localhost:49174](http://localhost:49174). To configure a different host or port, copy `settings.example.json` to `settings.local.json` before initialization.

To allow LAN access, stop the server and provide its actual LAN IP and the smallest required client range. These example addresses are reserved for documentation.

```sh
./keys lan 192.0.2.10 192.0.2.0/24
./keys serve
```

In the browser, use **Allowed devices** to edit network ranges or individual addresses. Use **EN / JA** in the upper right to switch languages.

## Connect a family device

In the vault, go to **Family setup** and copy the invitation instructions. Give the instructions to the agent on the receiving device. The invitation is valid once for 24 hours. Its helper stores the shared key in `~/.config/family-keys/key.env` by default.

For manual MCP configuration, register `family-keys` at the server's `/mcp` endpoint. In Codex, a local setup looks like this:

```toml
[mcp_servers.family-keys]
url = "http://localhost:49174/mcp"
```

## Use the vault

- **Find:** `search_env` searches names, purposes, and ENV names. `has_totp: true` indicates that an item can generate a two-factor code.
- **Receive:** `prepare_env(vars)` creates one authenticated, encrypted download. `append-env.sh URL .env` appends to a dotenv file. `append-env.sh URL - bundle-json COMMAND` passes `env` and current `totp` codes to a local command.
- **Register:** `begin_intake(items)` opens a form with an optional otpauth field. ENV names are required and unique. Use `register-env.sh` to send selected entries directly from a local dotenv file.
- **Update:** `manage_env` prepares a link for changing an ENV, deleting it, or replacing its two-factor setup.
- **Share workflows:** `family_skills` lists and finds shared skills. **Family setup** lets you edit the distributed skill and instructions.

See the [Family Keys skill](skills/family-keys/SKILL.md) for command syntax.

## Two-factor setup is write-only

Enter an otpauth URL, a Base32 seed, or a supported QR code. After saving, the vault API and UI expose setup status and the current code through their designated paths. The original URL, QR image, and seed are never returned. To change them, enter new setup details. Leaving the setup field blank keeps the current seed. The server retains encrypted seed material because it needs it to generate codes.

## Secure LAN operation

- Keep the vault on a trusted home VLAN or Wi-Fi network. Block it from guest networks and the Internet. Avoid router port forwarding or UPnP exposure. Apply the same policy to IPv4 and IPv6 at the host firewall.
- Allow specific client IPs or a dedicated subnet. The server checks the socket peer address and validates the HTTP Host and Origin. Keep hostnames explicit and avoid publishing the service through a reverse proxy that rewrites those checks without an equivalent policy.
- Use DHCP reservations to keep allowlist entries stable. MAC and IP addresses alone are weak device identifiers. Where the router or managed switch supports it, use DHCP snooping, IP Source Guard, and Dynamic ARP Inspection to enforce address bindings.
- Encrypted downloads and CLI uploads protect credential payloads. Plain HTTP does not protect browser sign-in, form submission, or MCP metadata on a hostile network. Prefer loopback for management or a properly trusted HTTPS connection for remote browser use.
- Protect `state/` and the client shared key with filesystem permissions. Encrypt backups with a separate key and restrict access to the backup. A lost client may retain credentials already saved to its `.env`; rotate those credentials at their original services.

## Test

```sh
./keys check
python3 tests/integration.py
node tests/intake_test.js
```

Tests use synthetic fixtures under `tmp/`. QR decoding includes code adapted from quirc under the [ISC license](licenses/quirc.txt).
