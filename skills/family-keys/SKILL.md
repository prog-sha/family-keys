---
name: family-keys
description: Find, receive, register, update, or delete credentials on the Family Keys LAN vault.
---

Keep values out of conversations, tool arguments, output, and logs. Use URLs on the registered MCP origin. The helpers are in the bundled `scripts/` directory.

**Sign-in:** Find the login ENV names with `search_env`, then pass them to `prepare_env(vars)`. Run `sh append-env.sh URL - bundle-json COMMAND`. The command receives JSON like `{"env":"DISCORD_PASSWORD=demo\n","totp":{"DISCORD_PASSWORD":"012345"}}` on stdin. When the two-factor prompt appears, fetch again by the ENV with `has_totp: true` (or its explicit `totp_env`) and use the fresh code locally.

- **Append:** `sh append-env.sh URL .env`. Local consumer exit codes are 0 OK, 10 NO_OTP, 11 NO_FIELD, 12 SUBMITTED.
- **Register:** `sh register-env.sh BASE SOURCE_ENV ENV TITLE PURPOSE [ENV TITLE PURPOSE ...]`. BASE is the MCP URL without `/mcp`. To register TOTP with the value, use `sh register-env.sh --with-totp BASE SOURCE_ENV ENV TITLE PURPOSE URI_FILE`. Use `-` for a URI piped over stdin.
- **Browser registration:** Call `begin_intake(items)` with `title, variable, purpose`, then open the returned URL. Insert values directly from local files into `#paste-value` or the input matching `data-variable`. Insert any setup URI in the optional two-factor field. Submit if permitted and call `wait_intake`. Ask the user to enter values you cannot access.
- **Modify or delete:** Call `manage_env(name, action)` with `update` or `delete`. Use `sh register-env.sh --change URL ENV SOURCE_ENV` or `sh register-env.sh --delete URL ENV`. Supply `title` or `purpose` and omit the source file for metadata-only changes. Specify the item ID for legacy duplicate names.
- **Replace TOTP:** Call `manage_env(name, action="totp")`, then `sh register-env.sh --totp URL ENV URI_FILE`. Use `-` for stdin, or let the user enter the replacement in the vault UI. Setup URLs and seeds cannot be retrieved.
- **Skills:** `family_skills` lists names with no arguments, searches summaries with `query`, or returns a chosen document URL with `name`.
