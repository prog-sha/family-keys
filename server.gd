# Serve the family key UI, authenticated dotenv downloads, and metadata-only HTTP MCP.
class_name FamilyKeysServer

const Core = preload("core.gd")
var vault := Core.new()
var app := GD.web.app()
var mcp_by_origin: Dictionary = {}
const MCP_WRITE_FIELDS := {
	"begin_intake": ["title", "purpose", "variable", "items"],
	"manage_env": ["name", "action", "id", "title", "purpose"],
}
var cfg: Dictionary
var root: String
var writing := false
var auth := preload("auth.gd").new()
var delivery := preload("delivery.gd").new()
const INVITE_LIFETIME_MS := 24 * 60 * 60 * 1000
var family_invites: Dictionary = {}
const SETUP_GUIDE := "このPCで家族LANのfamily-keysを使えるようにして。\n1. MCP「family-keys」を {{MCP_URL}} で登録。\n2. {{SKILL_URL}} の family-keys をスキル置き場に入れる。\n3. 同梱の scripts/setup-key.sh を sh で実行。引数は '{{INVITE_URL}}'。\n取得と二段階認証は同梱スキルに従う。"
var distribution: Dictionary
var family_skill_zip: PackedByteArray
const MAX_BATCH := 32
var prepared_batches: Dictionary = {}
var prepared_changes: Dictionary = {}

# Accept an exact address or an IPv4 subnet without trusting proxy headers.
func address_allowed(ip: String, pattern: String) -> bool:
	if not pattern.contains("/"):
		return ip == pattern
	var parts := pattern.split("/", false)
	var octets := ip.split(".", false)
	if parts.size() != 2 or octets.size() != 4 or not parts[1].is_valid_int():
		return false
	var network := parts[0].split(".", false)
	var bits := int(parts[1])
	if network.size() != 4 or bits < 0 or bits > 32:
		return false
	var left := 0
	var right := 0
	for i in 4:
		if not octets[i].is_valid_int() or not network[i].is_valid_int() or int(octets[i]) not in range(256) or int(network[i]) not in range(256):
			return false
		left = (left << 8) | int(octets[i])
		right = (right << 8) | int(network[i])
	var mask := (0xffffffff << (32 - bits)) & 0xffffffff
	return (left & mask) == (right & mask)

func reply(data: Variant, status: int = 200) -> GDWebResponse:
	return GD.web.json(data, status)!

func fail(message: String, status: int = 400) -> GDWebResponse:
	return reply({"error": message}, status)

# Trust the socket peer only; forwarded headers never identify a family member.
func guard(req: GDWebRequest) -> Variant:
	var ip := req.ip.trim_prefix("::ffff:")
	var device: Dictionary = {}
	for item in cfg.devices:
		if item.ip == ip:
			device = item
			break
	if device.is_empty():
		for pattern in cfg.get("allowed_networks", []):
			if address_allowed(ip, str(pattern)):
				device = {"ip": ip, "name": "家族のLAN"}
				break
	if device.is_empty():
		return fail("This IP is not registered", 403)
	var host := req.host.to_lower()
	var allowed := false
	for name in cfg.hosts:
		if host == name or host == str(name) + ":" + str(cfg.port):
			allowed = true
	if not allowed:
		return fail("Host is not registered", 403)
	var origin := req.get_header("Origin")
	if not origin.is_empty() and origin != ("https://" if req.is_tls() else "http://") + req.host:
		return fail("Cross-origin access is not allowed", 403)
	var session := auth.session(req)
	req.set_value("session", session)
	if req.path.begins_with("/api/") and req.path not in ["/api/status", "/api/login"]:
		if session.is_empty():
			return fail("ログインしてください", 401)
		if req.method not in ["GET", "HEAD", "OPTIONS"] and req.get_header("X-Keys-CSRF") != session.csrf:
			return fail("Reload the page before saving", 403)
	if req.method == "POST" and not req.get_header("Content-Type").begins_with("application/json"):
		return fail("JSON is required", 415)
	device = device.duplicate(true)
	device["member"] = "ALL"
	device["manage"] = true
	req.set_value("device", device)
	req.set_body_limit(Core.MAX_ENV * 6)
	return null

func headers(_req: GDWebRequest, res: GDWebResponse) -> GDWebResponse:
	res = GD.web.with_header(res, "Cache-Control", "no-store")
	res = GD.web.with_header(res, "X-Content-Type-Options", "nosniff")
	res = GD.web.with_header(res, "Referrer-Policy", "no-referrer")
	res = GD.web.with_header(res, "Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	return res

func home(_req) -> GDWebResponse:
	return GD.web.file("web/index.html")!

func asset(req: GDWebRequest) -> GDWebResponse:
	var name: String = req.get_param("name")
	if name == "family-keys-skill.zip":
		return family_skill_download(req)
	if name not in ["app.js", "style.css", "intake.js", "append-env.sh"]:
		return fail("Not found", 404)
	return GD.web.file("append-env.sh" if name == "append-env.sh" else "web/" + name)!

func status(req: GDWebRequest) -> GDWebResponse:
	var session: Dictionary = req.get_value("session")
	if session.is_empty():
		return reply({"authenticated": false})
	return reply({"authenticated": true, "device": req.get_value("device"), "csrf": session.csrf, "runtime": GD.cli.get_version(), "mcp_url": "http://" + str(cfg.get("public_host", "localhost")) + ":" + str(cfg.port) + "/mcp"})

func listing(req: GDWebRequest) -> GDWebResponse:
	return reply({"items": vault.search(req.get_query("q"))})

# Reject overlapping writes rather than allowing stale snapshots to overwrite one another.
func save(req: GDWebRequest) -> GDWebResponse:
	var data, err := req.read_json()
	if err or not data is Dictionary:
		return fail("Invalid request")
	if writing:
		return fail("Another save is in progress; retry", 409)
	var fields = data.get("env_fields")
	if not data.has("id") and fields is Array and fields.size() > 1:
		return save_web_batch(req, data)
	writing = true
	var item, save_err := vault.put(data)
	writing = false
	if save_err:
		return fail(str(save_err))
	audit(req, "save", item.id)
	return reply({"item": item})

func save_web_batch(req: GDWebRequest, data: Dictionary) -> GDWebResponse:
	var fields = data.get("env_fields")
	if data.has("id") or data.has("env") or data.has("env_base64") or not fields is Array or fields.is_empty() or fields.size() > MAX_BATCH:
		return fail("新規登録するENVを1〜32件指定してください")
	var names := {}
	var inputs: Array = []
	var otp = data.get("otp", {})
	if not otp is Dictionary:
		return fail("認証コードの設定を確認してください")
	for field in fields:
		if not field is Dictionary or not valid_env_name(field.get("name")) or names.has(field.name):
			return fail("重複しないENV名を指定してください")
		names[field.name] = true
		var input := {"name": data.get("name", ""), "note": data.get("note", ""), "aliases": data.get("aliases", ""), "env_fields": [field]}
		if otp.get("variable") == field.name:
			input["otp"] = otp
		inputs.append(input)
	if not otp.is_empty() and not names.has(otp.get("variable")):
		return fail("認証コードに紐づくENV名を指定してください")
	writing = true
	var items, err := vault.put_many(inputs)
	writing = false
	if err:
		return fail(str(err))
	for item in items:
		audit(req, "save", item.id)
	return reply({"items": items})

func remove(req: GDWebRequest) -> GDWebResponse:
	if writing:
		return fail("Another save is in progress; retry", 409)
	writing = true
	var err := vault.erase(req.get_param("id"))
	writing = false
	if err:
		return fail("Item was not found or could not be removed", 404)
	audit(req, "delete", req.get_param("id"))
	return reply({"status": "deleted"})

# Only this download path carries plaintext; MCP responses never do.
func download(req: GDWebRequest) -> GDWebResponse:
	var row := vault.find(req.get_param("id"))
	if row.is_empty() or not row.has_env:
		return fail("Dotenv document was not found", 404)
	var bytes, err := vault.env_bytes(row)
	if err:
		return fail("Item could not be opened", 500)
	audit(req, "download", row.id)
	var sealed, seal_err := delivery.seal(bytes)
	if seal_err:
		return fail("Delivery encryption failed", 500)
	var res := GD.web.text(sealed)
	return GD.web.with_header(res, "Content-Disposition", "attachment; filename=\".env.enc\"")

func devices(_req: GDWebRequest) -> GDWebResponse:
	return reply({"devices": cfg.devices, "allowed_networks": cfg.get("allowed_networks", []), "bind": cfg.bind, "hosts": cfg.hosts, "port": cfg.port})

static func valid_fixed_ip(ip: String) -> bool:
	if ip.length() > 45 or not ip.is_valid_ip_address():
		return false
	if ip.contains(":"):
		return not ip.contains("%") and not ip.contains(".")
	for octet in ip.split("."):
		if octet != str(int(octet)) or int(octet) not in range(256):
			return false
	return ip.count(".") == 3

func save_devices(req: GDWebRequest) -> GDWebResponse:
	var data, err := req.read_json()
	if err or not data is Dictionary or not data.get("devices") is Array:
		return fail("Invalid devices")
	var input_networks = data.get("allowed_networks", cfg.get("allowed_networks", []))
	if not input_networks is Array:
		return fail("許可範囲を1行ずつ入力してください")
	if input_networks.size() > 256 or data.devices.size() > 256:
		return fail("許可範囲と固定IPはそれぞれ256件までです")
	var networks: Array = []
	var range_format := RegEx.new()
	range_format.compile("\\A(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/(?:[1-9]|[12][0-9]|3[0-2])\\z")
	for i in input_networks.size():
		var entry = input_networks[i]
		if not entry is String or entry.length() > 64:
			return fail("許可範囲の %d 行目を確認してください" % (i + 1))
		var network := str(entry).strip_edges()
		if network.ends_with(".*"):
			network = network.trim_suffix("*") + "0/24"
		if not range_format.search(network) or not valid_fixed_ip(network.get_slice("/", 0)):
			return fail("許可範囲の %d 行目は 192.0.2.0/24 の形式で入力してください" % (i + 1))
		if network not in networks:
			networks.append(network)
	var ips: Array = []
	var keep_self := false
	for network in networks:
		if address_allowed(req.get_value("device").ip, str(network)):
			keep_self = true
	var updated: Array = []
	for i in data.devices.size():
		var d = data.devices[i]
		if not d is Dictionary or not d.get("ip") is String or not valid_fixed_ip(d.ip) or d.ip in ips or not d.get("name", "") is String or str(d.get("name", "")).length() > 128:
			return fail("固定IPの %d 行目を確認してください。例：192.0.2.10 または ::1" % (i + 1))
		ips.append(d.ip)
		updated.append({"ip": d.ip, "name": d.get("name", "")})
		if d.ip == req.get_value("device").ip:
			keep_self = true
	if not keep_self:
		return fail("この端末のIPが許可範囲か固定IPに含まれるようにしてください")
	var next := cfg.duplicate(true)
	next.devices = updated
	next.allowed_networks = networks
	var save_err := Core.private_write(root.path_join("config.json"), GD.data.var_to_json(next)!.to_utf8_buffer())
	if save_err:
		return fail("Could not save devices", 500)
	cfg = next
	return reply({"status": "saved", "allowed_networks": networks})

# Reveal decrypted text only to a logged-in human using the web entrance.
func reveal(req: GDWebRequest) -> GDWebResponse:
	var row := vault.find(req.get_param("id"))
	if row.is_empty():
		return fail("Item was not found", 404)
	var body, err := vault.unpack(row)
	if err:
		return fail("Item could not be opened", 500)
	var bytes := GD.data.base64_to_raw(body.env_base64)!
	audit(req, "reveal", row.id)
	var env := bytes.get_string_from_utf8()
	var result := {"item": vault.metadata(row), "note": body.note, "env": env}
	var options, options_err := req.read_json()
	if not options_err and options is Dictionary and options.get("fields") == true:
		var fields: Array = []
		if not bytes.is_empty():
			var values, err := GD.data.dotenv_to_dict(env)
			if err:
				return fail("ENVを読み込めませんでした", 500)
			for variable in values:
				fields.append({"name": variable, "value": values[variable]})
		result["fields"] = fields
	return reply(result)

func family_rule(_req: GDWebRequest) -> GDWebResponse:
	return reply({"rule": delivery.rule})

func otp_response(req: GDWebRequest, encrypted: bool) -> GDWebResponse:
	var row := vault.find(req.get_param("id"))
	if not row.has("otp_variable"):
		return fail("認証コードが未設定です", 404)
	var body, err := vault.unpack(row)
	if err:
		return fail("認証コードを生成できません", 500)
	var now := int(Time.get_unix_time_from_system())
	var code := generate_otp(body, now)
	if code.is_empty():
		return fail("認証コードを生成できません", 500)
	audit(req, "otp", row.id)
	if encrypted:
		var sealed, seal_err := delivery.seal(code.to_utf8_buffer())
		return fail("認証コードを配信できません", 500) if seal_err else GD.web.text(sealed)
	return reply({"code": code, "expires_in": 30 - now % 30})

func generate_otp(body: Dictionary, now: int) -> String:
	var seed, err := GD.data.base64_to_raw(body.get("otp", {}).get("seed", ""))
	return "" if err or seed.is_empty() else preload("totp.gd").code(seed, now)

func valid_env_name(value: Variant) -> bool:
	if not value is String or value.length() > 256 or value == "FAMILY_KEYS_K":
		return false
	var pattern := RegEx.new()
	pattern.compile("\\A[A-Za-z_][A-Za-z0-9_]*\\z")
	return pattern.search(value) != null

func prepare_batch(requested: Variant) -> Array, Err:
	if not requested is Array or requested.is_empty() or requested.size() > MAX_BATCH:
		return [], Err("Specify 1–32 ENV names")
	var selections: Array = []
	var used := {}
	for entry in requested:
		var variable = entry.get("name") if entry is Dictionary else entry
		var selected_id = entry.get("id", "") if entry is Dictionary else ""
		if not valid_env_name(variable) or not selected_id is String or used.has(variable):
			return [], Err("Use unique ENV names")
		var item_id, err := resolve_env(variable, selected_id)
		if err:
			return [], err
		used[variable] = true
		selections.append({"name": variable, "id": item_id})
	return selections, null

func resolve_env(variable: String, selected_id: String = "") -> String, Err:
	var key := vault.env_key(variable)
	if not selected_id.is_empty() and variable in vault.find(selected_id).get("variables", []):
		return selected_id, null
	if key.is_empty() or not selected_id.is_empty():
		return "", Err("Not found: " + variable)
	if key.get("item_id") == null:
		return "", Err("Legacy duplicate; use item id: " + variable)
	return key.item_id, null

func prepare_change(args: Dictionary) -> String, Err:
	var variable = args.get("name")
	var action = args.get("action")
	var selected_id = args.get("id", "")
	if not valid_env_name(variable) or action not in ["update", "delete", "totp"] or not selected_id is String:
		return "", Err("Specify ENV name and update, delete, or totp")
	if args.has("title") and (action != "update" or not args.title is String or args.title.strip_edges().is_empty() or args.title.length() > 160):
		return "", Err("Invalid title")
	if args.has("purpose") and (action != "update" or not args.purpose is String or args.purpose.to_utf8_buffer().size() > Core.MAX_ENV):
		return "", Err("Invalid purpose")
	var item_id, err := resolve_env(variable, selected_id)
	if err:
		return "", err
	var row := vault.find(item_id)
	var now := Time.get_ticks_msec()
	for token in prepared_changes.keys():
		if prepared_changes[token].until <= now:
			prepared_changes.erase(token)
	var token := GD.id.uuid()
	prepared_changes[token] = {"args": args, "id": item_id, "revision": row.revision, "until": now + 120000}
	return token, null

func apply_change(req: GDWebRequest) -> GDWebResponse:
	var token := req.get_param("id")
	var ticket: Dictionary = prepared_changes.get(token, {})
	if ticket.is_empty() or ticket.until <= Time.get_ticks_msec():
		return fail("Change expired", 404)
	var data, json_err := req.read_json()
	if json_err or not data is Dictionary or not data.get("mac", "") is String or data.get("mac", "").length() > 64:
		return fail("Invalid change")
	var args: Dictionary = ticket.args
	var signed := "FK1-MANAGE:%s:%s:%s:%s" % [token, args.action, args.name, data.get("mac", "")]
	var key := GD.data.sha256(("FK1-MANAGE-KEY:" + token + ":" + delivery.secret).to_utf8_buffer())
	var proof := GD.data.hmac_sha256(key, signed.to_utf8_buffer()).hex_encode()
	if not Crypto.new().constant_time_compare(proof.to_utf8_buffer(), req.get_header("X-Keys-Manage-Proof").to_utf8_buffer()):
		return fail("Authentication failed", 403)
	var row := vault.find(ticket.id)
	if row.is_empty() or row.revision != ticket.revision:
		return fail("ENV changed; retry", 409)
	var variable: String = args.name
	var deleting: bool = args.action == "delete"
	if deleting and not data.is_empty():
		return fail("Invalid deletion")
	var change_err: Err
	if deleting and row.variables.size() == 1:
		change_err = vault.erase(row.id)
	else:
		var body := vault.unpack(row)!
		var input := {"id": row.id, "name": args.get("title", row.name), "aliases": row.aliases, "note": args.get("purpose", body.note), "env_base64": body.env_base64}
		if args.action == "totp":
			var setup := decode_registration(data, true)
			if setup.has("error"):
				return fail(setup.error, setup.status)
			if setup.variable != variable or row.get("otp_variable", variable) != variable:
				return fail("TOTP ENV name mismatch", 409)
			input["otp"] = {"variable": variable, "seed": setup.seed}
		elif deleting or not data.is_empty():
			var original := GD.data.base64_to_raw(body.env_base64)!
			var values := GD.data.dotenv_to_dict(original.get_string_from_utf8())!
			if deleting:
				values.erase(variable)
				if row.get("otp_variable") == variable:
					input["otp"] = {"remove": true}
			else:
				var replacement := decode_registration(data)
				if replacement.has("error"):
					return fail(replacement.error, replacement.status)
				if replacement.has("seed") or replacement.variable != variable:
					return fail("ENV name mismatch")
				var incoming := GD.data.dotenv_to_dict(replacement.env)!
				values[variable] = incoming[variable]
			var updated, env_err := GD.data.dict_to_dotenv(values)
			if env_err:
				return fail("Invalid dotenv")
			input.erase("env_base64")
			input["env"] = updated
		elif not args.has("title") and not args.has("purpose"):
			return fail("Supply a value or metadata")
		var _saved: Dictionary
		_saved, change_err = vault.put(input)
	if change_err:
		return fail("Change failed", 409)
	prepared_changes.erase(token)
	audit(req, args.action, row.id)
	return reply({"status": "ok"})

func batch_download(req: GDWebRequest) -> GDWebResponse:
	var batch: Dictionary = prepared_batches.get(req.get_param("id"), {})
	if batch.is_empty() or batch.until <= Time.get_ticks_msec():
		return fail("取得URLの有効期限が切れました", 404)
	var values := {}
	var otps := {}
	var now := int(Time.get_unix_time_from_system())
	for selection in batch.entries:
		var row := vault.find(selection.id)
		if row.is_empty() or selection.name not in row.variables:
			return fail("ENVが変更されました。もう一度取得してください", 409)
		var body, body_err := vault.unpack(row)
		if body_err:
			return fail("ENVを開けません", 500)
		var bytes, decode_err := GD.data.base64_to_raw(body.env_base64)
		if decode_err:
			return fail("ENVを開けません", 500)
		var parsed, parse_err := GD.data.dotenv_to_dict(bytes.get_string_from_utf8())
		if parse_err or not parsed.has(selection.name):
			return fail("ENVを読み取れません", 500)
		values[selection.name] = parsed[selection.name]
		if row.get("otp_variable") == selection.name:
			var code := generate_otp(body, now)
			if code.is_empty():
				return fail("認証コードを生成できません", 500)
			otps[selection.name] = code
	var env, env_err := GD.data.dict_to_dotenv(values)
	if env_err or env.to_utf8_buffer().size() > Core.MAX_ENV:
		return fail("取得するENVを減らしてください", 413)
	var envelope: String
	if req.get_header("X-Keys-Bundle") == "json":
		envelope = GD.data.var_to_json({"env": env, "totp": otps})!
	else:
		envelope = "FK1-BATCH\n" + GD.data.raw_to_base64(env.to_utf8_buffer()) + "\n" + GD.data.var_to_json(otps)! + "\n"
	var sealed, err := delivery.seal(envelope.to_utf8_buffer())
	if err:
		return fail("ENVを配信できません", 500)
	for selection in batch.entries:
		audit(req, "batch_download", selection.id)
	return GD.web.text(sealed)

func save_otp_settings(req: GDWebRequest) -> GDWebResponse:
	var data, parse_err := req.read_json()
	if parse_err or not data is Dictionary or data.is_empty():
		return fail("認証コードの設定を確認してください")
	if writing:
		return fail("保存中です。もう一度お試しください", 409)
	var row := vault.find(req.get_param("id"))
	if row.is_empty():
		return fail("項目が見つかりません", 404)
	if data.has("qr"):
		var qr = data.qr
		if not qr is Dictionary or not qr.get("gray") is String or qr.gray.length() > 2613336:
			return fail("QR画像の形式を確認してください")
		for value in [qr.get("width"), qr.get("height")]:
			if not (value is int or value is float) or value < 21 or value > 1400 or value != floor(value):
				return fail("QR画像のサイズを確認してください")
		var gray, qr_err := GD.data.base64_to_raw(qr.gray)
		if qr_err or gray.size() != int(qr.width) * int(qr.height):
			return fail("QR画像の形式を確認してください")
		var uri := preload("qr_reader.gd").new().read(gray, int(qr.width), int(qr.height))
		if preload("totp.gd").uri_seed(uri).is_empty():
			return fail("対応するTOTPのQRが見つかりません。QRの周囲を切り取って貼り付けてください")
		data = {"variable": data.get("variable"), "seed": uri}
	var body, read_err := vault.unpack(row)
	if read_err:
		return fail("項目を開けません", 500)
	writing = true
	var item, save_err := vault.put({"id": row.id, "name": row.name, "aliases": row.aliases, "note": body.note, "env_base64": body.env_base64, "otp": data})
	writing = false
	if save_err:
		return fail(str(save_err))
	audit(req, "otp_settings", row.id)
	return reply({"item": item})

func skill_list(query: String) -> Array:
	if query.is_empty():
		return vault.db.query_all("SELECT name FROM family_skills ORDER BY name")!
	return vault.db.query_all("SELECT name,summary FROM family_skills WHERE instr(lower(name),lower(?))>0 OR instr(lower(summary),lower(?))>0 ORDER BY (name=? COLLATE NOCASE) DESC,name LIMIT 5", [query, query, query])!

func skill_read(req: GDWebRequest, editor: bool) -> GDWebResponse:
	var row, err := vault.db.query_row("SELECT name,summary,body FROM family_skills WHERE name=?", [req.get_param("name")])
	if err or row.is_empty():
		return fail("スキルが見つかりません", 404)
	return reply(row) if editor else GD.web.text(row.body)

func skill_save(req: GDWebRequest) -> GDWebResponse:
	var data, err := req.read_json()
	if err or not data is Dictionary or not data.get("name") is String or not data.get("summary") is String or not data.get("body") is String:
		return fail("名前・概要・本文を入力してください")
	var slug := RegEx.new()
	slug.compile("\\A[a-z0-9][a-z0-9-]{0,63}\\z")
	var summary: String = data.summary.strip_edges()
	if not slug.search(data.name) or summary.is_empty() or summary.length() > 160 or summary.contains("\n") or summary.contains("\r") or data.body.strip_edges().is_empty() or data.body.to_utf8_buffer().size() > 65536:
		return fail("名前は半角小文字・数字・ハイフン、概要は160文字の1行、本文は64KBまでです")
	var _, write_err := vault.db.exec("INSERT INTO family_skills(name,summary,body) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET summary=excluded.summary,body=excluded.body", [data.name, summary, data.body])
	return fail("スキルを保存できませんでした", 500) if write_err else reply({"status": "saved"})

func skill_delete(req: GDWebRequest) -> GDWebResponse:
	var _, err := vault.db.exec("DELETE FROM family_skills WHERE name=?", [req.get_param("name")])
	return fail("スキルを削除できませんでした", 500) if err else reply({"status": "deleted"})

func family_key_download(_req: GDWebRequest) -> GDWebResponse:
	return GD.web.with_header(GD.web.text(delivery.rule), "Content-Disposition", "attachment; filename=\"family-keys.env\"")

func create_family_invite(req: GDWebRequest) -> GDWebResponse:
	var now := Time.get_ticks_msec()
	for id in family_invites.keys():
		if family_invites[id].until <= now:
			family_invites.erase(id)
	var crypto := Crypto.new()
	var id := crypto.generate_random_bytes(16).hex_encode()
	var key := GD.data.raw_to_base64url(crypto.generate_random_bytes(32))
	family_invites[id] = {"key": key, "until": now + INVITE_LIFETIME_MS}
	var host := str(cfg.get("public_host", "localhost"))
	var origin := ("https://" if req.is_tls() else "http://") + host + ":" + str(cfg.port)
	var url := origin + "/agent/setup/" + id + "#" + key
	var guide: String = distribution.guide.replace("{{MCP_URL}}", origin + "/mcp").replace("{{SKILL_URL}}", origin + "/assets/family-keys-skill.zip").replace("{{INVITE_URL}}", url)
	return reply({"url": url, "instructions": guide})

func redeem_family_invite(req: GDWebRequest) -> GDWebResponse:
	var id := req.get_param("id")
	var invite: Dictionary = family_invites.get(id, {})
	if invite.is_empty() or invite.until <= Time.get_ticks_msec():
		family_invites.erase(id)
		return fail("招待の有効期限が切れたか、使用済みです", 404)
	# Prove possession of the URL fragment without sending the decryption key.
	var proof := GD.data.sha256(("FK1-INVITE-PROOF:" + id + ":" + invite.key).to_utf8_buffer()).hex_encode()
	if not Crypto.new().constant_time_compare(proof.to_utf8_buffer(), req.get_header("X-Keys-Invite-Proof").to_utf8_buffer()):
		return fail("招待を確認できません", 403)
	var sealed, err := delivery.seal_with(delivery.rule.to_utf8_buffer(), invite.key)
	if err:
		return fail("招待を処理できません", 500)
	family_invites.erase(id)
	return GD.web.text(sealed)

func family_skill_download(_req: GDWebRequest) -> GDWebResponse:
	return GD.web.with_header(GD.web.bytes(family_skill_zip, "application/zip"), "Content-Disposition", "attachment; filename=\"family-keys-skill.zip\"")

func pack_family_skill(path: String, skill: String) -> Err:
	var archive := ZIPPacker.new()
	if archive.open(path) != OK:
		return Err("Could not create the skill archive")
	for pair in [["skills/family-keys/SKILL.md", "family-keys/SKILL.md"], ["append-env.sh", "family-keys/scripts/append-env.sh"], ["register-env.sh", "family-keys/scripts/register-env.sh"], ["setup-key.sh", "family-keys/scripts/setup-key.sh"]]:
		var bytes: PackedByteArray
		var err: Err
		if pair[1] == "family-keys/SKILL.md":
			bytes = skill.to_utf8_buffer()
		else:
			bytes, err = GD.file.load_bytes(pair[0])
		if err or archive.start_file(pair[1]) != OK or archive.write_file(bytes) != OK or archive.close_file() != OK:
			archive.close()
			return Err("Could not package the family skill")
	if archive.close() != OK:
		return Err("Could not finish the skill archive")
	return null

func build_family_skill(skill: String) -> PackedByteArray, Err:
	var staging := root.path_join("tmp")
	GD.file.ensure_dir(staging)!
	var path := staging.path_join("family-skill-" + GD.id.uuid() + ".zip")
	defer:
		if GD.file.exists(path):
			var _cleanup_err := GD.file.remove(path)
	pack_family_skill(path, skill)?
	return GD.file.load_bytes(path)

func load_distribution() -> Err:
	vault.db.exec("CREATE TABLE IF NOT EXISTS family_distribution(id INTEGER PRIMARY KEY, skill TEXT NOT NULL, guide TEXT NOT NULL, revision INTEGER NOT NULL)")!
	var saved, err := vault.db.query_row("SELECT skill,guide,revision FROM family_distribution WHERE id=1")
	if err:
		distribution = {"skill": GD.file.load_text("skills/family-keys/SKILL.md")!, "guide": SETUP_GUIDE, "revision": 0}
	else:
		distribution = saved
	family_skill_zip = build_family_skill(distribution.skill)!
	return null

func save_distribution(req: GDWebRequest) -> GDWebResponse:
	var data, err := req.read_json()
	if err or not data is Dictionary or not data.get("skill") is String or not data.get("guide") is String:
		return fail("配布文面を確認してください")
	if data.get("revision") != distribution.revision:
		return fail("別の画面で保存されています。開き直してください", 409)
	var skill: String = data.skill.replace("\r\n", "\n").strip_edges() + "\n"
	var guide: String = data.guide.replace("\r\n", "\n").strip_edges()
	var header_end := skill.find("\n---\n", 4)
	if not skill.begins_with("---\n") or header_end < 0 or skill.substr(header_end + 5).strip_edges().is_empty() or skill.to_utf8_buffer().size() > 32768:
		return fail("SKILL.mdの名前・概要・本文を確認してください")
	var header, header_err := GD.data.yaml_to_var(skill.substr(4, header_end - 4))
	if header_err or not header is Dictionary or header.get("name") != "family-keys" or not header.get("description") is String or header.description.strip_edges().is_empty():
		return fail("SKILL.mdの名前・概要・本文を確認してください")
	if guide.to_utf8_buffer().size() > 4096 or guide.count("{{MCP_URL}}") != 1 or guide.count("{{SKILL_URL}}") != 1 or guide.count("{{INVITE_URL}}") != 1:
		return fail("案内には3つのURL用の置換文字を1回ずつ残してください")
	if skill.contains(delivery.secret) or guide.contains(delivery.secret):
		return fail("配布文面から共通キーを削除してください")
	var bytes := family_skill_zip
	if skill != distribution.skill:
		var archive_err: Err
		bytes, archive_err = build_family_skill(skill)
		if archive_err:
			return fail("スキルZIPを更新できません", 500)
	var revision: int = distribution.revision + 1
	var _, save_err := vault.db.exec("INSERT INTO family_distribution(id,skill,guide,revision) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET skill=excluded.skill,guide=excluded.guide,revision=excluded.revision", [skill, guide, revision])
	if save_err:
		return fail("配布文面を保存できません", 500)
	distribution = {"skill": skill, "guide": guide, "revision": revision}
	family_skill_zip = bytes
	return reply(distribution)

func intake_info(req: GDWebRequest) -> GDWebResponse:
	var ticket := vault.intake(req.get_param("id"))
	return fail("Intake was not found", 404) if ticket.is_empty() else reply(ticket)

# A one-time intake link permits submission only, never reading the vault.
func intake_page(_req: GDWebRequest) -> GDWebResponse:
	return GD.web.file("web/intake.html")!

func intake_nonce(id: String) -> String:
	# Bind to this vault and transaction, surviving service restarts.
	return GD.data.hmac_sha256(vault.key.slice(32, 64), ("FK1-INTAKE-CSRF:" + id).to_utf8_buffer()).hex_encode()

func paste_info(req: GDWebRequest) -> GDWebResponse:
	var id := req.get_param("id")
	if id.begins_with("cli-"):
		return fail("入力依頼が見つかりません", 404)
	if id.begins_with("batch-"):
		var group := vault.intake_group(id)
		if group.is_empty():
			return fail("入力依頼が見つかりません", 404)
		var items := group.map(func(ticket): return {"title": ticket.title, "purpose": ticket.note, "variable": ticket.variable})
		return reply({"items": items, "status": group[0].status, "csrf": intake_nonce(id)})
	var ticket := vault.intake(id)
	if ticket.is_empty():
		return fail("入力依頼が見つかりません", 404)
	return reply({"title": ticket.title, "purpose": ticket.note, "variable": ticket.variable, "status": ticket.status, "csrf": intake_nonce(ticket.id)})

func paste_complete(req: GDWebRequest) -> GDWebResponse:
	var id := req.get_param("id")
	if id.begins_with("cli-"):
		return fail("入力依頼が見つかりません", 404)
	if req.get_header("X-Intake-CSRF") != intake_nonce(id):
		return reply({"error": "確認情報を更新して、もう一度OKを押してください。入力内容は保持されています。", "code": "INTAKE_NONCE_STALE"}, 403)
	if id.begins_with("batch-"):
		return paste_group(req, id)
	var ticket := vault.intake(id)
	if ticket.is_empty() or ticket.status != "waiting":
		return fail("この入力は完了済みか、存在しません", 409)
	var data, err := req.read_json()
	if err or not data is Dictionary:
		return fail("キーを貼り付けてください")
	var input, input_err := intake_input(ticket, data.get("value"), data.get("otpauth", ""))
	if input_err:
		return fail(str(input_err))
	return save_intake(req, [input])

func paste_group(req: GDWebRequest, id: String) -> GDWebResponse:
	var group := vault.intake_group(id)
	if group.is_empty() or group[0].status != "waiting":
		return fail("この入力は完了済みか、存在しません", 409)
	var data, err := req.read_json()
	if err or not data is Dictionary or not data.get("values") is Array or data.values.size() != group.size():
		return fail("必要なキーをすべて入力してください")
	var uris = data.get("otpauths", [])
	if not uris is Array or (data.has("otpauths") and uris.size() != group.size()):
		return fail("二段階認証の入力を確認してください")
	var inputs: Array = []
	for i in group.size():
		var input, input_err := intake_input(group[i], data.values[i], "" if uris.is_empty() else uris[i])
		if input_err:
			return fail(str(input_err))
		inputs.append(input)
	return save_intake(req, inputs)

func valid_otpauth(uri: String) -> bool:
	return uri.begins_with("otpauth://") and not uri.contains("\n") and not uri.contains("\r") and not preload("totp.gd").decode(uri).is_empty()

func intake_input(ticket: Dictionary, value: Variant, otpauth: Variant) -> Dictionary, Err:
	if not value is String or value.is_empty() or value.to_utf8_buffer().size() > Core.MAX_ENV:
		return {}, Err("キーを貼り付けてください")
	if not otpauth is String or (not otpauth.is_empty() and not valid_otpauth(otpauth.strip_edges())):
		return {}, Err("有効な otpauth URLを貼り付けてください")
	var env, env_err := GD.data.dict_to_dotenv({ticket.variable: value})
	if env_err:
		return {}, Err("環境変数名を確認してください")
	var input := {"name": ticket.title, "note": ticket.note, "env": env, "intake_id": ticket.id}
	if not otpauth.is_empty():
		input["otp"] = {"variable": ticket.variable, "seed": otpauth.strip_edges()}
	return input, null

func save_intake(req: GDWebRequest, inputs: Array) -> GDWebResponse:
	var saved, save_err := vault.put_many(inputs)
	if save_err:
		return fail(str(save_err), 409)
	for item in saved:
		audit(req, "intake_ok", item.id)
	return reply({"status": "ok"})

func decode_registration(data: Variant, totp_setup: bool = false) -> Dictionary:
	if not data is Dictionary:
		return {"error": "Invalid registration envelope", "status": 400}
	for field in ["nonce", "title", "purpose", "variable", "iv", "cipher", "mac"]:
		if not data.get(field) is String:
			return {"error": "Invalid registration envelope", "status": 400}
	var hex := RegEx.new()
	hex.compile("\\A[0-9a-f]+\\z")
	for pair in [["nonce", 32], ["iv", 32], ["mac", 64]]:
		var value: String = data[pair[0]]
		if value.length() != pair[1] or not hex.search(value):
			return {"error": "Invalid registration envelope", "status": 400}
	if data.title.length() > 1024 or data.purpose.length() > 8192 or data.variable.length() > 256 or data.variable == "FAMILY_KEYS_K":
		return {"error": "Invalid registration metadata", "status": 400}
	var base64 := RegEx.new()
	base64.compile("\\A[A-Za-z0-9+/]*={0,2}\\z")
	if not base64.search(data.title) or not base64.search(data.purpose) or not base64.search(data.cipher):
		return {"error": "Invalid registration envelope", "status": 400}
	var variable_name := RegEx.new()
	variable_name.compile("\\A[A-Za-z_][A-Za-z0-9_]*\\z")
	if not variable_name.search(data.variable):
		return {"error": "Invalid variable name", "status": 400}
	var bytes, decrypt_err := delivery.unseal_registration(data)
	if decrypt_err:
		return {"error": "Authentication failed", "status": 403}
	var title_bytes, title_err := GD.data.base64_to_raw(data.title)
	var purpose_bytes, purpose_err := GD.data.base64_to_raw(data.purpose)
	var title := title_bytes.get_string_from_utf8()
	var purpose := purpose_bytes.get_string_from_utf8()
	if title_err or purpose_err or title.strip_edges().is_empty() or title.length() > 160 or title.to_utf8_buffer() != title_bytes or purpose.to_utf8_buffer() != purpose_bytes:
		return {"error": "Invalid registration metadata", "status": 400}
	var env := bytes.get_string_from_utf8()
	if totp_setup:
		var uri := env.strip_edges()
		if title != "totp" or not purpose.is_empty() or bytes.size() > 4098 or env.to_utf8_buffer() != bytes or not valid_otpauth(uri):
			return {"error": "Invalid TOTP otpauth URI", "status": 400}
		return {"variable": data.variable, "seed": uri}
	if env.to_utf8_buffer() != bytes:
		return {"error": "Use UTF-8", "status": 400}
	var record := {"id": "cli-" + data.nonce, "title": title, "purpose": purpose, "variable": data.variable}
	if env.begins_with("FK1-INTAKE-TOTP\n"):
		var parts := env.split("\n", true, 2)
		if parts.size() != 3 or not valid_otpauth(parts[1].strip_edges()):
			return {"error": "Invalid TOTP otpauth URI", "status": 400}
		record["seed"] = parts[1].strip_edges()
		env = parts[2]
	var values, env_err := GD.data.dotenv_to_dict(env)
	if env.to_utf8_buffer().size() > Core.MAX_ENV or env_err or values.size() != 1 or str(values.get(data.variable, "")).is_empty():
		return {"error": "Specify one nonempty dotenv variable", "status": 400}
	record["env"] = env
	return record

func register_cli(req: GDWebRequest) -> GDWebResponse:
	var data, err := req.read_json()
	if err or not data is Dictionary:
		return fail("Invalid registration envelope")
	var entries = data.get("entries", [data])
	if not entries is Array or entries.is_empty() or entries.size() > MAX_BATCH:
		return fail("Specify 1–32 registrations")
	var decoded: Array = []
	var seen := {}
	var ids := {}
	for entry in entries:
		var record := decode_registration(entry)
		if record.has("error"):
			return fail(record.error, record.status)
		if seen.has(record.variable) or ids.has(record.id):
			return fail("Use unique ENV names")
		seen[record.variable] = true
		ids[record.id] = true
		var prior := vault.intake(record.id)
		if not prior.is_empty() and (prior.title != record.title or prior.note != record.purpose or prior.variable != record.variable):
			return fail("Registration identifier already in use", 409)
		if prior.get("status") != "completed":
			decoded.append(record)
	var inputs: Array = []
	for record in decoded:
		if vault.intake(record.id).is_empty():
			vault.begin_intake(record, record.id)
		var input := {"name": record.title, "note": record.purpose, "env": record.env, "intake_id": record.id}
		if record.has("seed"):
			input["otp"] = {"variable": record.variable, "seed": record.seed}
		inputs.append(input)
	var saved, save_err := vault.put_many(inputs)
	if save_err:
		return fail("保存できませんでした", 409)
	for item in saved:
		audit(req, "intake_ok", item.id)
	return reply({"status": "ok"})

# Audit identifiers only, without request bodies, names, variable values, or download URLs.
func audit(req: GDWebRequest, action: String, id: String) -> void:
	var event := {"at": int(Time.get_unix_time_from_system()), "ip": req.get_value("device").ip, "member": req.get_value("device").member, "action": action, "id": id}
	GD.file.append_text(root.path_join("audit.jsonl"), GD.data.var_to_json(event)! + "\n")

func search_env(query: Variant = "", queries: Variant = null) -> Variant:
	var terms = [query] if queries == null else queries
	if not terms is Array or terms.is_empty() or terms.size() > MAX_BATCH or terms.any(func(term): return not term is String or term.length() > 256):
		return Err("Use 1–32 text queries")
	var items: Array = []
	var seen := {}
	for term in terms:
		for row in vault.search(term):
			if seen.has(row.id):
				continue
			if items.size() == 12:
				return {"items": items, "more": true}
			seen[row.id] = true
			var item: Dictionary = {"id": row.id, "name": row.name}
			if not row.variables.is_empty():
				item["variables"] = row.variables
			if row.has("otp_variable"):
				item["has_totp"] = true
				if row.variables.size() > 1:
					item["totp_env"] = row.otp_variable
			items.append(item)
	return {"items": items}

func intake_status(id: String) -> Dictionary:
	if id.begins_with("batch-"):
		var group := vault.intake_group(id)
		if group.is_empty():
			return {"status":"not_found"}
		return {"status":"ok","item_ids":group.map(func(ticket): return ticket.item_id)} if group[0].status == "completed" else {"status":"waiting"}
	var ticket := vault.intake(id)
	return {"status":"ok","item_id":ticket.item_id} if ticket.get("status") == "completed" else {"status":ticket.get("status","not_found")}

@wait
func wait_intake(id: String) -> Dictionary:
	var until := Time.get_ticks_msec() + 25000
	var snapshot := intake_status(id)
	while snapshot.status == "waiting" and Time.get_ticks_msec() < until:
		Task.sleep(0.25)
		snapshot = intake_status(id)
	return snapshot

func valid_intake(item: Variant) -> bool:
	return item is Dictionary and item.keys().all(func(field): return field in ["title", "purpose", "variable"]) and valid_env_name(item.get("variable")) and item.get("title") is String and not item.title.strip_edges().is_empty() and item.title.length() <= 160 and item.get("purpose", "") is String and str(item.get("purpose","")).length() <= 2048

# Link-bearing tools use the validated origin of their MCP connection.
class MCPLinks:
	var owner: WeakRef
	var origin: String

	var service: FamilyKeysServer:
		get: return owner.get_ref()

	func begin_intake(title: Variant = null, purpose: Variant = "", variable: Variant = null, items: Variant = null) -> Variant:
		var single := {"title": title, "purpose": purpose, "variable": variable}
		var inputs = [single] if items == null else items
		if not inputs is Array or inputs.is_empty() or inputs.size() > MAX_BATCH or inputs.any(func(entry): return not service.valid_intake(entry)):
			return Err("Use title and ENV name. Put otpauth in the form.")
		var names := {}
		for item in inputs:
			if names.has(item.variable) or not service.vault.env_key(item.variable).is_empty():
				return Err("ENV already registered: " + item.variable)
			names[item.variable] = true
		var id: String = service.vault.begin_intake(single).id if items == null else service.vault.begin_intake_group(inputs)
		return {"id": id, "url": origin + "/intake/" + id}

	func manage_env(name: Variant, action: Variant, id: Variant = "", title: Variant = null, purpose: Variant = null) -> Variant:
		var args := {"name": name, "action": action, "id": id}
		if title != null:
			args["title"] = title
		if purpose != null:
			args["purpose"] = purpose
		var token, err := service.prepare_change(args)
		return err if err else {"url": origin + "/agent/manage/" + token}

	func prepare_env(vars: Variant = null, id: Variant = "", otp: Variant = null) -> Variant:
		if not id is String:
			return Err("Invalid identifier")
		if vars != null:
			var selections, err := service.prepare_batch(vars)
			if err:
				return err
			var now := Time.get_ticks_msec()
			for key in service.prepared_batches.keys():
				if service.prepared_batches[key].until <= now:
					service.prepared_batches.erase(key)
			var token := GD.id.uuid()
			service.prepared_batches[token] = {"entries": selections, "until": now + 120000}
			return {"url": origin + "/agent/batch/" + token}
		if otp != null:
			if not service.valid_env_name(otp):
				return Err("Use the original ENV name")
			var matches := service.vault.search(otp).filter(func(row): return row.get("otp_variable") == otp and (id.is_empty() or row.id == id))
			if matches.size() != 1:
				return Err("Select the item id too if more than one item has this ENV name" if matches.size() > 1 else "OTP not configured")
			return {"url": origin + "/agent/otp/" + matches[0].id}
		var row := service.vault.find(id)
		if row.is_empty() or not row.has_env:
			return Err("Item was not found")
		return {"url": origin + "/agent/env/" + row.id, "script": origin + "/assets/append-env.sh"}

	func family_skills(query: Variant = "", name: Variant = "") -> Variant:
		if not query is String or not name is String:
			return Err("Use text for name or query")
		if name.is_empty():
			var term: String = query.strip_edges().left(160)
			var skills := service.skill_list(term)
			return {"names": skills.map(func(skill): return skill.name)} if term.is_empty() else {"items": skills}
		var skill, err := service.vault.db.query_row("SELECT name FROM family_skills WHERE name=?", [name])
		return Err("Skill not found") if err or skill.is_empty() else {"url": origin + "/agent/skills/" + skill.name}

func mcp_for_origin(origin: String) -> GDMCPServer, Err:
	if mcp_by_origin.has(origin):
		return mcp_by_origin[origin].server, null
	var mcp_server := GD.ai.mcp.server("family-keys", {"version": "0.1.0"})
	var links := MCPLinks.new()
	links.owner = weakref(self)
	links.origin = origin
	var string := {"type": "string"}
	var intake := {"type": "object", "properties": {"title": string, "variable": string, "purpose": string}, "required": ["title", "variable"]}
	var selected := {"type": "object", "properties": {"name": string, "id": string}, "required": ["name", "id"]}
	mcp_server.add_tool("search_env", search_env, {"description": "Search metadata. has_totp marks items with OTP.", "schema": {"query": string, "queries": {"type": "array", "items": string}}})?
	mcp_server.add_tool("prepare_env", links.prepare_env, {"description": "One encrypted download. bundle-json returns env and totp[ENV_NAME].", "schema": {"vars": {"type": "array", "items": {"anyOf": [string, selected]}}, "id": string, "otp": string}})?
	mcp_server.add_tool("manage_env", links.manage_env, {"description": "Update, delete, or set otpauth via skill CLI.", "schema": {"name": string, "action": {"type": "string", "enum": ["update", "delete", "totp"]}, "id": string, "title": string, "purpose": string}})?
	mcp_server.add_tool("family_skills", links.family_skills, {"description": "List, search, or get a skill URL.", "schema": {"query": string, "name": string}})?
	mcp_server.add_tool("begin_intake", links.begin_intake, {"description": "Register ENVs in a form with optional otpauth. Use title and variable, or items.", "schema": {"title": string, "purpose": string, "variable": string, "items": {"type": "array", "items": intake}}})?
	mcp_server.add_tool("intake_status", intake_status, {"description": "Get status."})?
	mcp_server.add_tool("wait_intake", wait_intake, {"description": "Wait for registration."})?
	mcp_by_origin[origin] = {"server": mcp_server, "links": links}
	return mcp_server, null

@wait
func mcp(req: GDWebRequest) -> GDWebResponse, Err:
	# The runtime ignores unknown arguments. Reject them on write tools before creating a ticket.
	var message, err := req.read_json()
	if not err and message is Dictionary and (message.get("jsonrpc") != "2.0" or not message.get("method") is String):
		return reply({"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "Invalid Request"}}, 400), null
	if not err and message is Dictionary and message.get("method") == "tools/call" and message.get("params") is Dictionary:
		if not message.has("id") or message.id == null:
			return GD.web.text("", 202), null
		var params: Dictionary = message.params
		var allowed: Array = MCP_WRITE_FIELDS.get(params.get("name"), [])
		var args = params.get("arguments", {})
		if not allowed.is_empty() and (not args is Dictionary or args.keys().any(func(key): return key not in allowed)):
			return reply({"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32602, "message": "Use the form or encrypted CLI for secrets"}}), null
	var origin := ("https://" if req.is_tls() else "http://") + req.host.to_lower()
	var service := mcp_for_origin(origin)?
	return service.handle(req)

func main(args) -> int:
	root = GD.cli.get_cwd().path_join("state") if args.is_empty() else str(args[0])
	var text, read_err := GD.file.load_text(root.path_join("config.json"))
	if read_err:
		printerr("Run ./keys init first")
		return 1
	var loaded, parse_err := GD.data.json_to_var(text)
	if parse_err or not loaded is Dictionary:
		printerr("Invalid server configuration")
		return 1
	cfg = loaded
	var open_err := vault.open(root)
	if open_err:
		printerr("Vault could not be authenticated")
		return 1
	if delivery.open(root):
		printerr("Family delivery rule could not be initialized")
		return 1
	load_distribution()!
	if auth.open(root):
		printerr("Web entrance could not be opened")
		return 1
	app.show_errors(false)
	app.pre(guard)
	app.after(headers)
	app.set_limits({"read_header_timeout": 10.0, "read_timeout": 30.0, "write_timeout": 30.0})!
	app.route("GET", "/", home)!
	app.route("GET", "/assets/:name", asset)!
	app.route("GET", "/api/status", status)!
	app.route("GET", "/api/family-rule", family_rule)!
	app.route("GET", "/api/family-key", family_key_download)!
	app.route("POST", "/api/family-invite", create_family_invite)!
	app.route("GET", "/api/family-skill", family_skill_download)!
	app.route("GET", "/api/family-distribution", func(_req): return reply(distribution))!
	app.route("POST", "/api/family-distribution", save_distribution)!
	app.route("POST", "/api/login", auth.login)!
	app.route("POST", "/api/logout", auth.logout)!
	app.route("GET", "/api/items", listing)!
	app.route("POST", "/api/items", save)!
	app.route("DELETE", "/api/items/:id", remove)!
	app.route("GET", "/api/items/:id/download", download)!
	app.route("GET", "/agent/env/:id", download)!
	app.route("GET", "/agent/batch/:id", batch_download)!
	app.route("GET", "/agent/otp/:id", func(req): return otp_response(req, true))!
	app.route("POST", "/api/items/:id/otp", func(req): return otp_response(req, false))!
	app.route("POST", "/api/items/:id/otp/settings", save_otp_settings)!
	app.route("GET", "/api/skills", func(_req): return reply({"items": skill_list("")}))!
	app.route("POST", "/api/skills", skill_save)!
	app.route("GET", "/api/skills/:name", func(req): return skill_read(req, true))!
	app.route("DELETE", "/api/skills/:name", skill_delete)!
	app.route("GET", "/agent/skills/:name", func(req): return skill_read(req, false))!
	app.route("POST", "/agent/register", register_cli)!
	app.route("POST", "/agent/manage/:id", apply_change)!
	app.route("POST", "/agent/setup/:id", redeem_family_invite)!
	app.route("POST", "/api/items/:id/reveal", reveal)!
	app.route("GET", "/api/intakes/:id", intake_info)!
	app.route("GET", "/intake/:id", intake_page)!
	app.route("GET", "/intake/:id/info", paste_info)!
	app.route("POST", "/intake/:id", paste_complete)!
	app.route("GET", "/api/devices", devices)!
	app.route("POST", "/api/devices", save_devices)!
	app.route("POST", "/mcp", mcp)!
	app.route("GET", "/mcp", func(_req): return GD.web.with_header(GD.web.text("", 405), "Allow", "POST"))!
	var listen_err := app.listen(cfg.port, cfg.bind)
	if listen_err:
		printerr("HTTP could not start; check the bind address and port")
		return 1
	print("Family Keys: http://", cfg.get("public_host", "localhost"), ":", app.port)
	return 0
