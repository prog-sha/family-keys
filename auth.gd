# Authenticate the shared web entrance without exposing passwords to logs or MCP.
extends RefCounted
@model
class LoginInput:
	@field(min = 1, max = 1024, secret = true)
	var password: String = ""

var stored: Dictionary
var sessions: Dictionary = {}
var attempts: Dictionary = {}

static func initialize(root: String, password: String) -> Err:
	var path := root.path_join("auth.json")
	var salt := Crypto.new().generate_random_bytes(24)
	var password_hash := GD.data.pbkdf2_sha256(password.to_utf8_buffer(), salt, 210000)?
	return preload("core.gd").private_write(path, GD.data.var_to_json({"salt": GD.data.raw_to_base64(salt), "hash": GD.data.raw_to_base64(password_hash), "rounds": 210000})?.to_utf8_buffer(), false)

func open(root: String) -> Err:
	var text, err := GD.file.load_text(root.path_join("auth.json"))
	if err:
		return Err("Web entrance is not initialized")
	var data, parse_err := GD.data.json_to_var(text)
	if parse_err or not data is Dictionary:
		return Err("Web entrance configuration is invalid")
	stored = data
	return null

func session(req: GDWebRequest) -> Dictionary:
	var token := req.get_cookie("keys_session")
	var digest := GD.data.sha256(token.to_utf8_buffer()).hex_encode()
	var found: Dictionary = sessions.get(digest, {})
	if found.is_empty() or found.ip != req.ip or found.until < Time.get_unix_time_from_system():
		sessions.erase(digest)
		return {}
	return found

func login(req: GDWebRequest) -> GDWebResponse:
	var data, err := req.bind(LoginInput)
	if err:
		return GD.web.json({"error": "パスワードを入力してください"}, 400)!
	var now := Time.get_unix_time_from_system()
	var attempt: Dictionary = attempts.get(req.ip, {"since": now, "count": 0})
	if now - attempt.since > 60:
		attempt = {"since": now, "count": 0}
	if attempt.count >= 10:
		return GD.web.json({"error": "少し待ってからお試しください"}, 429)!
	attempt.count += 1
	attempts[req.ip] = attempt
	var salt := GD.data.base64_to_raw(stored.salt)!
	var expected := GD.data.base64_to_raw(stored.hash)!
	var actual := GD.data.pbkdf2_sha256(data.password.to_utf8_buffer(), salt, stored.rounds)!
	if not Crypto.new().constant_time_compare(expected, actual):
		return GD.web.json({"error": "パスワードが違います"}, 401)!
	attempts.erase(req.ip)
	var token := GD.id.token()!
	var digest := GD.data.sha256(token.to_utf8_buffer()).hex_encode()
	sessions[digest] = {"ip": req.ip, "until": now + 43200, "csrf": GD.id.token()!}
	var response := GD.web.json({"status": "logged_in"})!
	return GD.web.with_header(response, "Set-Cookie", "keys_session=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200")

func logout(req: GDWebRequest) -> GDWebResponse:
	sessions.erase(GD.data.sha256(req.get_cookie("keys_session").to_utf8_buffer()).hex_encode())
	return GD.web.with_header(GD.web.json({"status": "logged_out"})!, "Set-Cookie", "keys_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
