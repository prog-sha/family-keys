# Authenticate the shared web entrance without exposing passwords to logs or MCP.
@import "./core"

@model
class LoginInput:
	@field(min = 1, max = 1024, secret = true)
	var password: String = ""

var stored: Dictionary
var sessions: Dictionary = {}
var attempts: Dictionary = {}

static func initialize(root: String, password: String) -> Err:
	var path := root.path_join("auth.json")
	var salt := GD.data.random(24)
	var password_hash := GD.data.pbkdf2_sha256(password, salt, 210000)?
	return core.private_write(path, GD.data.to_json({"salt": GD.data.to_base64(salt), "hash": GD.data.to_base64(password_hash), "rounds": 210000})?.to_utf8_buffer(), false)

func open(root: String) -> Err:
	var data, err := GD.file.load_json(root.path_join("auth.json"))
	if err or not data is Dictionary:
		return Err("Web entrance configuration is invalid")
	stored = data
	return null

func session(req: GDWebRequest) -> Dictionary:
	var token := req.get_cookie("keys_session")
	var digest := GD.data.sha256_hex(token)
	var found: Dictionary = sessions.get(digest, {})
	if found.is_empty() or found.ip != req.ip or found.until < Time.get_unix_time_from_system():
		sessions.erase(digest)
		return {}
	return found

func login(req: GDWebRequest) -> GDWebResponse:
	var data, err := req.bind(LoginInput)
	if err:
		return GD.web.json({"error": "Enter your password."}, 400)!
	var now := Time.get_unix_time_from_system()
	var attempt: Dictionary = attempts.get(req.ip, {"since": now, "count": 0})
	if now - attempt.since > 60:
		attempt = {"since": now, "count": 0}
	if attempt.count >= 10:
		return GD.web.json({"error": "Wait a moment before trying again."}, 429)!
	attempt.count += 1
	attempts[req.ip] = attempt
	var salt := GD.data.from_base64(stored.salt)!
	var expected := GD.data.from_base64(stored.hash)!
	var actual := GD.data.pbkdf2_sha256(data.password, salt, stored.rounds)!
	if not GD.data.equal(expected, actual):
		return GD.web.json({"error": "Incorrect password."}, 401)!
	attempts.erase(req.ip)
	var token := GD.id.token()!
	var digest := GD.data.sha256_hex(token)
	sessions[digest] = {"ip": req.ip, "until": now + 43200, "csrf": GD.id.token()!}
	var response := GD.web.json({"status": "logged_in"})!
	return GD.web.with_header(response, "Set-Cookie", "keys_session=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200")

func logout(req: GDWebRequest) -> GDWebResponse:
	sessions.erase(GD.data.sha256_hex(req.get_cookie("keys_session")))
	return GD.web.with_header(GD.web.json({"status": "logged_out"})!, "Set-Cookie", "keys_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
