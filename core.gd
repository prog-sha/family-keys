# Keep arbitrary service notes and exact dotenv documents in authenticated SQLite records.
extends RefCounted

const MAX_ENV := 1048576
const Totp = preload("totp.gd")
var root: String
var key: PackedByteArray
var db: GDSQLiteDB
var index: GDSQLiteDB
var crypto := Crypto.new()

func open(dir: String) -> Err:
	root = dir
	var raw, err := GD.file.load_bytes(root.path_join("master.key"))
	if err or raw.size() != 64:
		return Err("Key storage could not be opened")
	key = raw
	var opened, db_err := GD.db.sqlite.open(root.path_join("keys.sqlite3"))
	if db_err:
		return Err("SQLite could not be opened")
	db = opened
	db.exec("PRAGMA secure_delete=ON")!
	db.exec("CREATE TABLE IF NOT EXISTS items(id TEXT PRIMARY KEY, record TEXT NOT NULL)")!
	db.exec("CREATE TABLE IF NOT EXISTS env_keys(name TEXT NOT NULL PRIMARY KEY, item_id TEXT) WITHOUT ROWID")!
	db.exec("CREATE TABLE IF NOT EXISTS family_skills(name TEXT PRIMARY KEY, summary TEXT NOT NULL, body TEXT NOT NULL)")!
	db.exec("CREATE TABLE IF NOT EXISTS intakes(id TEXT PRIMARY KEY, title TEXT NOT NULL, note TEXT NOT NULL, variable TEXT NOT NULL, status TEXT NOT NULL, item_id TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL)")!
	db.exec("CREATE TABLE IF NOT EXISTS intake_groups(id TEXT PRIMARY KEY, members TEXT NOT NULL)")!
	FileAccess.set_unix_permissions(root.path_join("keys.sqlite3"), 384)
	index = GD.db.sqlite.open(":memory:")!
	index.exec("CREATE VIRTUAL TABLE lookup USING fts5(id UNINDEXED, text, tokenize='trigram')")!
	for saved in db.query_all("SELECT record FROM items")!:
		var row, parse_err := GD.data.json_to_var(saved.record)
		if parse_err or not row is Dictionary or not verify(row):
			return Err("Vault authentication failed")
		var body, body_err := unpack(row)
		if body_err:
			return body_err
		index_row(row, body.note)
	db.exec("BEGIN IMMEDIATE")!
	db.exec("DELETE FROM env_keys")!
	db.exec("INSERT INTO env_keys(name,item_id) SELECT names.value, CASE WHEN count(*)=1 THEN min(items.id) END FROM items,json_each(items.record,'$.variables') AS names GROUP BY names.value")!
	db.exec("COMMIT")!
	return null

func signature(row: Dictionary) -> PackedByteArray:
	var unsigned := row.duplicate(true)
	unsigned.erase("mac")
	var text := GD.data.var_to_json(unsigned, {"deterministic": true})!
	return GD.data.hmac_sha256(key.slice(32, 64), text.to_utf8_buffer())

func verify(row: Dictionary) -> bool:
	var mac, err := GD.data.base64_to_raw(str(row.get("mac", "")))
	return err == null and crypto.constant_time_compare(signature(row), mac)

func metadata(row: Dictionary) -> Dictionary:
	var out := row.duplicate(true)
	out.erase("iv")
	out.erase("cipher")
	out.erase("mac")
	return out

# Keep full prose searchable in an in-memory FTS index, never as plaintext on disk.
func index_row(row: Dictionary, note: String) -> void:
	index.exec("DELETE FROM lookup WHERE id=?", [row.id])!
	var text := canonical(row.name + " " + row.aliases + " " + note + " " + " ".join(row.variables))
	index.exec("INSERT INTO lookup(id,text) VALUES(?,?)", [row.id, text])!

func canonical(text: String) -> String:
	var normalized := text.to_lower().replace("　", " ")
	for pair in [["ディスコード", "discord"], ["ギットハブ", "github"], ["ボット", "bot"]]:
		normalized = normalized.replace(pair[0], pair[1])
	return normalized

func search(query: String = "") -> Array:
	var normalized := canonical(query)
	for filler in ["に使う", "に使える", "のための", "のやつ", "したい", "ください", "トークン", "パスワード", "の", "用の", "する"]:
		normalized = normalized.replace(filler, " ")
	var terms := normalized.split(" ", false)
	var scores: Dictionary = {}
	for term in terms:
		if term.length() >= 3:
			var expression := "\"" + term.replace("\"", "\"\"") + "\""
			var hits, err := index.query_all("SELECT id, rank FROM lookup WHERE lookup MATCH ? ORDER BY rank", [expression])
			if not err:
				for hit in hits:
					scores[hit.id] = scores.get(hit.id, 0.0) + 10.0 - float(hit.rank)
		for hit in index.query_all("SELECT id FROM lookup WHERE instr(text,?)>0", [term])!:
			scores[hit.id] = scores.get(hit.id, 0.0) + 1.0
	var out: Array = []
	for saved in db.query_all("SELECT record FROM items")!:
		var row: Dictionary = GD.data.json_to_var(saved.record)!
		if not query.strip_edges().is_empty() and not scores.has(row.id):
			continue
		var item := metadata(row)
		item["score"] = scores.get(row.id, 0.0)
		out.append(item)
	out.sort_custom(func(a, b): return a.score > b.score if a.score != b.score else a.updated > b.updated)
	return out

func find(id: String) -> Dictionary:
	var saved, err := db.query_row("SELECT record FROM items WHERE id=?", [id])
	if err:
		return {}
	var row: Dictionary = GD.data.json_to_var(saved.record)!
	return row if verify(row) else {}

func env_key(name: String) -> Dictionary:
	var row, err := db.query_row("SELECT item_id FROM env_keys WHERE name=?", [name])
	return {} if err else row

# A legacy collision reserves the name until only one item uses it.
func refresh_env_key(name: String) -> void:
	db.exec("DELETE FROM env_keys WHERE name=?", [name])!
	db.exec("INSERT INTO env_keys(name,item_id) SELECT ?, CASE WHEN count(*)=1 THEN min(items.id) END FROM items,json_each(items.record,'$.variables') AS names WHERE names.value=? HAVING count(*)>0", [name, name])!

# Encrypt prose and original bytes; metadata alone can be returned to an agent.
func format_env_fields(fields: Variant, old: Dictionary) -> String, Err:
	if not fields is Array or fields.is_empty() or fields.size() > 256:
		return "", Err("ENV名を1つ以上入力してください")
	var pattern := RegEx.new()
	pattern.compile("\\A[A-Za-z_][A-Za-z0-9_]{0,255}\\z")
	var values := {}
	for field in fields:
		if not field is Dictionary or not field.get("name") is String or not field.get("value") is String or field.name == "FAMILY_KEYS_K" or not pattern.search(field.name):
			return "", Err("ENV名には半角英数字とアンダースコアを使ってください")
		if values.has(field.name):
			return "", Err("同じENV名は複数登録できません")
		values[field.name] = field.value
	if old.get("has_env", false):
		var existing, err := env_bytes(old)
		if err:
			return "", err
		var current := existing.get_string_from_utf8()
		var parsed, parse_err := GD.data.dotenv_to_dict(current)
		if not parse_err and parsed == values:
			return current, null
	return GD.data.dict_to_dotenv(values)

func put(input: Dictionary) -> Dictionary, Err:
	var saved, err := put_many([input])
	return {} if err else saved[0], err

func put_record(input: Dictionary) -> Dictionary, Err:
	var name = input.get("name", "")
	var aliases = input.get("aliases", "")
	var note = input.get("note", "")
	var env = input.get("env", "")
	if not name is String or name.strip_edges().is_empty() or name.length() > 160 or not aliases is String or not note is String or not env is String:
		return {}, Err("Check the title, notes, and dotenv document")
	var id = input.get("id", "")
	if not id is String:
		return {}, Err("Invalid item identifier")
	var old := find(id)
	if not id.is_empty() and old.is_empty():
		return {}, Err("Item was not found")
	if input.has("env_fields"):
		if input.has("env") or input.has("env_base64"):
			return {}, Err("ENVの入力方法を1つにしてください")
		if not old.is_empty() and input.get("revision") != old.revision:
			return {}, Err("別の画面で変更されています。開き直してください")
		if input.env_fields is Array and input.env_fields.size() > maxi(1, old.get("variables", []).size()):
			return {}, Err("新しいENV名は別の項目として登録してください")
		var generated, fields_err := format_env_fields(input.env_fields, old)
		if fields_err:
			return {}, fields_err
		env = generated
	var source := env.to_utf8_buffer()
	if input.has("env_base64"):
		if not input.env_base64 is String:
			return {}, Err("Invalid document encoding")
		var decoded, decode_err := GD.data.base64_to_raw(input.env_base64)
		if decode_err:
			return {}, Err("Invalid document encoding")
		source = decoded
		env = source.get_string_from_utf8()
		if env.to_utf8_buffer() != source:
			return {}, Err("Use a UTF-8 dotenv file")
	if source.size() > MAX_ENV or note.to_utf8_buffer().size() > MAX_ENV or aliases.length() > 1000 or env.contains(String.chr(0)):
		return {}, Err("Document is too large or invalid")
	if source.is_empty() and note.strip_edges().is_empty():
		return {}, Err("Enter a note, a password, or a dotenv document")
	var vars := {}
	if not source.is_empty():
		var parsed, parse_err := GD.data.dotenv_to_dict(env)
		if parse_err or parsed.is_empty():
			return {}, Err("Use KEY=value in the optional dotenv field")
		vars = parsed
	var previous_names: Array = old.get("variables", [])
	for variable in vars:
		if variable not in previous_names and not env_key(variable).is_empty():
			return {}, Err("ENV already registered: " + variable)
	if id.is_empty():
		id = GD.id.uuid()
	var otp := {}
	if old.has("otp_variable"):
		var old_body, old_err := unpack(old)
		if old_err:
			return {}, old_err
		otp = old_body.get("otp", {})
	var otp_update = input.get("otp", {})
	if not otp_update is Dictionary:
		return {}, Err("認証コードの入力を確認してください")
	if otp_update.get("remove") == true:
		otp = {}
	elif not otp_update.is_empty():
		var variable = otp_update.get("variable")
		var seed = otp_update.get("seed", "")
		if not variable is String or not seed is String or not vars.has(variable):
			return {}, Err("認証コードには同じ項目にある元のENV名を指定してください")
		var decoded := Totp.decode(seed)
		if not seed.is_empty():
			if decoded.is_empty():
				return {}, Err("Base32設定キー、または6桁・30秒・SHA1のTOTP用otpauth URLを入力してください")
			otp = {"seed": GD.data.raw_to_base64(decoded)}
		if otp.is_empty():
			return {}, Err("認証コードの設定キーを入力してください")
		otp["variable"] = variable
	if not otp.is_empty() and not vars.has(otp.variable):
		return {}, Err("認証コードに紐づくENV名を残すか、認証コード設定を解除してください")
	var now := int(Time.get_unix_time_from_system())
	var row := {"id": id, "owner": "ALL", "name": name.strip_edges(), "aliases": aliases, "variables": vars.keys(), "has_env": not source.is_empty(), "updated": now, "created": old.get("created", now), "revision": int(old.get("revision", 0)) + 1}
	var body := {"env_base64": GD.data.raw_to_base64(source), "note": note}
	if not otp.is_empty():
		row["otp_variable"] = otp.variable
		body["otp"] = otp
	var plain := GD.data.var_to_json(body)!.to_utf8_buffer()
	var iv := crypto.generate_random_bytes(16)
	var padding := 16 - plain.size() % 16
	for i in padding:
		plain.append(padding)
	var aes := AESContext.new()
	if aes.start(AESContext.MODE_CBC_ENCRYPT, key.slice(0, 32), iv) != OK:
		return {}, Err("Encryption could not start")
	row["iv"] = GD.data.raw_to_base64(iv)
	row["cipher"] = GD.data.raw_to_base64(aes.update(plain))
	aes.finish()
	row["mac"] = GD.data.raw_to_base64(signature(row))
	var _, save_err := db.exec("INSERT INTO items(id,record) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET record=excluded.record", [id, GD.data.var_to_json(row)!])
	var ticket = input.get("intake_id", "")
	if not save_err and ticket is String and not ticket.is_empty():
		var changed, ticket_err := db.exec("UPDATE intakes SET status='completed', item_id=? WHERE id=? AND status='waiting'", [id, ticket])
		if ticket_err or changed != 1:
			save_err = Err("Intake is unavailable")
	if save_err:
		return {}, Err("Save did not complete")
	for variable in previous_names:
		if not vars.has(variable):
			refresh_env_key(variable)
	for variable in vars:
		if variable not in previous_names:
			db.exec("INSERT INTO env_keys(name,item_id) VALUES(?,?)", [variable, id])!
	return metadata(row), null

func put_many(inputs: Array) -> Array, Err:
	if inputs.is_empty():
		return [], null
	db.exec("BEGIN IMMEDIATE")!
	var saved: Array = []
	for input in inputs:
		var item, err := put_record(input)
		if err:
			db.exec("ROLLBACK")!
			return [], err
		saved.append(item)
	db.exec("COMMIT")!
	for i in saved.size():
		index_row(saved[i], inputs[i].get("note", ""))
	return saved, null

func decrypt(row: Dictionary) -> PackedByteArray, Err:
	if not verify(row):
		return PackedByteArray(), Err("Vault authentication failed")
	var iv, iv_err := GD.data.base64_to_raw(row.iv)
	var cipher, cipher_err := GD.data.base64_to_raw(row.cipher)
	if iv_err or cipher_err or iv.size() != 16 or cipher.is_empty() or cipher.size() % 16 != 0:
		return PackedByteArray(), Err("Vault record is invalid")
	var aes := AESContext.new()
	if aes.start(AESContext.MODE_CBC_DECRYPT, key.slice(0, 32), iv) != OK:
		return PackedByteArray(), Err("Decryption could not start")
	var plain := aes.update(cipher)
	aes.finish()
	var padding := int(plain[-1])
	if padding < 1 or padding > 16:
		return PackedByteArray(), Err("Vault record is invalid")
	for i in padding:
		if plain[plain.size() - 1 - i] != padding:
			return PackedByteArray(), Err("Vault record is invalid")
	return plain.slice(0, plain.size() - padding), null

func unpack(row: Dictionary) -> Dictionary, Err:
	var bytes, err := decrypt(row)
	if err:
		return {}, err
	var value, parse_err := GD.data.json_to_var(bytes.get_string_from_utf8())
	if parse_err or not value is Dictionary:
		return {}, Err("Record is invalid")
	return value, null

func env_bytes(row: Dictionary) -> PackedByteArray, Err:
	var body, err := unpack(row)
	if err:
		return PackedByteArray(), err
	return GD.data.base64_to_raw(body.env_base64)

func erase(id: String) -> Err:
	db.exec("BEGIN IMMEDIATE")!
	var row := find(id)
	var _, err := db.exec("DELETE FROM items WHERE id=?", [id])
	if err:
		db.exec("ROLLBACK")!
		return err
	for variable in row.get("variables", []):
		refresh_env_key(variable)
	db.exec("COMMIT")!
	index.exec("DELETE FROM lookup WHERE id=?", [id])!
	return null

func begin_intake(data: Dictionary, id: String = "") -> Dictionary:
	if id.is_empty():
		id = GD.id.uuid()
	var title := str(data.get("title", "新しいキー"))
	var note := str(data.get("purpose", ""))
	var variable := str(data.get("variable", "API_KEY"))
	db.exec("INSERT INTO intakes(id,title,note,variable,status,created) VALUES(?,?,?,?,'waiting',?)", [id, title, note, variable, int(Time.get_unix_time_from_system())])!
	return intake(id)

func intake(id: String) -> Dictionary:
	var row, err := db.query_row("SELECT id,title,note,variable,status,item_id FROM intakes WHERE id=?", [id])
	return {} if err else row

func begin_intake_group(entries: Array) -> String:
	var id := "batch-" + GD.id.uuid()
	var members: Array = []
	for entry in entries:
		members.append(begin_intake(entry).id)
	db.exec("INSERT INTO intake_groups(id,members) VALUES(?,?)", [id, GD.data.var_to_json(members)!])!
	return id

func intake_group(id: String) -> Array:
	var row, err := db.query_row("SELECT members FROM intake_groups WHERE id=?", [id])
	if err:
		return []
	var ids: Array = GD.data.json_to_var(row.members)!
	return ids.map(func(member): return intake(member))

# Write atomically through a private sibling directory and reject symbolic links.
static func private_write(path: String, bytes: PackedByteArray, replace: bool = true) -> Err:
	if not path.is_absolute_path():
		return Err("An absolute destination is required")
	var parent := path.get_base_dir()
	var dir := DirAccess.open(parent)
	if dir == null:
		return Err("Destination directory does not exist")
	if dir.is_link(path.get_file()) or dir.dir_exists(path.get_file()):
		return Err("Destination must be a regular file")
	if not replace and dir.file_exists(path.get_file()):
		return Err("Destination exists; explicitly enable overwrite to replace it")
	var work := parent.path_join(".keys-" + GD.id.uuid())
	if DirAccess.make_dir_absolute(work) != OK:
		return Err("Could not create a private staging directory")
	if OS.get_name() != "Windows" and FileAccess.set_unix_permissions(work, 448) != OK:
		DirAccess.remove_absolute(work)
		return Err("Could not protect the staging directory")
	var temp := work.path_join("payload")
	var err := GD.file.save_bytes(temp, bytes)
	if not err and OS.get_name() != "Windows" and FileAccess.set_unix_permissions(temp, 384) != OK:
		err = Err("Could not protect the destination file")
	if not err:
		# Link atomically without replacing when the caller did not grant overwrite.
		if not replace:
			var linked, link_err := GD.cli.run("ln", [temp, path])
			if link_err or linked.get("code", 1) != 0:
				err = Err("Destination exists or could not be created")
		else:
			err = GD.file.rename(temp, path)
	if GD.file.exists(temp):
		GD.file.remove(temp)
	DirAccess.remove_absolute(work)
	return err
