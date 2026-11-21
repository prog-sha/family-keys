extends RefCounted

# RFC 6238 defaults used by authenticator apps: Base32, SHA-1, 6 digits, 30 seconds.
static func decode(input: String) -> PackedByteArray:
	var value := input.strip_edges()
	if value.begins_with("otpauth:"):
		value = uri_seed(value)
	var text := value.to_upper().replace(" ", "").strip_edges()
	if text.contains("="):
		var raw := text.get_slice("=", 0)
		if text.length() % 8 != 0 or text != raw + "=".repeat(text.length() - raw.length()):
			return PackedByteArray()
		text = raw
	if text.length() < 16 or text.length() > 256:
		return PackedByteArray()
	var alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var output := PackedByteArray()
	var bits := 0
	var buffer := 0
	for character in text:
		var digit := alphabet.find(character)
		if digit < 0:
			return PackedByteArray()
		buffer = (buffer << 5) | digit
		bits += 5
		if bits >= 8:
			bits -= 8
			output.append(buffer >> bits)
			buffer &= (1 << bits) - 1
	return output if buffer == 0 and bits < 5 else PackedByteArray()

static func uri_seed(uri: String) -> String:
	if not uri.begins_with("otpauth://totp/") or uri.length() > 4096 or uri.contains("#"):
		return ""
	var split := uri.split("?", true, 1)
	if split.size() != 2 or split[0] == "otpauth://totp/":
		return ""
	var params := {}
	for field in split[1].split("&", false):
		var pair := field.split("=", true, 1)
		if pair.size() != 2:
			return ""
		var name := pair[0].uri_decode().to_lower()
		if params.has(name):
			return ""
		params[name] = pair[1].uri_decode()
	if str(params.get("algorithm", "SHA1")).to_upper() != "SHA1" or params.get("digits", "6") != "6" or params.get("period", "30") != "30":
		return ""
	return str(params.get("secret", ""))

static func code(secret: PackedByteArray, unix_time: int) -> String:
	var message := PackedByteArray()
	message.resize(8)
	var counter := int(unix_time / 30.0)
	for i in 8:
		message[7 - i] = (counter >> (i * 8)) & 255
	var mac := Crypto.new().hmac_digest(HashingContext.HASH_SHA1, secret, message)
	if mac.size() != 20:
		return ""
	var offset := mac[-1] & 15
	var value := ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3]
	return "%06d" % (value % 1000000)
