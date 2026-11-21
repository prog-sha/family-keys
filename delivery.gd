# Encrypt downloads with the family rule's shared secret and authenticate every ciphertext.
extends RefCounted
const Core = preload("core.gd")
var secret: String
var rule: String

func open(root: String) -> Err:
	var path := root.path_join("FAMILY-RULE.md")
	var pattern := RegEx.new()
	pattern.compile("(?m)^(?:K|FAMILY_KEYS_K)=([A-Za-z0-9_-]{32,})")
	if GD.file.exists(path):
		var text, err := GD.file.load_text(path)
		if err:
			return Err("Family rule could not be opened")
		var found := pattern.search(text)
		if found == null:
			return Err("Family rule is invalid")
		secret = found.get_string(1)
	else:
		secret = GD.data.raw_to_base64url(Crypto.new().generate_random_bytes(32))
	rule = "FAMILY_KEYS_K=" + secret + "\n"
	return Core.private_write(path, rule.to_utf8_buffer())

func seal(bytes: PackedByteArray) -> String, Err:
	return seal_with(bytes, secret)

func seal_with(bytes: PackedByteArray, recipient_secret: String) -> String, Err:
	var iv := Crypto.new().generate_random_bytes(16)
	var key := GD.data.sha256(("FK1-ENC:" + recipient_secret).to_utf8_buffer())
	var plain := bytes.duplicate()
	var pad := 16 - plain.size() % 16
	for i in pad:
		plain.append(pad)
	var aes := AESContext.new()
	if aes.start(AESContext.MODE_CBC_ENCRYPT, key, iv) != OK:
		return "", Err("Delivery encryption failed")
	var cipher := GD.data.raw_to_base64(aes.update(plain))
	aes.finish()
	var signed := iv.hex_encode() + "\n" + cipher
	var mac := GD.data.hmac_sha256(("FK1-MAC:" + recipient_secret).to_utf8_buffer(), signed.to_utf8_buffer()).hex_encode()
	return mac + "\n" + signed, null

func unseal_registration(request: Dictionary) -> PackedByteArray, Err:
	var signed := "\n".join(["FK1-REGISTER", request.nonce, request.title, request.purpose, request.variable, request.iv, request.cipher])
	var mac_key := GD.data.sha256(("FK1-REGISTER-MAC:" + request.nonce + ":" + secret).to_utf8_buffer())
	var mac := GD.data.hmac_sha256(mac_key, signed.to_utf8_buffer())
	var rejected := Err("Invalid registration envelope")
	if not Crypto.new().constant_time_compare(mac, request.mac.hex_decode()):
		return PackedByteArray(), rejected
	var cipher, err := GD.data.base64_to_raw(request.cipher)
	if err or cipher.is_empty() or cipher.size() % 16 != 0 or cipher.size() > Core.MAX_ENV + 16:
		return PackedByteArray(), rejected
	var key := GD.data.sha256(("FK1-REGISTER-ENC:" + request.nonce + ":" + secret).to_utf8_buffer())
	var aes := AESContext.new()
	if aes.start(AESContext.MODE_CBC_DECRYPT, key, request.iv.hex_decode()) != OK:
		return PackedByteArray(), rejected
	var plain := aes.update(cipher)
	aes.finish()
	var padding := int(plain[-1])
	if padding < 1 or padding > 16:
		return PackedByteArray(), rejected
	for offset in padding:
		if plain[-1 - offset] != padding:
			return PackedByteArray(), rejected
	return plain.slice(0, plain.size() - padding), null
