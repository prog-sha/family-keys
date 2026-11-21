# Public connection settings; no vault data belongs here.
extends RefCounted

static func load_settings() -> Dictionary, Err:
	var path := "settings.local.json" if GD.file.exists("settings.local.json") else "settings.example.json"
	var text, read_error := GD.file.load_text(path)
	if read_error:
		return {}, Err("Could not read settings file")
	var value, parse_error := GD.data.json_to_var(text)
	if parse_error or not value is Dictionary:
		return {}, Err("Invalid settings file")
	var port = value.get("port")
	if not (port is int or port is float) or float(port) != floor(float(port)) or port < 1 or port > 65535:
		return {}, Err("settings file port must be an integer from 1 to 65535")
	var host = value.get("host")
	var pattern := RegEx.new()
	pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9.-]*$")
	if not host is String or pattern.search(host) == null:
		return {}, Err("settings file host must be a hostname or IPv4 address")
	var aliases = value.get("aliases", [])
	if not aliases is Array:
		return {}, Err("settings file aliases must be an array of hostnames")
	for alias in aliases:
		if not alias is String or pattern.search(alias) == null:
			return {}, Err("settings file alias must be a hostname or IPv4 address")
	value["port"] = int(port)
	return value, null

static func endpoint(settings: Dictionary) -> String:
	return "http://" + str(settings.host) + ":" + str(settings.port)
