# Create local encrypted storage and shared LAN access.
const Core = preload("core.gd")
const Auth = preload("auth.gd")

func main(args) -> int:
	var settings := preload("settings.gd").load_settings()!
	var root := GD.cli.get_cwd().path_join("state")
	if not args.is_empty():
		root = str(args[0])
	if not root.is_absolute_path():
		printerr("Use an absolute state directory")
		return 1
	for file in ["config.json", "master.key", "auth.json"]:
		if GD.file.exists(root.path_join(file)):
			printerr("Already initialized; open the device settings to make changes")
			return 1
	var password := OS.read_string_from_stdin(4097).trim_suffix("\n").trim_suffix("\r")
	if password.length() < 12 or password.length() > 1024 or password.contains("\n") or password.contains("\r"):
		printerr("Use a single-line password of 12–1024 characters")
		return 1
	GD.file.ensure_dir(root)!
	if FileAccess.set_unix_permissions(root, 448) != OK:
		printerr("Could not protect the state directory")
		return 1
	var cfg := {"bind": "127.0.0.1", "port": settings.port, "public_host": settings.host, "hosts": ["localhost", "127.0.0.1", "[::1]", settings.host], "allowed_networks": [], "devices": [{"ip": "127.0.0.1", "name": "This device"}, {"ip": "::1", "name": "This device IPv6"}]}
	cfg.hosts.append_array(settings.get("aliases", []))
	initialize(root, cfg, password)!
	print("Initialized. Start with ./keys serve and open ", preload("settings.gd").endpoint(settings))
	return 0

func initialize(root: String, cfg: Dictionary, password: String) -> Err:
	var master_path := root.path_join("master.key")
	var auth_path := root.path_join("auth.json")
	Core.private_write(master_path, Crypto.new().generate_random_bytes(64), false)?
	errdefer:
		var _cleanup_err := GD.file.remove(master_path)
	Auth.initialize(root, password)?
	errdefer:
		var _cleanup_err := GD.file.remove(auth_path)
	return Core.private_write(root.path_join("config.json"), GD.data.var_to_json(cfg)?.to_utf8_buffer(), false)
