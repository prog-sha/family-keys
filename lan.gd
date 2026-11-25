# Enable access from an explicit IPv4 LAN range on this installation.
@import "./core"
@import "./settings" as Settings
@import "./server"

func main(args) -> int:
	if args.size() != 2:
		printerr("Usage: ./keys lan SERVER_IPV4 CLIENT_CIDR")
		return 1
	var ip: String = args[0]
	var network: String = args[1]
	var prefix := network.split("/")
	if not server.valid_fixed_ip(ip) or ip.contains(":") or prefix.size() != 2 or not server.valid_fixed_ip(prefix[0]) or prefix[0].contains(":") or not prefix[1].is_valid_int() or int(prefix[1]) not in range(1, 33):
		printerr("Specify an IPv4 address and an IPv4 CIDR of /1–/32")
		return 1
	var settings := Settings.load_settings()!
	var path := GD.cli.get_cwd().path_join("state/config.json")
	var cfg := GD.file.load_json(path)!
	cfg["bind"] = "0.0.0.0"
	cfg["port"] = settings.port
	cfg["public_host"] = ip if settings.host == "localhost" else settings.host
	cfg["hosts"] = ["localhost", "127.0.0.1", "[::1]", cfg.public_host, ip]
	cfg.hosts.append_array(settings.get("aliases", []))
	cfg["allowed_networks"] = [network]
	core.private_write(path, GD.data.to_json(cfg)!.to_utf8_buffer())!
	print("Start with ./keys serve; open http://", cfg.public_host, ":", cfg.port)
	return 0
