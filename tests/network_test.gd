# Check exact IPv4 subnet boundaries and reject lookalike addresses.
const Server = preload("../server.gd")
func main() -> int:
	var server := Server.new()
	for address in ["192.0.2.1", "192.0.2.132", "192.0.2.254"]:
		assert(server.address_allowed(address, "192.0.2.0/24"))
	for address in ["198.51.100.1", "192.0.3.1", "192.0.2.132.evil", "192.0.2.999", "::1"]:
		assert(not server.address_allowed(address, "192.0.2.0/24"))
	print("PASS IPv4 subnet boundaries")
	return 0
