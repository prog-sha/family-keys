# Lightweight quirc decoder port for flat QR screenshots, without external tools.
# quirc Copyright (C) 2010-2012 Daniel Beer; see licenses/quirc.txt (ISC).
@import "./qr_tables"

const ALPHANUMERIC := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
var pixels: PackedByteArray
var width: int
var height: int
var threshold: int
var exp_table := PackedInt32Array()
var log_table := PackedInt32Array()

func read(gray: PackedByteArray, w: int, h: int) -> String:
	if w < 21 or h < 21 or w > 1400 or h > 1400 or w * h != gray.size():
		return ""
	pixels = gray
	width = w
	height = h
	threshold = otsu()
	var finders := locate()
	if finders.size() < 3:
		return ""
	init_field()
	# A QR has three right-angle finder centers. Limit trials to the best-supported hits.
	for origin in finders:
		for right in finders:
			if right == origin:
				continue
			var x_axis: Vector2 = right.center - origin.center
			for down in finders:
				if down == origin or down == right:
					continue
				var y_axis: Vector2 = down.center - origin.center
				var x_length := x_axis.length()
				var y_length := y_axis.length()
				if minf(x_length, y_length) < 14.0 or absf(x_axis.dot(y_axis)) > x_length * y_length * 0.19 or x_axis.cross(y_axis) <= 0:
					continue
				if absf(x_length - y_length) > maxf(x_length, y_length) * 0.20:
					continue
				var pitch: float = (origin.pitch + right.pitch + down.pitch) / 3.0
				var guess := roundi(((x_length + y_length) / (2.0 * pitch) - 10.0) / 4.0)
				for delta in [0, -1, 1]:
					var version: int = guess + delta
					if version not in range(1, 41):
						continue
					var size := 17 + version * 4
					var grid := sample(origin.center, x_axis / float(size - 7), y_axis / float(size - 7), size)
					if grid.is_empty():
						continue
					var decoded := decode(grid, size, version)
					if not decoded.is_empty():
						return decoded
	return ""

# Otsu thresholding, adapted from quirc's grayscale image identification.
func otsu() -> int:
	var histogram := PackedInt32Array()
	histogram.resize(256)
	var total := 0
	for i in range(0, pixels.size(), 2):
		var value := pixels[i]
		histogram[value] += 1
		total += value
	var count := (pixels.size() + 1) >> 1
	var below := 0
	var sum := 0
	var level := 127
	var best := 0.0
	for i in 255:
		below += histogram[i]
		sum += histogram[i] * i
		if below == 0 or below == count:
			continue
		var difference := float(sum) / below - float(total - sum) / (count - below)
		var variance := float(below) * (count - below) * difference * difference
		if variance > best:
			best = variance
			level = i
	return level

func dark(x: int, y: int) -> bool:
	return pixels[y * width + x] <= threshold

func finder_pitch(runs: Array) -> float:
	var pitch: float = (runs[0] + runs[1] + runs[2] + runs[3] + runs[4]) / 7.0
	var tolerance := pitch * 0.65
	if pitch < 0.85 or absf(runs[2] - 3.0 * pitch) > tolerance * 2.0:
		return 0.0
	for i in [0, 1, 3, 4]:
		if absf(runs[i] - pitch) > tolerance:
			return 0.0
	return pitch

func vertical_finder(x: int, y: int, pitch: float) -> Vector2:
	if not dark(x, y):
		return Vector2.ZERO
	var runs := [0, 0, 1, 0, 0]
	var limit := ceili(pitch * 6)
	var top := y
	var bottom := y
	for direction in [-1, 1]:
		var part := 2
		var position: int = y + direction
		while position >= 0 and position < height:
			if dark(x, position) != (part % 2 == 0):
				if part == 2:
					if direction < 0:
						top = position + 1
					else:
						bottom = position - 1
				part += direction
				if part < 0 or part > 4:
					break
			runs[part] += 1
			if runs[part] > limit:
				return Vector2.ZERO
			position += direction
	var confirmed := finder_pitch(runs)
	if confirmed <= 0.0 or absf(confirmed - pitch) > pitch * 0.45:
		return Vector2.ZERO
	return Vector2((top + bottom + 1) / 2.0, confirmed)

func locate() -> Array:
	var candidates: Array = []
	for y in range(0, height, 2 if height > 800 else 1):
		var runs := [0, 0, 0, 0, 0]
		var last := dark(0, y)
		var count := 0
		for x in range(width + 1):
			var bit := dark(x, y) if x < width else not last
			if bit == last:
				count += 1
				continue
			runs.pop_front()
			runs.append(count)
			if last and runs[0] > 0:
				var pitch := finder_pitch(runs)
				if pitch > 0:
					var mid: float = x - runs[4] - runs[3] - runs[2] * 0.5
					var vertical := vertical_finder(floori(mid), y, pitch)
					if vertical.y > 0.0:
						var center := Vector2(mid, vertical.x)
						var found := false
						for candidate in candidates:
							if center.distance_to(candidate.center) <= pitch * 1.4:
								candidate.count += 1
								candidate.center = candidate.center.lerp(center, 1.0 / candidate.count)
								candidate.pitch = lerpf(candidate.pitch, (pitch + vertical.y) / 2.0, 1.0 / candidate.count)
								found = true
								break
						if not found and candidates.size() < 150:
							candidates.append({"center": center, "pitch": (pitch + vertical.y) / 2.0, "count": 1})
			count = 1
			last = bit
	candidates.sort_custom(func(a, b): return a.count > b.count)
	return candidates.slice(0, 8)

func sample(origin: Vector2, dx: Vector2, dy: Vector2, size: int) -> PackedByteArray:
	var grid := PackedByteArray()
	grid.resize(size * size)
	for y in size:
		var row := origin + dy * (y - 3) - dx * 3
		for x in size:
			var point := row + dx * x
			if point.x < 0.0 or point.y < 0.0 or point.x >= width or point.y >= height:
				return PackedByteArray()
			grid[y * size + x] = int(dark(floori(point.x), floori(point.y)))
	return grid

func format_values(grid: PackedByteArray, size: int) -> Array:
	var xs := [8,8,8,8,8,8,8,8,7,5,4,3,2,1,0]
	var ys := [0,1,2,3,4,5,7,8,8,8,8,8,8,8,8]
	var first := 0
	var second := 0
	for i in 15:
		first |= grid[ys[i] * size + xs[i]] << i
	for i in 7:
		second = (second << 1) | grid[(size - 1 - i) * size + 8]
	for i in 8:
		second = (second << 1) | grid[8 * size + size - 8 + i]
	var results: Array = []
	for bits in [first, second]:
		for value in 32:
			var remainder := value << 10
			for bit in range(14, 9, -1):
				if remainder & (1 << bit):
					remainder ^= 0x537 << (bit - 10)
			var difference := bits ^ (((value << 10) | remainder) ^ 0x5412)
			var errors := 0
			while difference:
				errors += 1
				difference &= difference - 1
			if errors <= 3 and value not in results:
				results.append(value)
	return results

func mask_bit(mask: int, x: int, y: int) -> int:
	var product := x * y
	match mask:
		0: return int((x + y) % 2 == 0)
		1: return int(y % 2 == 0)
		2: return int(x % 3 == 0)
		3: return int((x + y) % 3 == 0)
		4: return int(((y >> 1) + floori(x / 3.0)) % 2 == 0)
		5: return int(product % 2 + product % 3 == 0)
		6: return int((product % 2 + product % 3) % 2 == 0)
		_: return int((product % 3 + (x + y) % 2) % 2 == 0)

func reserved(version: int, size: int, x: int, y: int, alignment: Array) -> bool:
	if (x < 9 and (y < 9 or y >= size - 8)) or (y < 9 and x >= size - 8) or x == 6 or y == 6:
		return true
	if version >= 7 and ((y < 6 and x >= size - 11) or (x < 6 and y >= size - 11)):
		return true
	var xi := -1
	var yi := -1
	for i in alignment.size():
		if absi(x - alignment[i]) < 3:
			xi = i
		if absi(y - alignment[i]) < 3:
			yi = i
	var last := alignment.size() - 1
	return xi >= 0 and yi >= 0 and ((xi > 0 and xi < last) or (yi > 0 and yi < last) or (xi == last and yi == last))

func decode(grid: PackedByteArray, size: int, version: int) -> String:
	var params: Array = qr_tables.VERSIONS[version - 1]
	for format in format_values(grid, size):
		var raw := PackedByteArray()
		raw.resize(params[0])
		var pos := 0
		var x := size - 1
		var up := true
		while x > 0:
			if x == 6:
				x -= 1
			for row in size:
				var y := size - row - 1 if up else row
				for col in [x, x - 1]:
					if not reserved(version, size, col, y, params[1]) and pos < raw.size() * 8:
						raw[pos >> 3] |= (grid[y * size + col] ^ mask_bit(format & 7, col, y)) << (7 - (pos & 7))
						pos += 1
			x -= 2
			up = not up
		if pos != raw.size() * 8:
			continue
		var payload := join_blocks(raw, params[2][format >> 3])
		if not payload.is_empty():
			var result := parse_payload(payload, version)
			if not result.is_empty():
				return result
	return ""

func join_blocks(raw: PackedByteArray, spec: Array) -> PackedByteArray:
	var short_size: int = spec[0]
	var data_size: int = spec[1]
	var short_count: int = spec[2]
	var long_count := floori(float(raw.size() - short_size * short_count) / (short_size + 1))
	var count := short_count + long_count
	var ecc_start := data_size * count + long_count
	var ecc_bytes := short_size - data_size
	var output := PackedByteArray()
	for block in count:
		var words := PackedByteArray()
		for i in data_size:
			words.append(raw[i * count + block])
		if block >= short_count:
			words.append(raw[data_size * count + block - short_count])
		var length := words.size()
		for i in ecc_bytes:
			words.append(raw[ecc_start + i * count + block])
		if not correct(words, ecc_bytes):
			return PackedByteArray()
		output.append_array(words.slice(0, length))
	return output

func init_field() -> void:
	exp_table.resize(255)
	log_table.resize(256)
	var value := 1
	for i in 255:
		exp_table[i] = value
		log_table[value] = i
		value <<= 1
		if value & 256:
			value ^= 0x11d

func mul(a: int, b: int) -> int:
	return exp_table[(log_table[a] + log_table[b]) % 255] if a != 0 and b != 0 else 0

func div_field(a: int, b: int) -> int:
	return exp_table[(log_table[a] - log_table[b] + 255) % 255] if a != 0 else 0

func evaluate(poly: PackedByteArray, at: int) -> int:
	var result := 0
	for i in range(poly.size() - 1, -1, -1):
		result = mul(result, at) ^ poly[i]
	return result

func syndromes(words: PackedByteArray, count: int) -> PackedByteArray:
	var result := PackedByteArray()
	for i in count:
		var value := 0
		for word in words:
			value = mul(value, exp_table[i]) ^ word
		result.append(value)
	return result

# Berlekamp–Massey and Forney error correction, adapted from quirc.
func correct(words: PackedByteArray, count: int) -> bool:
	var s := syndromes(words, count)
	if s.count(0) == count:
		return true
	var sigma := PackedByteArray()
	sigma.resize(count + 1)
	sigma[0] = 1
	var previous := sigma.duplicate()
	var degree := 0
	var distance := 1
	var factor := 1
	for i in count:
		var d := int(s[i])
		for j in range(1, degree + 1):
			d ^= mul(sigma[j], s[i - j])
		if d == 0:
			distance += 1
			continue
		var copy := sigma.duplicate()
		for j in range(sigma.size() - distance):
			sigma[j + distance] ^= mul(previous[j], div_field(d, factor))
		if degree * 2 <= i:
			degree = i + 1 - degree
			previous = copy
			factor = d
			distance = 1
		else:
			distance += 1
	if degree * 2 > count:
		return false
	var derivative := PackedByteArray()
	derivative.resize(count)
	for i in range(0, count, 2):
		derivative[i] = sigma[i + 1]
	var omega := PackedByteArray()
	omega.resize(count - 1)
	for i in range(degree + 1):
		for j in range(omega.size() - i):
			omega[i + j] ^= mul(sigma[i], s[j + 1])
	for i in words.size():
		var inverse := exp_table[(255 - i) % 255]
		if evaluate(sigma, inverse) == 0:
			var scale := evaluate(derivative, inverse)
			if scale == 0:
				return false
			words[words.size() - 1 - i] ^= div_field(evaluate(omega, inverse), scale)
	return syndromes(words, count).count(0) == count

class Bits:
	var data: PackedByteArray
	var offset := 0
	func take(length: int) -> int:
		if offset + length > data.size() * 8:
			return -1
		var value := 0
		for i in length:
			value = (value << 1) | ((data[offset >> 3] >> (7 - (offset & 7))) & 1)
			offset += 1
		return value

func parse_payload(data: PackedByteArray, version: int) -> String:
	var stream := Bits.new()
	stream.data = data
	var output := PackedByteArray()
	while stream.offset + 4 <= data.size() * 8:
		var mode := stream.take(4)
		if mode == 0:
			break
		if mode == 7:
			var eci := stream.take(8)
			if eci < 0 or (eci & 128) != 0 or eci not in [3, 26]:
				return ""
			continue
		var group := 0 if version < 10 else (1 if version < 27 else 2)
		var widths := {1:[10,12,14],2:[9,11,13],4:[8,16,16]}
		if not widths.has(mode):
			return ""
		var count := stream.take(widths[mode][group])
		if count < 0 or output.size() + count > 4096:
			return ""
		match mode:
			4:
				for i in count:
					var byte := stream.take(8)
					if byte < 0: return ""
					output.append(byte)
			1, 2:
				var chunk := 3 if mode == 1 else 2
				while count > 0:
					var length := mini(count, chunk)
					var bits := [0,4,7,10][length] if mode == 1 else [0,6,11][length]
					var value := stream.take(bits)
					if value < 0:
						return ""
					var radix := 10 if mode == 1 else 45
					var text := ""
					for i in length:
						var digit := value % radix
						text = (str(digit) if mode == 1 else ALPHANUMERIC[digit]) + text
						value = floori(float(value) / radix)
					if value != 0: return ""
					output.append_array(text.to_ascii_buffer())
					count -= length
	var text := output.get_string_from_utf8()
	return text if text.to_utf8_buffer() == output else ""
