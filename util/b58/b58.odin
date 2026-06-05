package b58

import "base:runtime"
import "core:math/rand"
import "core:slice"
import "core:testing"

ALPHABET :: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
@(rodata)
DECODE_TABLE := [?]i8 {
	0,
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	9,
	10,
	11,
	12,
	13,
	14,
	15,
	16,
	-1,
	17,
	18,
	19,
	20,
	21,
	-1,
	22,
	23,
	24,
	25,
	26,
	27,
	28,
	29,
	30,
	31,
	32,
	-1,
	-1,
	-1,
	-1,
	-1,
	-1,
	33,
	34,
	35,
	36,
	37,
	38,
	39,
	40,
	41,
	42,
	43,
	-1,
	44,
	45,
	46,
	47,
	48,
	49,
	50,
	51,
	52,
	53,
	54,
	55,
	56,
	57,
}
TABLE_START :: 49

encode :: proc(data: []u8) -> string {
	if len(data) == 0 {
		return ""
	}

	zeros := 0
	for b in data {
		if b != 0 {
			break
		}
		zeros += 1
	}

	// log(256)/log(58) ≈ 1.365
	size := (len(data) - zeros) * 138 / 100 + 1

	out := make([]u8, zeros + size, context.temp_allocator)
	length := zeros

	for b in data[zeros:] {
		carry := int(b)

		i := zeros
		for ; i < length; i += 1 {
			carry += int(out[i]) << 8
			out[i] = u8(carry % 58)
			carry /= 58
		}

		for carry > 0 {
			out[length] = u8(carry % 58)
			length += 1
			carry /= 58
		}
	}

	slice.reverse(out[zeros:length])

	alphabet := ALPHABET
	for i in 0 ..< length {
		out[i] = alphabet[out[i]]
	}

	return string(out[:length])
}

decode :: proc(encoded: string) -> ([]u8, bool) {
	encoded := transmute([]u8)encoded

	if len(encoded) == 0 {
		return nil, true
	}

	zeros := 0
	for c in encoded {
		if c != ALPHABET[0] {
			break
		}
		zeros += 1
	}

	// log(58)/log(256) ≈ 0.733
	size := (len(encoded) - zeros) * 733 / 1000 + 1

	out := make([]u8, zeros + size, context.temp_allocator)
	length := zeros

	for c in encoded[zeros:] {
		if c < TABLE_START || c - TABLE_START >= len(DECODE_TABLE) {
			return nil, false
		}

		val := DECODE_TABLE[c - TABLE_START]

		if val < 0 do return nil, false

		carry := int(val)

		for i := zeros; i < length; i += 1 {
			carry += int(out[i]) * 58
			out[i] = u8(carry & 0xff)
			carry >>= 8
		}

		for carry > 0 {
			out[length] = u8(carry & 0xff)
			length += 1
			carry >>= 8
		}
	}

	slice.zero(out[:zeros])
	slice.reverse(out[zeros:length])

	return out[:length], true
}

@(test)
test_sanity :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator

	input := transmute([]u8)string("hello world")
	encoded := encode(input)
	decoded, ok := decode(encoded)
	testing.expect(t, ok)
	testing.expect_value(t, string(input), string(decoded))
}

@(test)
test_fuzz_garbage :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	buf: [dynamic]u8

	for _ in 0 ..< 100000 {
		len := rand.int_range(0, 512)
		resize(&buf, len)
		ok := runtime.random_generator_read_bytes(
			context.random_generator,
			buf[:],
		)
		assert(ok)

		runtime.DEFAULT_TEMP_ALLOCATOR_TEMP_GUARD()
		decode(string(buf[:]))
	}
}

@(test)
test_fuzz_alphabet :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	buf: [dynamic]u8

	for _ in 0 ..< 10000 {
		len := rand.int_range(0, 128)
		resize(&buf, len)
		for &b in buf[:] {
			b = rand.choice(transmute([]u8)string(ALPHABET))
		}

		runtime.DEFAULT_TEMP_ALLOCATOR_TEMP_GUARD()
		decode(string(buf[:]))
	}
}

@(test)
test_fuzz_encdec :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	buf: [dynamic]u8

	for _ in 0 ..< 10000 {
		len := rand.int_range(0, 128)
		resize(&buf, len)
		ok := runtime.random_generator_read_bytes(
			context.random_generator,
			buf[:],
		)
		assert(ok)

		runtime.DEFAULT_TEMP_ALLOCATOR_TEMP_GUARD()
		encoded := encode(buf[:])
		decoded, oka := decode(encoded)
		testing.expect(t, oka)
		testing.expectf(
			t,
			string(buf[:]) == string(decoded),
			"\n%02x\n%02x",
			buf[:],
			decoded,
		)
	}
}
