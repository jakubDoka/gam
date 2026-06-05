package nm

Name :: struct {
	bytes: [32]u8,
}

from_str :: proc(str: string) -> (name: Name, ok: bool) #optional_ok {
	copy(name.bytes[:], str)
	ok = len(str) <= size_of(Name)
	return
}

from_bytes :: proc(bytes: []u8) -> (name: Name, ok: bool) #optional_ok {
	copy(name.bytes[:], bytes)
	ok = len(bytes) <= size_of(Name)
	return
}

str :: proc(name: ^Name) -> string {
	return string(bytes(name))
}

bytes :: proc(name: ^Name) -> []u8 {
	return name.bytes[:ln(name^)]
}

ln :: proc(name: Name) -> int {
	ln := 0
	for ln < len(name.bytes) && name.bytes[ln] != 0 do ln += 1
	return ln
}
