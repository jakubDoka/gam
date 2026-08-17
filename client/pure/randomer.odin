package pure_client

import "../../sim"
import "../../util/bit_arr"

Retained_Array :: struct($E: typeid) {
	slots:  []E,
	active: int,
}

retained_add :: proc(arr: ^Retained_Array($E)) -> (res: ^E) {
	if arr.active == len(arr.slots) do return

	res = &arr.slots[arr.active]
	arr.active += 1
	res^ = {}

	return
}

Retained_Iter_State :: struct {
	i:    int,
	keep: int,
}

retained_iter :: proc(
	retained: ^Retained_Array($E),
	state: ^Retained_Iter_State,
) -> (
	^E,
	bool,
) {
	if state.i >= retained.active {
		retained.active = state.keep
		return nil, false
	}

	p := &retained.slots[state.i]

	if p.age < p.lifetime {
		retained.slots[state.keep] = p^
		state.keep += 1
	}

	state.i += 1

	return p, true
}

retained_active :: proc(retained: ^Retained_Array($E)) -> []E {
	return retained.slots[:retained.active]
}

snap_to_tile :: proc(pos: sim.Vec) -> sim.Vec {
	return sim.map_pos_to_vec(sim.map_vec_to_pos(pos))
}

map_tile_center :: sim.map_pos_to_vec

fuzzy_rank_new_bitset :: proc(
	name: string,
	query: string,
) -> ^bit_arr.Bit_Set {
	matched_chars := new(bit_arr.Bit_Set, context.temp_allocator)
	matched_chars^ = bit_arr.init(len(name), context.temp_allocator)
	fuzzy_rank(name, query, matched_chars^)
	return matched_chars
}

fuzzy_rank :: proc(
	sample, pattern: string,
	highlighted: bit_arr.Bit_Set = {},
) -> int {
	MATCH :: 10
	BOUNDARY_BONUS :: 8
	MISMATCH :: -2
	SKIP_SAMPLE :: -1
	SKIP_PATTERN :: -5
	MAX_PATTERN :: 128

	m := len(pattern)
	if m == 0 do return 0
	if m > MAX_PATTERN do m = MAX_PATTERN

	prev: [MAX_PATTERN + 1]int
	curr: [MAX_PATTERN + 1]int

	char_occs: [256]u8
	for c in transmute([]u8)pattern {
		char_occs[c] += 1
	}

	for j in 1 ..= m {
		prev[j] = prev[j - 1] + SKIP_PATTERN
	}
	best := prev[m]

	for i in 1 ..= len(sample) {
		sc := to_lower(sample[i - 1])
		curr[0] = 0

		matched := false
		for j in 1 ..= m {
			pc := to_lower(pattern[j - 1])

			sub_step: int
			if sc == pc {
				if highlighted.bit_length != 0 && char_occs[sc] > 0 {
					matched = true
					bit_arr.set(highlighted, i - 1)
				}
				boundary := i == 1 || is_separator(sample[i - 2])
				sub_step = MATCH + (BOUNDARY_BONUS if boundary else 0)
			} else {
				sub_step = MISMATCH
			}

			diag := prev[j - 1] + sub_step
			skip_s := prev[j] + SKIP_SAMPLE
			skip_p := curr[j - 1] + SKIP_PATTERN
			curr[j] = max(diag, skip_s, skip_p)
		}

		char_occs[sc] -= u8(matched)

		prev = curr
	}

	return curr[m]

	to_lower :: proc(c: u8) -> u8 {
		return (c + 32) if (c >= 'A' && c <= 'Z') else c
	}

	is_separator :: proc(c: u8) -> bool {
		switch c {
		case ' ', '_', '-', '.', '/', '\\', ':':
			return true
		}
		return false
	}
}
