package bit_arr

import "base:intrinsics"
import "core:testing"
MASK_SIZE :: size_of(uint) * 8

Bit_Set :: struct {
	masks:      [^]int,
	bit_length: int,
}

mask_len :: proc(bit_length: int) -> int {
	return (bit_length + MASK_SIZE - 1) / MASK_SIZE
}

init :: proc(
	#any_int bit_length: int,
	allocator := context.allocator,
	loc := #caller_location,
) -> Bit_Set {
	return {
		raw_data(make([]int, mask_len(bit_length), allocator, loc = loc)),
		bit_length,
	}
}

init_from_masks :: proc(masks: []int) -> Bit_Set {
	return {raw_data(masks), len(masks) * MASK_SIZE}
}

is_empty :: proc(bset: Bit_Set) -> bool {
	for m in bset.masks[:mask_len(bset.bit_length)] {
		if m != 0 do return false
	}

	return true
}

destroy :: proc(bset: Bit_Set) {
	delete(bset.masks[:mask_len(bset.bit_length)])
}

set :: proc(bset: Bit_Set, #any_int index: int, value := true) {
	assert(index < bset.bit_length)
	if value {
		bset.masks[index / MASK_SIZE] |= 1 << uint(index % MASK_SIZE)
	} else {
		bset.masks[index / MASK_SIZE] &= ~(1 << uint(index % MASK_SIZE))
	}
}

set_unbounded :: proc(bset: Bit_Set, index: int, value := true) {
	if index < 0 || index >= bset.bit_length do return
	set(bset, index, value)
}

contains_unbounded :: proc(bset: Bit_Set, #any_int index: int) -> bool {
	if index < 0 || index >= bset.bit_length do return false
	return contains(bset, index)
}

contains :: proc(bset: Bit_Set, #any_int index: int) -> bool {
	assert(index < bset.bit_length)
	return bset.masks[index / MASK_SIZE] & (1 << uint(index % MASK_SIZE)) != 0
}

pop_count :: proc(bset: Bit_Set) -> (count: int) {
	for mask in bset.masks[:mask_len(bset.bit_length)] {
		count += intrinsics.count_ones(mask)
	}
	return
}

Iter :: struct {
	i:            int,
	current_mask: int,
	set:          Bit_Set,
}

iter :: proc(bset: Bit_Set) -> Iter {
	return {set = bset}
}

iter_next :: proc(it: ^Iter) -> (int, bool) {
	len := mask_len(it.set.bit_length)

	for it.current_mask == 0 {
		if it.i >= len do return -1, false
		it.current_mask = it.set.masks[it.i]
		it.i += 1
	}

	pos :=
		(it.i - 1) * MASK_SIZE +
		intrinsics.count_trailing_zeros(it.current_mask)
	it.current_mask &= it.current_mask - 1

	return pos, true
}

@(test)
iter_sanity :: proc(t: ^testing.T) {
	masks: [2]int
	st := init_from_masks(masks[:])

	set(st, 65)
	set(st, 125)

	it := iter(st)
	testing.expect_value(t, iter_next(&it) or_else panic(""), 65)
	testing.expect_value(t, iter_next(&it) or_else panic(""), 125)
	_, ok := iter_next(&it)
	testing.expect(t, !ok)
}
