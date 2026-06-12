package packer

import "../bit_arr"
import "../nm"
import "core:log"
import "core:math"
import la "core:math/linalg"
import "core:sort"
import "core:testing"
import rl "vendor:raylib"

Sheet_Frame_Name :: nm.Name

Sheet_Frame :: struct {
	using rect: rl.Rectangle,
	name:       Sheet_Frame_Name,
}

Sheet :: struct {
	texture: rl.Texture2D,
	frames:  []Sheet_Frame,
}

sheet_destroy :: proc(sheet: Sheet) {
	rl.UnloadTexture(sheet.texture)
	delete(sheet.frames)
}

pack_into_sheet :: proc(
	textures: []rl.Image,
	allocator := context.allocator,
) -> Sheet {
	packed, dims := pack(textures, allocator)

	image := rl.GenImageColor(dims.x, dims.y, rl.BLANK)
	defer rl.UnloadImage(image)

	for frame, i in packed {
		img := textures[i]
		rl.ImageDraw(
			&image,
			img,
			{0, 0, f32(img.width), f32(img.height)},
			frame,
			rl.WHITE,
		)
	}

	return {rl.LoadTextureFromImage(image), packed}
}

pack :: proc(
	textures: []rl.Image,
	allocator := context.allocator,
) -> (
	[]Sheet_Frame,
	[2]i32,
) {
	context.allocator = context.temp_allocator
	textures := textures
	slots := make([]Sheet_Frame, len(textures), allocator)

	lcd :: proc(current: i32, other: i32) -> i32 {
		if current == 0 || other == 0 {
			return max(current, other)
		}

		current := current
		other := other
		for {
			if current > other {
				current %= other
				if current == 0 {
					return other
				}
			} else {
				other %= current
				if other == 0 {
					return current
				}
			}
		}
	}

	unit := [2]i32{0, 0}
	max_unit := [2]i32{0, 0}
	area: i32 = 0

	for texture, i in textures {
		unit.x = lcd(unit.x, texture.width)
		unit.y = lcd(unit.y, texture.height)
		max_unit.x = max(max_unit.x, texture.width)
		max_unit.y = max(max_unit.y, texture.height)
		area += texture.width * texture.height
		slots[i] = {
			width  = f32(texture.width),
			height = f32(texture.height),
		}
	}

	unit = la.max(unit, [2]i32{1, 1})

	size := i32(math.sqrt(f32(area)))
	dims := [2]i32{size, size}
	dims = la.max(dims, max_unit)

	dims = (dims + unit - 1) / unit * unit
	bitset_dims := dims / unit

	sorted := make([]i32, len(textures))
	for &s, i in sorted do s = i32(i)
	context.user_ptr = &textures
	sort.quick_sort_proc(sorted, proc(a, b: i32) -> int {
		textures := (^[]rl.Image)(context.user_ptr)
		area_a := textures[a].width * textures[a].height
		area_b := textures[b].width * textures[b].height
		return int(area_b - area_a)
	})

	retry: for {
		bitset := bit_arr.init(int(bitset_dims.x * bitset_dims.y))

		resolve: for i in sorted {
			texture := &textures[i]
			slot := &slots[i]

			width := texture.width / unit.x
			height := texture.height / unit.y

			for y in 0 ..= bitset_dims.y - height {
				search: for x in 0 ..= bitset_dims.x - width {

					for dy in 0 ..< height {
						for dx in 0 ..< width {
							taken := bit_arr.contains(
								bitset,
								(x + dx) + (y + dy) * bitset_dims.x,
							)
							if taken do continue search
						}
					}

					for dy in 0 ..< height {
						for dx in 0 ..< width {
							bit_arr.set(
								bitset,
								(x + dx) + (y + dy) * bitset_dims.x,
							)
						}
					}

					slot.x = f32(x * unit.x)
					slot.y = f32(y * unit.y)
					continue resolve
				}
			}

			bitset_dims += max_unit / unit

			continue retry
		}

		break
	}

	return slots, bitset_dims * unit
}

@(test)
test_pack :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator

	textures := [?]rl.Image {
		{width = 8, height = 8},
		{width = 8, height = 8},
		{width = 8, height = 8},
		{width = 8, height = 8},
		{width = 16, height = 16},
		{width = 16, height = 16},
		{width = 16, height = 16},
		{width = 32, height = 32},
		{width = 32, height = 32},
		{width = 32, height = 32},
		{width = 32, height = 32},
	}

	slots, _ := pack(textures[:])
	for slot in slots {
		log.debug(slot)
	}
}
