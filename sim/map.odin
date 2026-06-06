package sim

import "base:intrinsics"
import rt "base:runtime"
import "core:math"
import "core:math/linalg"
import "core:math/rand"
import "core:mem"
import str "core:strings"
import "core:testing"

FILE_ALIGNMENT :: size_of(int)
MASK_SIZE :: size_of(int) * 8
TILE_SIZE :: 128
TILE_RECIPRO :: 1.0 / TILE_SIZE

Map_Pos :: [2]int

Ent_Team :: struct {
	color: Color,
}

Map_Ent :: struct {
	stat:   Ent_Stats_ID,
	team:   Ent_Team_ID,
	pos:    Map_Pos,
	parent: int,
}

Map_Charger :: struct {
	pos:    Map_Pos,
	radius: int,
}

Map_Sprite_Kind :: enum {
	Wall,
	Floor,
	Core,
}

Map :: struct {
	version:  int,
	width:    int,
	height:   int,
	sprites:  [Map_Sprite_Kind]Asset_ID,
	tiles:    []int,
	ents:     []Map_Ent,
	chargers: []Map_Charger,
	teams:    []Ent_Team,
}

map_is_initialized :: proc(mapa: ^Map) -> bool {
	return mapa.width * mapa.height != 0
}

map_text_to_bin :: proc(text: string, e: ^Encoder, core_stat: Ent_Stats_ID) {
	context.allocator = context.temp_allocator

	text := str.trim(text, "\n")

	mapa: Map

	mapa.width = str.index_byte(text, '\n')
	mapa.height = str.count(text, "\n") + 1
	charger_count := str.count(text, "a")

	core_count := 0
	for c in text do if '0' <= c && c <= '9' {
		core_count = max(core_count, int(c - '0') + 1)
	}

	tile_len := map_tile_storage_size(mapa.width, mapa.height)
	mapa.tiles = make([]int, tile_len)
	mapa.ents = make([]Map_Ent, core_count + 1)
	mapa.teams = make([]Ent_Team, core_count + 1)
	mapa.chargers = make([]Map_Charger, charger_count)

	y, charger_idx: int
	for row in str.split_iterator(&text, "\n") {
		x: int
		for c in row {
			switch c {
			case 'w':
				idx := y * mapa.width + x
				mapa.tiles[idx / MASK_SIZE] |= 1 << uint(idx % MASK_SIZE)
			case ' ':
			case '0' ..= '9':
				idx := Ent_Team_ID(c - '0') + 1
				mapa.ents[idx] = {
					pos  = {x, y},
					team = idx,
					stat = core_stat,
				}
				mapa.teams[idx] = {Color(rand.uint32() | 0x000000FF)}
			case 'a':
				mapa.chargers[charger_idx] = {
					pos    = {x, y},
					radius = 1,
				}
				charger_idx += 1
			}
			x += 1
		}
		y += 1
	}

	map_store(mapa, e)
}

map_tile_storage_size :: proc(width: int, height: int) -> int {
	tile_count := rawptr(uintptr(width * height))
	UNIT :: FILE_ALIGNMENT * 8
	return int(uintptr(mem.align_forward(tile_count, MASK_SIZE))) / MASK_SIZE
}

map_quad_size :: proc(mapa: ^Map) -> int {
	return(
		max(
			math.next_power_of_two(mapa.width),
			math.next_power_of_two(mapa.height),
		) *
		TILE_SIZE /
		2 \
	)
}

map_load :: proc(
	raw: []u8,
	max_ents := MAX_ENTS_PER_GAME,
) -> (
	mapa: Map,
	ok: bool,
) {
	assert(mem.is_aligned(raw_data(raw), FILE_ALIGNMENT))

	header_populate(mapa, raw) or_return

	if len(mapa.teams) == 0 do return
	if len(mapa.ents) == 0 do return
	if len(mapa.ents) > max_ents do return

	for e in mapa.ents {
		if e.parent < 0 do return
		if e.parent >= len(mapa.ents) do return
	}

	tile_count, tcov := intrinsics.overflow_mul(mapa.width, mapa.height)
	if tcov do return

	if tile_count > len(mapa.tiles) * MASK_SIZE do return

	ok = true
	return
}

map_store :: proc(mapa: Map, e: ^Encoder) -> (ok: bool) {
	header_serialize(mapa, e) or_return
	return true
}

map_vec_to_pos :: proc(v: Vec) -> Map_Pos {
	return {int(v.x * TILE_RECIPRO), int(v.y * TILE_RECIPRO)}
}

map_pos_to_vec :: proc(pos: Map_Pos) -> Vec {
	return {
		f32(pos.x * TILE_SIZE + TILE_SIZE / 2),
		f32(pos.y * TILE_SIZE + TILE_SIZE / 2),
	}
}

map_tile_is_solid :: proc(mapa: ^Map, pos: Map_Pos) -> bool {
	if pos.x < 0 || pos.x >= mapa.width do return true
	if pos.y < 0 || pos.y >= mapa.height do return true

	idx := pos.y * mapa.width + pos.x

	return mapa.tiles[idx / MASK_SIZE] & (1 << uint(idx % MASK_SIZE)) != 0
}

map_tile_set :: proc(mapa: ^Map, pos: Map_Pos, value: bool) {
	if pos.x < 0 || pos.x >= mapa.width do return
	if pos.y < 0 || pos.y >= mapa.height do return

	idx := pos.y * mapa.width + pos.x

	if value {
		mapa.tiles[idx / MASK_SIZE] |= 1 << uint(idx % MASK_SIZE)
	} else {
		mapa.tiles[idx / MASK_SIZE] &= ~(1 << uint(idx % MASK_SIZE))
	}
}

next_pos_along_normal :: proc(pos: Vec, normal: Map_Pos) -> Vec {
	return {
		math.nextafter(pos.x, math.inf_f32(normal.x)),
		math.nextafter(pos.y, math.inf_f32(normal.y)),
	}
}

map_clamp_to_tile :: proc(pos: Vec, tile: Map_Pos) -> Vec {
	tile_min := Vec{f32(tile.x * TILE_SIZE), f32(tile.y * TILE_SIZE)}
	tile_max := next_pos_along_normal(tile_min + TILE_SIZE, {-1, -1})
	return linalg.clamp(pos, tile_min, tile_max)
}

map_wall_collision :: proc(
	mapa: ^Map,
	pos: Vec,
	vel: Vec,
	log := false,
) -> (
	t: f32,
	normal: Vec,
	new_tile: Map_Pos,
) {
	normal = {1, 1}

	cursor := map_vec_to_pos(pos)

	inv_vx := 1.0 / vel.x
	inv_vy := 1.0 / vel.y

	step_x := int(math.sign(vel.x))
	step_y := int(math.sign(vel.y))

	tile_min := linalg.floor(pos * TILE_RECIPRO) * TILE_SIZE
	tile_max := tile_min + TILE_SIZE

	next_boundary_x := tile_max.x if step_x >= 0 else tile_min.x
	next_boundary_y := tile_max.y if step_y >= 0 else tile_min.y

	tMaxX := (next_boundary_x - pos.x) * inv_vx
	tMaxY := (next_boundary_y - pos.y) * inv_vy

	tDeltaX := TILE_SIZE * math.abs(inv_vx)
	tDeltaY := TILE_SIZE * math.abs(inv_vy)

	new_tile = cursor

	for !map_tile_is_solid(mapa, cursor) && t < 1 {
		new_tile = cursor

		if tMaxX < tMaxY {
			t = tMaxX
			tMaxX += tDeltaX
			cursor.x += step_x
			normal = {-1, 1}
		} else {
			t = tMaxY
			tMaxY += tDeltaY
			cursor.y += step_y
			normal = {1, -1}
		}
	}

	t = min(t, 1)

	return
}

map_tile_collide :: proc(
	ents: ^Map,
	tile: Map_Pos,
	pos: Vec,
	radius: f32,
) -> (
	normal: Vec,
	contact_point: Vec,
) {
	origin_tile := map_vec_to_pos(pos)

	x, y := tile.x, tile.y

	tile_min := Vec{f32(x), f32(y)} * TILE_SIZE
	tile_max := tile_min + TILE_SIZE

	corners := [?]Vec {
		tile_min,
		{tile_max.x, tile_min.y},
		tile_max,
		{tile_min.x, tile_max.y},
	}

	out := true

	if map_tile_is_solid(ents, {x, y}) {
		origin_tile_pos := map_pos_to_vec({x, y})

		out = origin_tile.x != x && origin_tile.y != y

		if !out {
			rel_pos := pos - origin_tile_pos
			if abs(rel_pos.x) > abs(rel_pos.y) {
				normal = {math.sign(rel_pos.x), 0}
				if rel_pos.x > 0 {
					contact_point = {tile_max.x, pos.y}
				} else {
					contact_point = {tile_min.x, pos.y}
				}
			} else {
				normal = {0, math.sign(rel_pos.y)}
				if rel_pos.y > 0 {
					contact_point = {pos.x, tile_max.y}
				} else {
					contact_point = {pos.x, tile_min.y}
				}
			}
		}

		if out {
			min_dist := math.inf_f32(1)
			min_idx := 0

			for c, i in corners {
				dist := linalg.length2(pos - c)
				if dist < min_dist {
					min_dist = dist
					min_idx = i
				}
			}

			out &= min_dist > radius * radius

			if !out {
				normal = linalg.normalize0(pos - corners[min_idx])
				contact_point = corners[min_idx]
			}
		}
	}

	return
}

map_tile_find_empty :: proc(ents: ^Ents, origin: Map_Pos) -> Map_Pos {
	dirs := [?]Map_Pos{{1, -1}, {1, 1}, {-1, 1}, {-1, -1}}

	search: for radius in 1 ..< 100 {
		cursor := Map_Pos{origin.x - radius, origin.y}
		for d in dirs {
			for _ in 0 ..< radius {
				if !map_tile_is_solid(ents, cursor) {
					return cursor
				}
				cursor += d
			}
		}
		assert(cursor == {origin.x - radius, origin.y})
	}

	return {}
}

@(test)
test_map_wall_collision :: proc(t: ^testing.T) {
	mapa: Map
	mapa.width = 4
	mapa.height = 4
	mapa.tiles = []int{0b1000_0000_1000_1111}

	tm: f32
	normal: Vec
	new_tile: Map_Pos

	close :: proc(a, b: f32) -> bool {
		return abs(a - b) < 1e-4
	}

	tm, normal, new_tile = map_wall_collision(
		&mapa,
		map_pos_to_vec({0, 1}),
		{0, -TILE_SIZE},
	)
	testing.expectf(t, close(tm, 0.5), "%v", tm)
	testing.expectf(t, normal == {1, -1}, "%v", normal)

	tm, normal, new_tile = map_wall_collision(
		&mapa,
		map_pos_to_vec({0, 2}),
		{0, -TILE_SIZE},
	)
	testing.expectf(t, tm == 1.0, "%v", tm)

	tm, normal, new_tile = map_wall_collision(&mapa, {0, TILE_SIZE}, {0, 0})
	testing.expectf(t, tm == 1.0, "%v", tm)

	tm, normal, new_tile = map_wall_collision(
		&mapa,
		{0, TILE_SIZE},
		{TILE_SIZE, 0},
	)
	testing.expectf(t, tm == 1.0, "%v", tm)

	tm, normal, new_tile = map_wall_collision(&mapa, {0, 0}, {0, 0})
	testing.expectf(t, tm == 0.0, "%v", tm)
	testing.expectf(t, normal == {1, 1}, "%v", normal)

	tm, normal, new_tile = map_wall_collision(
		&mapa,
		map_pos_to_vec({2, 1}),
		{TILE_SIZE, -TILE_SIZE},
	)
	testing.expectf(t, close(tm, 0.5), "%v", tm)
	testing.expectf(t, normal == {1, -1}, "%v", normal)

	tm, normal, new_tile = map_wall_collision(
		&mapa,
		{TILE_SIZE * 3 + TILE_SIZE / 2, TILE_SIZE * 3},
		{0, -TILE_SIZE / 2},
	)
	testing.expectf(t, tm == 0, "%v", tm)

	tm, normal, new_tile = map_wall_collision(
		&mapa,
		map_pos_to_vec({2, 2}),
		{TILE_SIZE, -TILE_SIZE},
	)
	testing.expectf(t, close(tm, 0.5), "%v", tm)
	testing.expectf(t, normal == {-1, 1}, "%v", normal)

	tm, normal, new_tile = map_wall_collision(
		&mapa,
		map_pos_to_vec({2, 2}),
		{TILE_SIZE, -TILE_SIZE} / 2,
	)
	testing.expectf(t, tm == 1, "%v", tm)
	testing.expectf(t, normal == {1, -1}, "%v", normal)

	flaky_pos: Vec = {TILE_SIZE * 3, TILE_SIZE}
	flaky_vel: Vec = {TILE_SIZE, -TILE_SIZE}

	flaky_pos = next_pos_along_normal(flaky_pos, {-1, 1})
	tm, normal, new_tile = map_wall_collision(&mapa, flaky_pos, flaky_vel)
	testing.expectf(t, close(tm, 0), "%v", tm)
	testing.expectf(t, normal == {1, -1}, "%v %v", normal, tm)

	flaky_pos += flaky_vel * tm
	flaky_pos = map_clamp_to_tile(flaky_pos, new_tile)
	flaky_vel *= normal

	tm, normal, new_tile = map_wall_collision(&mapa, flaky_pos, flaky_vel)
	testing.expectf(t, close(tm, 0), "%v", tm)
	testing.expectf(t, normal == {-1, 1}, "%v", normal)

	flaky_pos += flaky_vel * tm
	flaky_vel *= normal
}
