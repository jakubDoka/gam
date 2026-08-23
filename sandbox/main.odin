package sandbox

import "core:fmt"
import "core:math"
import "core:mem"
import "core:simd"
import "core:testing"
import "core:time"
import rl "vendor:raylib"

WINDOW_WIDTH :: 1440
WINDOW_HEIGHT :: 900
PANEL_WIDTH :: 330
MAX_LINES :: 100_000
SAMPLE_COUNT :: 120
SIMD_LANES :: 8

Entity :: struct {
	x, y:   f32,
	vx, vy: f32,
	radius: f32,
}

Pair :: struct {
	a, b: int,
}

Search_Entity :: struct {
	x, y:   f32,
	radius: f32,
	index:  int,
}

Hybrid_Sector :: struct {
	entities: #soa[]Search_Entity,
	len:      int,
}

Strategy :: enum {
	Spatial_Hash,
	SIMD_All_Pairs,
	Hybrid,
}

World :: struct {
	entities:         #soa[dynamic]Entity,
	collided:         [dynamic]bool,
	pairs:            [dynamic]Pair,
	heads:            [dynamic]int,
	next:             [dynamic]int,
	strategy:         Strategy,
	entity_count:     int,
	map_size:         f32,
	cell_size:        f32,
	hybrid_cell_size: f32,
	seed:             u64,
	paused:           bool,
	collision_count:  int,
	pair_tests:       u64,
	search_us:        f64,
	samples:          [SAMPLE_COUNT]f64,
	sample_cursor:    int,
	samples_filled:   int,
}

random_u32 :: proc(state: ^u64) -> u32 {
	x := state^
	x = x ~ (x << 13)
	x = x ~ (x >> 7)
	x = x ~ (x << 17)
	state^ = x
	return u32(x >> 32)
}

random_f32 :: proc(state: ^u64, lo, hi: f32) -> f32 {
	t := f32(random_u32(state)) / f32(0xffffffff)
	return lo + (hi - lo) * t
}

respawn :: proc(world: ^World) {
	clear(&world.entities)
	clear(&world.collided)
	clear(&world.pairs)
	resize(&world.entities, world.entity_count)
	resize(&world.collided, world.entity_count)

	rng := world.seed
	for i in 0 ..< world.entity_count {
		radius := random_f32(&rng, 3.5, 6.5)
		angle := random_f32(&rng, 0, 2 * math.PI)
		speed := random_f32(&rng, 20, 62)
		world.entities.x[i] = random_f32(&rng, radius, world.map_size - radius)
		world.entities.y[i] = random_f32(&rng, radius, world.map_size - radius)
		world.entities.vx[i] = math.cos(angle) * speed
		world.entities.vy[i] = math.sin(angle) * speed
		world.entities.radius[i] = radius
	}

	world.samples = {}
	world.sample_cursor = 0
	world.samples_filled = 0
}

move_entities :: proc(world: ^World, dt: f32) {
	for i in 0 ..< len(world.entities) {
		x := world.entities.x[i] + world.entities.vx[i] * dt
		y := world.entities.y[i] + world.entities.vy[i] * dt
		r := world.entities.radius[i]
		if x < r {
			x = r
			world.entities.vx[i] = -world.entities.vx[i]
		} else if x > world.map_size - r {
			x = world.map_size - r
			world.entities.vx[i] = -world.entities.vx[i]
		}
		if y < r {
			y = r
			world.entities.vy[i] = -world.entities.vy[i]
		} else if y > world.map_size - r {
			y = world.map_size - r
			world.entities.vy[i] = -world.entities.vy[i]
		}
		world.entities.x[i] = x
		world.entities.y[i] = y
	}
}

record_collision :: #force_inline proc(world: ^World, a, b: int) {
	assert(a != b)
	world.collision_count += 1
	world.collided[a] = true
	world.collided[b] = true
	if len(world.pairs) < MAX_LINES {
		append(&world.pairs, Pair{a, b})
	}
}

collide_spatial :: proc(world: ^World) {
	columns := int(math.ceil(world.map_size / world.cell_size))
	cell_count := columns * columns
	resize(&world.heads, cell_count)
	resize(&world.next, len(world.entities))
	for &head in world.heads do head = -1

	for i in 0 ..< len(world.entities) {
		cx := int(world.entities.x[i] / world.cell_size)
		cy := int(world.entities.y[i] / world.cell_size)
		cx = clamp(cx, 0, columns - 1)
		cy = clamp(cy, 0, columns - 1)
		cell := cy * columns + cx
		world.next[i] = world.heads[cell]
		world.heads[cell] = i
	}

	for i in 0 ..< len(world.entities) {
		cx := int(world.entities.x[i] / world.cell_size)
		cy := int(world.entities.y[i] / world.cell_size)
		for oy in -1 ..= 1 {
			ny := cy + oy
			if ny < 0 || ny >= columns do continue
			for ox in -1 ..= 1 {
				nx := cx + ox
				if nx < 0 || nx >= columns do continue
				j := world.heads[ny * columns + nx]
				for j >= 0 {
					if j > i {
						world.pair_tests += 1
						dx := world.entities.x[j] - world.entities.x[i]
						dy := world.entities.y[j] - world.entities.y[i]
						r :=
							world.entities.radius[j] + world.entities.radius[i]
						if dx * dx + dy * dy <= r * r {
							record_collision(world, i, j)
						}
					}
					j = world.next[j]
				}
			}
		}
	}
}

collide_simd :: proc(world: ^World) {
	n := len(world.entities)
	for i in 0 ..< n {
		xi := (#simd[SIMD_LANES]f32)(world.entities.x[i])
		yi := (#simd[SIMD_LANES]f32)(world.entities.y[i])
		ri := (#simd[SIMD_LANES]f32)(world.entities.radius[i])
		j := i + 1
		for ; j + SIMD_LANES <= n; j += SIMD_LANES {
			xj := simd.from_slice(
				#simd[SIMD_LANES]f32,
				world.entities.x[j:][:SIMD_LANES],
			)
			yj := simd.from_slice(
				#simd[SIMD_LANES]f32,
				world.entities.y[j:][:SIMD_LANES],
			)
			rj := simd.from_slice(
				#simd[SIMD_LANES]f32,
				world.entities.radius[j:][:SIMD_LANES],
			)
			dx := xj - xi
			dy := yj - yi
			r := rj + ri
			mask := simd.lanes_le(dx * dx + dy * dy, r * r)
			bits := transmute(u8)simd.extract_lsbs(mask)
			world.pair_tests += SIMD_LANES
			for lane in 0 ..< SIMD_LANES {
				if bits & (u8(1) << u8(lane)) != 0 {
					record_collision(world, i, j + lane)
				}
			}
		}
		for ; j < n; j += 1 {
			world.pair_tests += 1
			dx := world.entities.x[j] - world.entities.x[i]
			dy := world.entities.y[j] - world.entities.y[i]
			r := world.entities.radius[j] + world.entities.radius[i]
			if dx * dx + dy * dy <= r * r {
				record_collision(world, i, j)
			}
		}
	}
}

hybrid_scan_entity :: #force_inline proc(
	world: ^World,
	x, y, radius: f32,
	index: int,
	candidates: #soa[]Search_Entity,
	lena: int,
	start: int,
) {
	xi := (#simd[SIMD_LANES]f32)(x)
	yi := (#simd[SIMD_LANES]f32)(y)
	ri := (#simd[SIMD_LANES]f32)(radius)
	j := start
	for ; j + SIMD_LANES <= len(candidates); j += SIMD_LANES {
		xj := simd.from_slice(
			#simd[SIMD_LANES]f32,
			candidates.x[j:][:SIMD_LANES],
		)
		yj := simd.from_slice(
			#simd[SIMD_LANES]f32,
			candidates.y[j:][:SIMD_LANES],
		)
		rj := simd.from_slice(
			#simd[SIMD_LANES]f32,
			candidates.radius[j:][:SIMD_LANES],
		)
		dx := xj - xi
		dy := yj - yi
		r := rj + ri
		bits := transmute(u8)simd.extract_lsbs(
			simd.lanes_le(dx * dx + dy * dy, r * r),
		)
		world.pair_tests += SIMD_LANES

		for ; bits != 0; bits &= bits - 1 {
			idx := j + int(simd.count_trailing_zeros(bits))
			record_collision(world, index, candidates.index[idx])
		}
	}
}

collide_hybrid :: proc(world: ^World) {
	cell_size := world.hybrid_cell_size
	columns := int(math.ceil(world.map_size / cell_size))
	sector_count := columns * columns
	counts := make([]int, sector_count, context.temp_allocator)
	sectors := make([]Hybrid_Sector, sector_count, context.temp_allocator)

	max_radius: f32
	for i in 0 ..< len(world.entities) {
		cx := clamp(int(world.entities.x[i] / cell_size), 0, columns - 1)
		cy := clamp(int(world.entities.y[i] / cell_size), 0, columns - 1)
		counts[cy * columns + cx] += 1
		max_radius = max(max_radius, world.entities.radius[i])
	}

	for &count in counts {
		count = mem.align_forward_int(count, SIMD_LANES)
	}

	for count, i in counts {
		if count > 0 {
			sectors[i].entities = make(
				#soa[]Search_Entity,
				count,
				context.temp_allocator,
			)
		}
	}
	for i in 0 ..< len(world.entities) {
		cx := clamp(int(world.entities.x[i] / cell_size), 0, columns - 1)
		cy := clamp(int(world.entities.y[i] / cell_size), 0, columns - 1)
		sec := &sectors[cy * columns + cx]
		sec.entities[sec.len] = Search_Entity {
			world.entities.x[i],
			world.entities.y[i],
			world.entities.radius[i],
			i,
		}
		sec.len += 1
	}

	for sector_index in 0 ..< sector_count {
		current := &sectors[sector_index]
		for i in 0 ..< current.len {
			hybrid_scan_entity(
				world,
				current.entities.x[i],
				current.entities.y[i],
				current.entities.radius[i],
				current.entities.index[i],
				current.entities,
				current.len,
				i + 1,
			)

			x := current.entities.x[i]
			y := current.entities.y[i]
			reach := current.entities.radius[i] + max_radius
			min_x := clamp(int((x - reach) / cell_size), 0, columns - 1)
			max_x := clamp(int((x + reach) / cell_size), 0, columns - 1)
			min_y := clamp(int((y - reach) / cell_size), 0, columns - 1)
			max_y := clamp(int((y + reach) / cell_size), 0, columns - 1)

			for ny in min_y ..= max_y {
				for nx in min_x ..= max_x {
					other_index := ny * columns + nx
					if other_index <= sector_index ||
					   len(sectors[other_index].entities) == 0 {
						continue
					}

					sector_min_x := f32(nx) * cell_size
					sector_min_y := f32(ny) * cell_size
					sector_max_x := min(
						sector_min_x + cell_size,
						world.map_size,
					)
					sector_max_y := min(
						sector_min_y + cell_size,
						world.map_size,
					)
					nearest_x := clamp(x, sector_min_x, sector_max_x)
					nearest_y := clamp(y, sector_min_y, sector_max_y)
					dx := x - nearest_x
					dy := y - nearest_y
					if dx * dx + dy * dy > reach * reach do continue

					other := sectors[other_index].entities
					hybrid_scan_entity(
						world,
						x,
						y,
						current.entities.radius[i],
						current.entities.index[i],
						other,
						sectors[other_index].len,
						0,
					)
				}
			}
		}
	}
}

run_collision_search :: proc(world: ^World) {
	for &hit in world.collided do hit = false
	clear(&world.pairs)
	world.collision_count = 0
	world.pair_tests = 0

	started := time.now()
	switch world.strategy {
	case .Spatial_Hash:
		collide_spatial(world)
	case .SIMD_All_Pairs:
		collide_simd(world)
	case .Hybrid:
		collide_hybrid(world)
	}
	elapsed := time.since(started)
	world.search_us = time.duration_microseconds(elapsed)
	world.samples[world.sample_cursor] = world.search_us
	world.sample_cursor = (world.sample_cursor + 1) % SAMPLE_COUNT
	world.samples_filled = min(world.samples_filled + 1, SAMPLE_COUNT)
}

timing_stats :: proc(world: ^World) -> (average, p95: f64) {
	if world.samples_filled == 0 do return
	ordered: [SAMPLE_COUNT]f64
	for value, i in world.samples[:world.samples_filled] {
		average += value
		ordered[i] = value
	}
	average /= f64(world.samples_filled)
	for i in 1 ..< world.samples_filled {
		value := ordered[i]
		j := i
		for j > 0 && ordered[j - 1] > value {
			ordered[j] = ordered[j - 1]
			j -= 1
		}
		ordered[j] = value
	}
	p95 = ordered[int(f32(world.samples_filled - 1) * 0.95)]
	return
}

point_in_rect :: proc(point: rl.Vector2, rect: rl.Rectangle) -> bool {
	return(
		point.x >= rect.x &&
		point.x <= rect.x + rect.width &&
		point.y >= rect.y &&
		point.y <= rect.y + rect.height \
	)
}

button :: proc(rect: rl.Rectangle, label: cstring, active := false) -> bool {
	mouse := rl.GetMousePosition()
	hovered := point_in_rect(mouse, rect)
	color := rl.Color{35, 43, 55, 255}
	if active do color = {37, 112, 108, 255}
	if hovered do color = active ? rl.Color{45, 132, 127, 255} : rl.Color{48, 58, 72, 255}
	rl.DrawRectangleRounded(rect, 0.18, 5, color)
	width := rl.MeasureText(label, 16)
	rl.DrawText(
		label,
		i32(rect.x + (rect.width - f32(width)) / 2),
		i32(rect.y + 9),
		16,
		rl.Color{226, 232, 238, 255},
	)
	return hovered && rl.IsMouseButtonPressed(.LEFT)
}

slider :: proc(label, value_text: cstring, y, normalized: f32) -> (f32, bool) {
	result := normalized
	rl.DrawText(label, 24, i32(y), 16, rl.Color{164, 176, 190, 255})
	text_width := rl.MeasureText(value_text, 16)
	rl.DrawText(
		value_text,
		PANEL_WIDTH - 24 - text_width,
		i32(y),
		16,
		rl.Color{238, 242, 245, 255},
	)
	track := rl.Rectangle{24, y + 31, PANEL_WIDTH - 48, 5}
	rl.DrawRectangleRounded(track, 1, 4, rl.Color{47, 57, 70, 255})
	fill := track
	fill.width *= normalized
	rl.DrawRectangleRounded(fill, 1, 4, rl.Color{62, 184, 174, 255})
	knob_x := track.x + track.width * normalized
	rl.DrawCircleV({knob_x, track.y + 2.5}, 8, rl.Color{219, 251, 247, 255})

	mouse := rl.GetMousePosition()
	hit := rl.Rectangle{track.x - 8, track.y - 12, track.width + 16, 29}
	changed := false
	if point_in_rect(mouse, hit) && rl.IsMouseButtonDown(.LEFT) {
		result = clamp((mouse.x - track.x) / track.width, 0, 1)
		changed = true
	}
	return result, changed
}

draw_panel :: proc(world: ^World) {
	rl.DrawRectangle(
		0,
		0,
		PANEL_WIDTH,
		rl.GetScreenHeight(),
		rl.Color{18, 23, 30, 255},
	)
	rl.DrawLine(
		PANEL_WIDTH,
		0,
		PANEL_WIDTH,
		rl.GetScreenHeight(),
		rl.Color{48, 58, 70, 255},
	)
	rl.DrawText("COLLISION LAB", 24, 24, 24, rl.Color{235, 240, 244, 255})
	rl.DrawText(
		"Broad-phase performance bench",
		24,
		54,
		15,
		rl.Color{121, 136, 153, 255},
	)

	rl.DrawText("SEARCH STRATEGY", 24, 96, 13, rl.Color{102, 119, 136, 255})
	left := rl.Rectangle{24, 119, 89, 36}
	middle := rl.Rectangle{121, 119, 89, 36}
	right := rl.Rectangle{218, 119, 88, 36}
	if button(left, "HASH", world.strategy == .Spatial_Hash) {
		world.strategy = .Spatial_Hash
		respawn(world)
	}
	if button(middle, "SIMD ALL", world.strategy == .SIMD_All_Pairs) {
		world.strategy = .SIMD_All_Pairs
		respawn(world)
	}
	if button(right, "HYBRID", world.strategy == .Hybrid) {
		world.strategy = .Hybrid
		respawn(world)
	}

	norm, changed := slider(
		"Entities",
		fmt.ctprintf("%d", world.entity_count),
		182,
		f32(world.entity_count - 100) / 7900,
	)
	if changed {
		count := int(100 + norm * 7900)
		count = (count / 10) * 10
		if count != world.entity_count {
			world.entity_count = count
			world.seed += 1
			respawn(world)
		}
	}

	norm, changed = slider(
		"World size",
		fmt.ctprintf("%.0f x %.0f", world.map_size, world.map_size),
		250,
		(world.map_size - 600) / 4400,
	)
	if changed {
		size := f32(int((600 + norm * 4400) / 50) * 50)
		if size != world.map_size {
			world.map_size = size
			world.seed += 1
			respawn(world)
		}
	}

	norm, changed = slider(
		"Hash cell size",
		fmt.ctprintf("%.0f units", world.cell_size),
		318,
		(world.cell_size - 16) / 184,
	)
	if changed {
		world.cell_size = f32(int(16 + norm * 184))
	}

	norm, changed = slider(
		"Hybrid cell size",
		fmt.ctprintf("%.0f units", world.hybrid_cell_size),
		386,
		(world.hybrid_cell_size - 32) / 368,
	)
	if changed {
		world.hybrid_cell_size = f32(int(32 + norm * 368))
	}
	hash_columns := int(math.ceil(world.map_size / world.cell_size))
	hybrid_columns := int(math.ceil(world.map_size / world.hybrid_cell_size))
	rl.DrawText(
		fmt.ctprintf(
			"Hash %d sectors  |  Hybrid %d",
			hash_columns * hash_columns,
			hybrid_columns * hybrid_columns,
		),
		24,
		433,
		14,
		rl.Color{100, 157, 153, 255},
	)

	rl.DrawLine(24, 462, PANEL_WIDTH - 24, 462, rl.Color{43, 52, 64, 255})
	rl.DrawText("COLLISION SEARCH", 24, 482, 13, rl.Color{102, 119, 136, 255})
	average, p95 := timing_stats(world)
	rl.DrawText(
		fmt.ctprintf("%.1f", world.search_us),
		24,
		508,
		38,
		rl.Color{106, 226, 212, 255},
	)
	rl.DrawText(
		"microseconds / frame",
		133,
		524,
		14,
		rl.Color{135, 148, 162, 255},
	)
	rl.DrawText(
		fmt.ctprintf("Rolling avg   %.1f us", average),
		24,
		562,
		16,
		rl.Color{218, 225, 231, 255},
	)
	rl.DrawText(
		fmt.ctprintf("P95 (120f)    %.1f us", p95),
		24,
		587,
		16,
		rl.Color{218, 225, 231, 255},
	)
	rl.DrawText(
		fmt.ctprintf("Pair tests    %d", world.pair_tests),
		24,
		621,
		16,
		rl.Color{167, 178, 190, 255},
	)
	rl.DrawText(
		fmt.ctprintf("Collisions    %d", world.collision_count),
		24,
		646,
		16,
		rl.Color{167, 178, 190, 255},
	)
	rl.DrawText(
		fmt.ctprintf("Frame rate    %d fps", rl.GetFPS()),
		24,
		671,
		16,
		rl.Color{167, 178, 190, 255},
	)

	if button({24, 711, 137, 38}, world.paused ? "RESUME" : "PAUSE") {
		world.paused = !world.paused
	}
	if button({169, 711, 137, 38}, "RESPAWN") {
		world.seed += 1
		respawn(world)
	}

	rl.DrawText(
		"TIMING SCOPE",
		24,
		rl.GetScreenHeight() - 115,
		12,
		rl.Color{102, 119, 136, 255},
	)
	rl.DrawText(
		"Index/packing + candidate search +",
		24,
		rl.GetScreenHeight() - 92,
		13,
		rl.Color{133, 146, 160, 255},
	)
	rl.DrawText(
		"narrow phase. Motion and drawing",
		24,
		rl.GetScreenHeight() - 73,
		13,
		rl.Color{133, 146, 160, 255},
	)
	rl.DrawText(
		"are excluded. Release build advised.",
		24,
		rl.GetScreenHeight() - 54,
		13,
		rl.Color{133, 146, 160, 255},
	)
}

draw_world :: proc(world: ^World) {
	screen_w := f32(rl.GetScreenWidth())
	screen_h := f32(rl.GetScreenHeight())
	margin: f32 = 26
	view_w := screen_w - PANEL_WIDTH - margin * 2
	view_h := screen_h - margin * 2
	scale := min(view_w, view_h) / world.map_size
	world_px := world.map_size * scale
	origin := rl.Vector2 {
		PANEL_WIDTH + margin + (view_w - world_px) / 2,
		margin + (view_h - world_px) / 2,
	}

	rl.DrawRectangleRounded(
		{origin.x - 1, origin.y - 1, world_px + 2, world_px + 2},
		0.008,
		4,
		rl.Color{41, 51, 62, 255},
	)
	rl.DrawRectangle(
		i32(origin.x),
		i32(origin.y),
		i32(world_px),
		i32(world_px),
		rl.Color{11, 16, 22, 255},
	)

	if world.strategy != .SIMD_All_Pairs {
		cell_size :=
			world.strategy == .Spatial_Hash ? world.cell_size : world.hybrid_cell_size
		grid_color :=
			world.strategy == .Spatial_Hash ? rl.Color{52, 132, 126, 72} : rl.Color{177, 126, 66, 72}
		columns := int(math.ceil(world.map_size / cell_size))
		for i in 1 ..< columns {
			offset := min(f32(i) * cell_size, world.map_size) * scale
			rl.DrawLineV(
				{origin.x + offset, origin.y},
				{origin.x + offset, origin.y + world_px},
				grid_color,
			)
			rl.DrawLineV(
				{origin.x, origin.y + offset},
				{origin.x + world_px, origin.y + offset},
				grid_color,
			)
		}
	}

	for pair in world.pairs {
		a := rl.Vector2 {
			origin.x + world.entities.x[pair.a] * scale,
			origin.y + world.entities.y[pair.a] * scale,
		}
		b := rl.Vector2 {
			origin.x + world.entities.x[pair.b] * scale,
			origin.y + world.entities.y[pair.b] * scale,
		}
		rl.DrawLineV(a, b, rl.Color{239, 91, 105, 105})
	}
	for i in 0 ..< len(world.entities) {
		pos := rl.Vector2 {
			origin.x + world.entities.x[i] * scale,
			origin.y + world.entities.y[i] * scale,
		}
		radius := max(world.entities.radius[i] * scale, 1.4)
		color :=
			world.collided[i] ? rl.Color{249, 93, 108, 255} : rl.Color{69, 197, 185, 235}
		rl.DrawCircleV(pos, radius, color)
	}

	strategy_text: cstring
	switch world.strategy {
	case .Spatial_Hash:
		strategy_text = "SPATIAL HASH"
	case .SIMD_All_Pairs:
		strategy_text = "SOA / SIMD ALL-PAIRS"
	case .Hybrid:
		strategy_text = "PACKED SECTOR / SIMD HYBRID"
	}
	rl.DrawText(
		strategy_text,
		i32(origin.x + 12),
		i32(origin.y + 12),
		14,
		rl.Color{118, 136, 151, 255},
	)
	rl.DrawText(
		fmt.ctprintf("1 px = %.2f units", 1 / scale),
		i32(origin.x + 12),
		i32(origin.y + 32),
		13,
		rl.Color{79, 95, 109, 255},
	)
}

@(test)
test_strategies_match_scalar_reference :: proc(t: ^testing.T) {
	world := World {
		entity_count = 257,
		map_size     = 240,
		cell_size    = 16,
		seed         = 0x12345678,
	}
	defer delete(world.entities)
	defer delete(world.collided)
	defer delete(world.pairs)
	defer delete(world.heads)
	defer delete(world.next)
	respawn(&world)

	reference_count := 0
	for i in 0 ..< len(world.entities) {
		for j in i + 1 ..< len(world.entities) {
			dx := world.entities.x[j] - world.entities.x[i]
			dy := world.entities.y[j] - world.entities.y[i]
			r := world.entities.radius[j] + world.entities.radius[i]
			if dx * dx + dy * dy <= r * r do reference_count += 1
		}
	}

	world.strategy = .Spatial_Hash
	run_collision_search(&world)
	testing.expect_value(t, world.collision_count, reference_count)
	world.strategy = .SIMD_All_Pairs
	run_collision_search(&world)
	testing.expect_value(t, world.collision_count, reference_count)
	world.strategy = .Hybrid
	for cell_size in ([5]f32{8, 13, 32, 64, 127}) {
		world.hybrid_cell_size = cell_size
		run_collision_search(&world)
		testing.expect_value(t, world.collision_count, reference_count)
	}
}

main :: proc() {
	rl.SetConfigFlags({.WINDOW_RESIZABLE, .MSAA_4X_HINT})
	rl.InitWindow(
		WINDOW_WIDTH,
		WINDOW_HEIGHT,
		"Collision Lab - Hash vs SIMD vs Hybrid",
	)
	defer rl.CloseWindow()
	rl.SetWindowMinSize(980, 900)
	rl.SetTargetFPS(144)

	world := World {
		strategy         = .Spatial_Hash,
		entity_count     = 1800,
		map_size         = 1200,
		cell_size        = 32,
		hybrid_cell_size = 128,
		seed             = 0x9e3779b97f4a7c15,
	}
	defer delete(world.entities)
	defer delete(world.collided)
	defer delete(world.pairs)
	defer delete(world.heads)
	defer delete(world.next)
	respawn(&world)

	for !rl.WindowShouldClose() {
		if !world.paused {
			move_entities(&world, min(rl.GetFrameTime(), 1.0 / 30.0))
		}
		run_collision_search(&world)

		rl.BeginDrawing()
		rl.ClearBackground(rl.Color{8, 12, 17, 255})
		draw_world(&world)
		draw_panel(&world)
		rl.EndDrawing()
		free_all(context.temp_allocator)
	}
}
