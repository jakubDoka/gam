package sandbox

import "../sim"
import "../util/arna"
import "../util/hot"
import "core:container/queue"
import "core:fmt"
import "core:log"
import "core:math"
import "core:math/linalg"
import "core:strings"
import rl "vendor:raylib"

GRAVITY :: sim.Vec{0, 0}
RADIUS_ :: 64
ESP :: 1e-5
DIST_ESP :: 1e-3

Ent :: struct {
	pos:    sim.Vec,
	vel:    sim.Vec,
	id:     int,
	radius: f32,
}

Physics_State :: struct {
	fuel:             f32,
	no_change_streak: u32,
	quad:             sim.Quad_Ent,
	spatial:          sim.Spatial_Ent,
	ent:              ^Ent,
}

Ents :: struct {
	pivot:       sim.Vec,
	camera:      rl.Camera2D,
	using mapa:  sim.Map,
	slots:       [dynamic]Ent,
	pstate:      []Physics_State,
	spatial_map: sim.Spatial_Map,
	quad_tree:   sim.Quad_Tree,
}

Ents_Query :: union #no_nil {
	sim.Quad_Iter,
	sim.Spatial_Iter,
}

ents_query :: proc(ents: ^Ents, pos: sim.Vec, radius: f32) -> Ents_Query {
	context.allocator = context.temp_allocator

	if radius <= sim.TILE_SIZE {
		return sim.Spatial_Iter {
			mapa = &ents.spatial_map,
			pos = sim.map_vec_to_pos(pos),
		}
	}

	config := sim.Quad_Config {
		quad_size = i32(sim.map_quad_size(&ents.mapa)),
	}

	return sim.quad_iter(
		&ents.quad_tree,
		sim.quad_rect_square(pos, radius),
		config,
	)
}

ents_query_next :: proc(query: ^Ents_Query) -> (s: ^Ent, ok: bool) {
	st := ents_query_next_low(query) or_return
	return st.ent, true
}

ents_query_next_low :: proc(query: ^Ents_Query) -> (^Physics_State, bool) {
	switch &q in query^ {
	case sim.Quad_Iter:
		ent, ok := sim.quad_iter_next(&q)
		return (^Physics_State)(uintptr(ent) - offset_of(Physics_State, quad)),
			ok
	case sim.Spatial_Iter:
		ent, ok := sim.spatial_iter_next(&q)
		return (^Physics_State)(
				uintptr(ent) - offset_of(Physics_State, spatial),
			),
			ok
	case:
		return nil, false
	}
}

ents_radius :: proc(ents: ^Ents, id: int) -> f32 {
	return ents.slots[id].radius
}

@(export)
sandbox_memory_size :: proc() -> (count: int) {
	for t in sim.HOT_TYPES do count += size_of(t)
	count += size_of(Ents) + size_of(Ent)
	return
}

@(export)
sandbox_static_init :: proc(params: hot.Static_Init_Params) {}

@(export)
sandbox_init :: proc(reloader: ^hot.Reloader) -> (ents: ^Ents) {
	context.allocator = reloader.init_allocator

	ents = new(Ents)

	MAP ::
		"wwwwwwwwwwwww\n" +
		"w     0     w\n" +
		"w           w\n" +
		"w    www    w\n" +
		"w           w\n" +
		"w  w     w  w\n" +
		"w  w  w  w  w\n" +
		"w  w     w  w\n" +
		"w     a     w\n" +
		"w  w     w  w\n" +
		"w  w  w  w  w\n" +
		"w  w     w  w\n" +
		"w           w\n" +
		"w    www    w\n" +
		"w           w\n" +
		"w     1     w\n" +
		"wwwwwwwwwwwww\n"

	buf := make([]u8, 1024)
	e := sim.Encoder{buf}

	sim.map_text_to_bin(MAP, &e, 0)
	ents.mapa = sim.map_load(buf) or_else panic("")

	ents.camera.zoom = 0.3
	ents.camera.target =
		{f32(ents.width), f32(ents.height)} * sim.TILE_SIZE / 2

	return
}

step :: proc(ents: ^Ents, ent: ^Ent) {
	radius := ents_radius(ents, ent.id)

	overscan := radius / linalg.length(ent.vel)

	inv_v := 1.0 / ent.vel

	step_x := int(math.sign(ent.vel.x))
	step_y := int(math.sign(ent.vel.y))

	tDelta := sim.TILE_SIZE * linalg.abs(inv_v)

	tolerance: f32 = min(abs(tDelta.x), abs(tDelta.y))

	p1 := ent.pos + linalg.orthogonal(linalg.normalize(ent.vel) * radius)
	p2 := ent.pos - linalg.orthogonal(linalg.normalize(ent.vel) * radius)

	cursor1 := sim.map_vec_to_pos(p1)
	cursor2 := sim.map_vec_to_pos(p2)

	prevc1, prevc2: sim.Map_Pos

	tile_min1 := linalg.floor(p1 * sim.TILE_RECIPRO) * sim.TILE_SIZE
	tile_max1 := tile_min1 + sim.TILE_SIZE

	tile_min2 := linalg.floor(p2 * sim.TILE_RECIPRO) * sim.TILE_SIZE
	tile_max2 := tile_min2 + sim.TILE_SIZE

	next_boundary1 := sim.Vec {
		tile_max1.x if step_x >= 0 else tile_min1.x,
		tile_max1.y if step_y >= 0 else tile_min1.y,
	}
	next_boundary2 := sim.Vec {
		tile_max2.x if step_x >= 0 else tile_min2.x,
		tile_max2.y if step_y >= 0 else tile_min2.y,
	}

	tMax1 := (next_boundary1 - p1) * inv_v
	tMax2 := (next_boundary2 - p2) * inv_v

	t1, t2: f32

	pstate := &ents.pstate[ent.id]

	best_t := pstate.fuel
	best_normal := linalg.orthogonal(ent.vel)

	for (t1 - tolerance - overscan <= best_t ||
		    t2 - tolerance - overscan <= best_t) &&
	    abs(step_x) + abs(step_y) != 0 {

		col := rl.ColorAlpha(rl.GREEN, 0.5)
		opts := [?]sim.Map_Pos{cursor1, cursor2}
		for cursor in opts {
			if !sim.map_tile_is_solid(ents, cursor) do continue

			tile_min := sim.Vec{f32(cursor.x), f32(cursor.y)} * sim.TILE_SIZE
			tile_max := tile_min + sim.TILE_SIZE

			corners := [?]sim.Vec {
				tile_min,
				{tile_max.x, tile_min.y},
				tile_max,
				{tile_min.x, tile_max.y},
			}

			for c in corners {
				t := sim.circle_collision(c, ent.pos, 0, ent.vel, 0, radius)
				if 0 <= t && t < best_t {
					best_t = t
					best_normal = linalg.normalize0(ent.pos - c)
				}
			}

			for b in ([?]sim.Vec{tile_min, tile_max}) {
				d := b - ent.pos

				tx := math.copy_sign(abs(d.x) - radius, d.x) * inv_v.x
				ty := math.copy_sign(abs(d.y) - radius, d.y) * inv_v.y

				projy := ent.pos.y + tx * ent.vel.y
				projx := ent.pos.x + ty * ent.vel.x

				inx := tile_min.y <= projy && projy < tile_max.y
				iny := tile_min.x <= projx && projx < tile_max.x

				if 0 <= tx && tx < best_t && inx {
					best_t = tx
					best_normal = {math.copy_sign(1.0, -ent.vel.x), 0}
				}

				if 0 <= ty && ty < best_t && iny {
					best_t = ty
					best_normal = {0, math.copy_sign(1.0, -ent.vel.y)}
				}
			}
		}

		if tMax1.x < tMax1.y {
			t1 = tMax1.x
			tMax1.x += tDelta.x
			cursor1.x += step_x
		} else {
			t1 = tMax1.y
			tMax1.y += tDelta.y
			cursor1.y += step_y
		}

		if tMax2.x < tMax2.y {
			t2 = tMax2.x
			tMax2.x += tDelta.x
			cursor2.x += step_x
		} else {
			t2 = tMax2.y
			tMax2.y += tDelta.y
			cursor2.y += step_y
		}
	}

	collider := -1
	vel_estimate := ent.vel * best_t
	movement_range := radius * 2 + linalg.length2(vel_estimate)
	iter := ents_query(ents, ent.pos + vel_estimate / 2, movement_range)
	for oent in ents_query_next(&iter) {
		if oent == ent do continue
		t := sim.circle_collision(
			ent.pos,
			oent.pos,
			ent.vel,
			oent.vel,
			radius,
			radius,
		)

		opstate := ents.pstate[oent.id]

		if ESP <= t && t < best_t && t <= opstate.fuel {
			ot, _, _ := sim.map_wall_collision(ents, oent.pos, oent.vel * t)
			if ot != 1 do continue

			best_t = t
			collider = oent.id
		}
	}

	ent.pos += ent.vel * best_t

	if collider >= 0 {
		coll := &ents.slots[collider]
		cpstate := &ents.pstate[coll.id]

		coll.pos += coll.vel * best_t
		cpstate.fuel -= best_t

		norm := linalg.normalize(ent.pos - coll.pos)

		cradius := ents_radius(ents, coll.id)

		amass := radius * radius * math.PI * 1
		bmass := cradius * cradius * math.PI * 1

		p :=
			2.0 *
			(linalg.dot(ent.vel, norm) - linalg.dot(coll.vel, norm)) /
			(amass + bmass)

		ap := p * bmass * 1
		bp := p * amass * 1

		ent.vel -= ap * norm
		coll.vel += ap * norm
	} else {
		ent.vel = linalg.reflect(ent.vel, best_normal)
	}

	pstate.no_change_streak += u32(best_t < ESP)
	pstate.fuel -= best_t

	return
}

draw_tile :: proc(pos: sim.Map_Pos, color: rl.Color) {
	rl.DrawRectangleRec(
		{
			f32(pos.x * sim.TILE_SIZE),
			f32(pos.y * sim.TILE_SIZE),
			sim.TILE_SIZE,
			sim.TILE_SIZE,
		},
		color,
	)
}

@(export)
sandbox_update :: proc(ents: ^Ents) {
	rl.BeginDrawing()

	rl.ClearBackground(rl.RAYWHITE)

	delta := rl.GetFrameTime()
	mouse_pos := rl.GetScreenToWorld2D(rl.GetMousePosition(), ents.camera)
	mouse_tile := sim.map_vec_to_pos(mouse_pos)

	CAMERA_SPEED :: 500

	ents.camera.offset =
		{f32(rl.GetScreenWidth()), f32(rl.GetScreenHeight())} / 2

	if rl.IsKeyDown(.A) {
		ents.camera.target.x -= CAMERA_SPEED / ents.camera.zoom * delta
	}
	if rl.IsKeyDown(.W) {
		ents.camera.target.y -= CAMERA_SPEED / ents.camera.zoom * delta
	}
	if rl.IsKeyDown(.D) {
		ents.camera.target.x += CAMERA_SPEED / ents.camera.zoom * delta
	}
	if rl.IsKeyDown(.S) {
		ents.camera.target.y += CAMERA_SPEED / ents.camera.zoom * delta
	}

	if rl.IsMouseButtonPressed(.LEFT) {
		ents.pivot = mouse_pos
	}

	if rl.IsMouseButtonReleased(.LEFT) {
		for _ in 0 ..< 100 {
			append(
				&ents.slots,
				Ent {
					pos = ents.pivot,
					vel = ents.pivot - mouse_pos,
					radius = 16,
					id = len(ents.slots),
				},
			)
		}
	}

	if rl.IsMouseButtonPressed(.RIGHT) {
		sim.map_tile_set(
			ents,
			mouse_tile,
			!sim.map_tile_is_solid(ents, mouse_tile),
		)
	}

	if rl.IsKeyDown(.C) {
		clear(&ents.slots)
	}

	ents.camera.target = linalg.clamp(
		ents.camera.target,
		0,
		sim.Vec{f32(ents.width), f32(ents.height)} * sim.TILE_SIZE,
	)

	ents.camera.zoom *= 1 - rl.GetMouseWheelMove() * 0.1

	rl.BeginMode2D(ents.camera)

	for y in 0 ..< ents.height {
		for x in 0 ..< ents.width {
			if sim.map_tile_is_solid(ents, {x, y}) {
				draw_tile({x, y}, rl.GRAY)
			} else {
				rl.DrawRectangleLinesEx(
					{
						f32(x * sim.TILE_SIZE),
						f32(y * sim.TILE_SIZE),
						sim.TILE_SIZE,
						sim.TILE_SIZE,
					},
					1 / ents.camera.zoom,
					rl.GRAY,
				)
			}
		}
	}

	move(ents, delta)

	for &ent in ents.slots {
		radius := ents_radius(ents, ent.id)

		rl.DrawCircleV(ent.pos, radius, rl.RED)

		compute: for _ in 0 ..< 3 {
			eliminate_overlap(ents, &ent)
		}
	}

	if rl.IsMouseButtonDown(.LEFT) {
		rl.DrawLineEx(ents.pivot, mouse_pos, 2 / ents.camera.zoom, rl.RED)
	}

	rl.EndMode2D()

	rl.DrawFPS(10, 10)

	rl.DrawText(
		strings.clone_to_cstring(
			fmt.tprint(len(ents.slots)),
			context.temp_allocator,
		),
		100,
		10,
		20,
		rl.BLACK,
	)

	rl.EndDrawing()
}

move :: proc(ents: ^Ents, delta: f32) {
	worklist: queue.Queue(^Ent)
	{context.allocator = context.temp_allocator
		ents.quad_tree = {}
		sim.spatial_map_init(&ents.spatial_map, ents.width, ents.height)
		ents.pstate = make([]Physics_State, len(ents.slots))
		queue.init(&worklist, len(ents.slots))

		config := sim.Quad_Config {
			quad_size = i32(sim.map_quad_size(&ents.mapa)),
		}

		for &ent, i in ents.slots {
			pstate := &ents.pstate[i]
			pstate^ = {
				fuel = delta,
				ent  = &ent,
			}

			radius := ents_radius(ents, ent.id)
			pstate.quad.rect = sim.quad_rect_square(ent.pos, radius)
			sim.quad_tree_add(&ents.quad_tree, &pstate.quad, config)
			pos := sim.map_vec_to_pos(ent.pos)
			sim.spatial_map_insert(&ents.spatial_map, pos, &pstate.spatial)

			queue.append(&worklist, &ent)
			ent.vel += GRAVITY * delta
		}
	}

	for ent in queue.pop_front_safe(&worklist) {
		pstate := &ents.pstate[ent.id]
		if pstate.fuel <= ESP do continue
		mpos := sim.map_vec_to_pos(ent.pos)
		if sim.map_tile_is_solid(ents, mpos) do continue

		step(ents, ent)

		if pstate.fuel > ESP && pstate.no_change_streak <= 1 {
			queue.append(&worklist, ent)
		}
	}
}

eliminate_overlap :: proc(ents: ^Ents, ent: ^Ent) {
	radius := ents_radius(ents, ent.id)

	iter := ents_query(ents, ent.pos, ent.radius)
	for oent in ents_query_next(&iter) {
		if ent == oent do continue

		oradius := ents_radius(ents, ent.id)

		min_dist := oradius + radius

		if linalg.length2(ent.pos - oent.pos) > min_dist * min_dist {
			continue
		}

		normal: sim.Vec
		if oent.pos == ent.pos {
			normal = sim.vec_of(f32((oent.id << 32) | ent.id))
		} else {
			normal = linalg.normalize(oent.pos - ent.pos)
		}

		contact_point := (oent.pos + ent.pos) / 2

		oent.pos = contact_point + normal * (oradius + DIST_ESP)
		ent.pos = contact_point - normal * (radius + DIST_ESP)
	}

	min_tile := sim.map_vec_to_pos(ent.pos - radius)
	max_tile := sim.map_vec_to_pos(ent.pos + radius)

	best_normal: sim.Vec
	best_contact_point: sim.Vec

	collide: for y in min_tile.y ..= max_tile.y {
		for x in min_tile.x ..= max_tile.x {
			normal, contact_point := collide_tile(
				ents,
				{x, y},
				ent.pos,
				radius,
			)

			if linalg.length2(ent.pos - contact_point) <
			   linalg.length2(ent.pos - best_contact_point) {
				best_contact_point = contact_point
				best_normal = normal
			}
		}
	}

	if best_contact_point != {} {
		ent.pos = best_contact_point + best_normal * (radius + DIST_ESP)
		ent.vel = linalg.reflect(ent.vel, best_normal)
	}

	tile := sim.map_vec_to_pos(ent.pos)

	if sim.map_tile_is_solid(ents, tile) {
		tile := find_empty_tile(ents, tile)

		tile_min := sim.Vec{f32(tile.x), f32(tile.y)} * sim.TILE_SIZE
		tile_max := tile_min + sim.TILE_SIZE

		ent.pos = linalg.clamp(ent.pos, tile_min + 1, tile_max - 1)
	}
}

collide_tile :: proc(
	ents: ^Ents,
	tile: sim.Map_Pos,
	pos: sim.Vec,
	radius: f32,
) -> (
	normal: sim.Vec,
	contact_point: sim.Vec,
) {
	origin_tile := sim.map_vec_to_pos(pos)

	x, y := tile.x, tile.y

	tile_min := sim.Vec{f32(x), f32(y)} * sim.TILE_SIZE
	tile_max := tile_min + sim.TILE_SIZE

	corners := [?]sim.Vec {
		tile_min,
		{tile_max.x, tile_min.y},
		tile_max,
		{tile_min.x, tile_max.y},
	}

	out := true

	if sim.map_tile_is_solid(ents, {x, y}) {
		origin_tile_pos := sim.map_pos_to_vec({x, y})

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

	if !out {
		draw_tile({x, y}, rl.ColorAlpha(rl.RED, 0.1))
	}

	return
}

find_empty_tile :: proc(ents: ^Ents, origin: sim.Map_Pos) -> sim.Map_Pos {
	dirs := [?]sim.Map_Pos{{1, -1}, {1, 1}, {-1, 1}, {-1, -1}}

	search: for radius in 1 ..< 100 {
		cursor := sim.Map_Pos{origin.x - radius, origin.y}
		for d in dirs {
			for _ in 0 ..< radius {
				if !sim.map_tile_is_solid(ents, cursor) {
					return cursor
				} else {
					draw_tile(cursor, rl.ColorAlpha(rl.RED, 1.0 / f32(radius)))
				}
				cursor += d
			}
		}
		assert(cursor == {origin.x - radius, origin.y})
	}

	return {}
}

@(export)
sandbox_deinit :: proc(ents: ^Ents) {}

when ODIN_BUILD_MODE == .Executable || ODIN_BUILD_MODE == .Object {
	main :: proc() {
		main_proc()
	}
}

main_proc :: proc() {
	context.logger = log.create_console_logger()

	init_arna: arna.Allocator
	init_arna.reserved = 1024 * 1024

	err := arna.bulk_init(&init_arna)
	assert(err == nil)

	hr: hot.Reloader
	hr.watch_dirs = {"sandbox", "sim"}
	hr.extra_args = {"-define:RAYLIB_SHARED=true"}
	hr.lib = {
		memory_size = sandbox_memory_size,
		static_init = sandbox_static_init,
		init        = auto_cast sandbox_init,
		update      = auto_cast sandbox_update,
		deinit      = auto_cast sandbox_deinit,
	}
	hr.init_allocator = arna.allocator(&init_arna)

	rl.SetConfigFlags({.WINDOW_RESIZABLE})
	rl.InitWindow(800, 600, "gam")
	rl.SetTargetFPS(60)

	for !rl.WindowShouldClose() {
		_ = hot.reload(&hr, {module_name = "sandbox"})

		hot.update(&hr)

		free_all(context.temp_allocator)
	}
}
