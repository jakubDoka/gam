package sim

import "../util/b58"
import "../util/nm"
import "../util/packer"
import rt "base:runtime"
import "core:container/queue"
import "core:fmt"
import "core:io"
import "core:log"
import "core:math"
import "core:math/linalg"
import "core:math/rand"
import "core:mem"
import "core:reflect"
import "core:simd"
import "core:slice"
import "core:sort"
import "core:testing"

ESP :: 1e-5
DIST_ESP :: 1e-4
MAX_ENT_RADIUS :: 64
MAX_ENTS_PER_GAME :: 128
HOT_TYPES :: [?]typeid{Ent, Ent_Stats, Ents, Map}
LOCAL :: #config(LOCAL, false)

Vec :: [2]f32
Color :: distinct u32
Asset_ID :: distinct u32
Asset_Idx :: distinct i32
Ent_Team_ID :: distinct int
Ent_Stats_ID :: distinct int
Ent_Stats_Name :: nm.Name

Asset_Ref :: struct #raw_union {
	id: Asset_ID,
}

@(rodata)
NIL_TEAM_MEM := Ent_Team {
	color = 0x2BBDFBFF,
}
NIL_TEAM := &NIL_TEAM_MEM

Ent_Net_ID :: struct {
	peer: u32,
	seq:  u32,
}

Ent_ID :: struct {
	gen:   u32,
	index: u32,
}

@(rodata)
NIL_STATS_MEM := Ent_Stats{}
NIL_STATS := &NIL_STATS_MEM

Ent_Stats_Ref :: struct #raw_union {
	name: string,
	id:   Ent_Stats_ID,
}

TARGETABLE :: bit_set[Ent_Kind]{.Building, .Unit, .PowerSource, .Rocket}
DRAWS_ENERGY :: bit_set[Ent_Kind]{.Building, .Unit, .PowerSource}
AUTO_RECONNECT :: bit_set[Ent_Kind]{.Unit}
REPELS :: bit_set[Ent_Kind]{.Unit}
COLLIDES_WITH_WALLS :: ~bit_set[Ent_Kind]{.Shell}
COLLIDES_WITH_OTHERS :: ~bit_set[Ent_Kind]{.Shell, .Beam}

Ent_Kind :: enum u8 {
	Building,
	Unit,
	PowerSource,
	Bullet,
	Laser,
	Beam,
	Rocket,
	Shell,
}

Ent_Stats_Attack :: struct {
	shots_per_reload_minus_one: int,
	bullets_per_shot_minus_one: int,
	shot_spacing:               f32 `gam:"round2"`,
	spread:                     f32 `gam:"round2"`,
	innaccuracy:                f32 `gam:"round2"`,
	recoil:                     f32 `gam:"round"`,
	bullet:                     Ent_Stats_Ref,
	unwind:                     f32 `gam:"round2"`,
}

Ent_Stats :: struct {
	name:             Ent_Stats_Name `gam:"hidden"`,
	id:               Ent_Stats_ID `gam:"hidden"`,
	playable:         bool,
	placable:         bool,
	can_spawn_player: bool,
	kind:             Ent_Kind,
	spawn_unit:       Ent_Stats_Ref,
	using physics:    struct {
		speed:                   f32 `gam:"round"`,
		friction:                f32 `gam:"round"`,
		lifetime:                f32 `gam:"round2"`,
		radius:                  f32 `gam:"round"`,
		sprite_factor_minus_one: f32 `gam:"round1"`,
		mass_mult_minus_one:     f32 `gam:"round1"`,
		absorbtion:              f32 `gam:"round"`,
		sprite:                  Asset_Ref,
		spin:                    f32 `gam:"round"`,
		body_damage:             f32 `gam:"round"`,
		bounce_multiplier:       f32 `gam:"round1"`,
		lifetime_multiplier:     f32 `gam:"round1"`,
		bounce_age_reduction:    f32 `gam:"round1"`,
	},
	using attack:     Ent_Stats_Attack,
	parry:            struct {
		invincibility: f32 `gam:"round1"`,
		duration:      f32,
		cooldown:      f32,
		attack:        Ent_Stats_Attack,
	},
	using turret:     struct {
		cannon:    Asset_Ref,
		aim_speed: f32 `gam:"round1"`,
		range:     f32 `gam:"round"`,
		reload:    f32 `gam:"round2"`,
	},
	using health:     struct {
		energy:         f32 `gam:"round"`,
		energy_drain:   f32 `gam:"round1"`,
		recharge_speed: f32 `gam:"round1"`,
		bind_range:     f32 `gam:"round"`,
	},
	trail:            struct {
		spacing:           f32 `gam:"round2"`,
		spawn_innaccuracy: f32 `gam:"round"`,
		quantity_per_tick: int,
		particle:          Particle_Stats,
	},
	explosion:        struct {
		radius:                      f32 `gam:"round"`,
		on_contact:                  bool,
		damage_multiplier_minus_one: f32 `gam:"round1"`,
		particle_quantity:           int,
		particle:                    Particle_Stats,
	},
}

add_asset :: proc(buf: ^[dynamic]Asset_ID, sprite: Asset_ID) -> Asset_Idx {
	for s, i in buf {
		if s == sprite {
			return Asset_Idx(i)
		}
	}

	append(buf, sprite)
	return Asset_Idx(len(buf) - 1)
}

simd_search :: proc(haistack: []$T, needle: T) -> int {
	LANES :: 16 / size_of(T)

	for i in 0 ..< len(haistack) / LANES {
		chunk := simd.from_slice(
			#simd[LANES]Asset_ID,
			haistack[i * LANES:][:LANES],
		)
		mask := simd.lanes_eq(chunk, (#simd[LANES]T)(needle))
		bits := transmute(u8)simd.extract_lsbs(mask)
		if bits == 0 do continue
		return i * LANES + int(simd.count_trailing_zeros(bits))
	}

	idx, _ := slice.linear_search(
		haistack[len(haistack) / LANES * LANES:],
		needle,
	)
	if idx < 0 do return -1
	return len(haistack) / LANES * LANES + idx
}

asset_id_to_idx :: proc(mapping: []Asset_ID, id: Asset_ID) -> Asset_Idx {
	return Asset_Idx(simd_search(mapping, id))
}

asset_idx_to_id :: proc(mapping: []Asset_ID, idx: Asset_Idx) -> Asset_ID {
	if idx < 0 || int(idx) >= len(mapping) do return 0
	return mapping[idx]
}

ents_apply_stat_multipliers :: proc(
	ents: ^Ents,
	eid: Ent_ID,
	off: uintptr,
) -> f32 {
	e := ents_get(ents, eid)
	s := ents_stats_get(ents, e.stats)
	base := (^f32)(uintptr(s) + off)^
	return(
		base +
		f32(e.counter) * base * s.bounce_multiplier +
		base * e.age * s.lifetime_multiplier \
	)
}

ents_radius :: proc(ents: ^Ents, eid: Ent_ID) -> f32 {
	e := ents_get(ents, eid)
	s := ents_stats_get(ents, e.stats)

	if s.kind == .Shell {
		return s.radius * (1 + (math.sin(e.age / s.lifetime * math.PI) * 2))
	}

	return ents_apply_stat_multipliers(ents, eid, offset_of(Ent_Stats, radius))
}

ents_damage :: proc(ents: ^Ents, eid: Ent_ID) -> f32 {
	vl := ents_apply_stat_multipliers(
		ents,
		eid,
		offset_of(Ent_Stats, body_damage),
	)

	e := ents_get(ents, eid)
	s := ents_stats_get(ents, e.stats)

	if s.kind == .Beam {
		vl *= ents.delta
	}

	return vl
}

Particle_Stats :: struct {
	one_minus_radius_ratio: f32 `gam:"round1"`,
	lifetime:               f32 `gam:"round2"`,
	end_color:              Color,
	end_radius_ratio:       f32 `gam:"round1"`,
	lifetime_variation:     f32 `gam:"round2"`,
}

Validation_Context :: struct {
	stat_count: int,
	id:         Ent_Stats_ID,
}

validate :: proc(val: any, ctx: Validation_Context) -> bool {
	switch &v in val {
	case f32, bool, int, Color, u8, Asset_Ref, nm.Name:
		return true
	case Ent_Stats_ID:
		return v == ctx.id
	case Ent_Stats_Ref:
		return 0 <= v.id && int(v.id) < ctx.stat_count
	}

	#partial switch info in type_info_of(reflect.typeid_base(val.id)).variant {
	case rt.Type_Info_Struct:
		for field in reflect.struct_fields_zipped(val.id) {
			value := reflect.struct_field_value(val, field)
			if !validate(value, ctx) do return false
		}
		return true
	case rt.Type_Info_Fixed_Capacity_Dynamic_Array:
		len := (^int)(uintptr(val.data) + info.len_offset)^
		if len > info.capacity {
			return false
		}

		i := 0
		for value, i in reflect.iterate_array(val, &i) {
			if !validate(value, ctx) do return false
		}

		return true
	case rt.Type_Info_Enum:
		if info.base.id != u8 {
			log.error("expected enum to be based on u8")
			return false
		}

		value := (^u8)(val.data)^

		for vl in info.values {
			if u8(vl) == value do return true
		}

		return false
	case:
		log.error("unhandled type for validation:", val.id)
		return false
	}
}

@(test)
test_validate :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator

	stat: Ent_Stats
	stat.name = nm.from_str("test")
	stat.placable = true

	validation_context: Validation_Context
	validation_context.stat_count = 1
	validation_context.id = 0

	assert(validate(stat, validation_context))
}

Field_Presence :: struct {
	bits:   packer.Bit_Set,
	cursor: int,
}

field_presence_init :: proc(ctx: ^Field_Presence, slot: []int) {
	ctx^ = {
		bits = {masks = raw_data(slot), bit_length = len(slot) * 64},
	}
}

field_presence_set :: proc(ctx: ^Field_Presence, value: bool) -> bool {
	if value do packer.bit_set_set(ctx.bits, ctx.cursor)
	ctx.cursor += 1
	return value
}

field_presence_get :: proc(ctx: ^Field_Presence) -> bool {
	defer ctx.cursor += 1
	return packer.bit_set_contains(ctx.bits, ctx.cursor)
}

@(test)
test_ent_stat_encode_decode :: proc(t: ^testing.T) {
	buf: [4096]u8

	stat: Ent_Stats
	stat.name = nm.from_str("test")
	stat.placable = true
	stat.speed = 10
	stat.sprite.id = 1
	stat.bullet.id = 2

	e := Encoder{buf[:]}
	assert(ent_stats_encode(stat, &e))

	stat = {}

	d := Decoder{buf[:]}
	assert(ent_stats_decode(&stat, 0, &d))

	testing.expect_value(t, nm.str(&stat.name), "test")
	testing.expect_value(t, stat.placable, true)
	testing.expect_value(t, stat.speed, 10)
}

Ent_Synced :: struct {
	stats:           Ent_Stats_ID,
	net_id:          Ent_Net_ID,
	parent_net_id:   Ent_Net_ID,
	pos:             Vec,
	vel:             Vec,
	age:             f32,
	reload:          f32,
	parry_progress:  f32,
	rot:             f32,
	team:            Ent_Team_ID,
	energy_consumed: f32,
	counter:         int,
}

Ent_Objective :: struct {
	cmd:       Client_Control_Cmd,
	pos:       Vec,
	commander: Ent_ID,
	gen:       u32,
}

Ent :: struct {
	id:            Ent_ID,
	queued_remove: bool,
	parried:       bool,
	using _:       struct #raw_union {
		next_queued_remove: ^Ent,
		next_free:          ^Ent,
	},
	parent:        Ent_ID,
	turret_rot:    f32,
	objective:     Ent_Objective,
	using synced:  Ent_Synced,
}

ent_reset :: proc(ent: ^Ent) {
	ent^ = {
		id        = {ent.id.gen + 1, ent.id.index},
		next_free = ent.next_free,
	}
}

ent_is_alive :: proc(ent: ^Ent) -> bool {
	return ent.id.gen % 2 == 1
}

@(rodata)
NIL_ENT_MEM := Ent{}
NIL_ENT := &NIL_ENT_MEM

Input_State :: struct {
	using inner: Client_Input,
	next_net_id: Ent_Net_ID,
}

PState :: struct {
	fuel:             f32,
	no_change_streak: u32,
	quad:             Quad_Ent,
	spatial:          Spatial_Ent,
	ent:              ^Ent,
}

Ents :: struct {
	slots:         []Ent,
	len:           int,
	pstate:        []PState,
	queued_remove: ^Ent,
	free:          ^Ent,
	delta:         f32,
	on_remove:     proc(_: ^Ents, _: ^Ent),
	on_laser:      proc(_: ^Ents, _: ^Ent),
	stats:         [dynamic]Ent_Stats,
	using mapa:    Map,
	spawn_seq:     ^Ent_Net_ID,
	quad_tree:     Quad_Tree,
	spatial_map:   Spatial_Map,
	buildings:     []u32,
}

team_spawnable :: proc(team: Ent_Team_ID, counts: []int) -> bool {
	if team < 0 || int(team) >= len(counts) do return false

	mi, ma := 999, 0
	for c in counts[min(len(counts), 1):] {
		mi = min(mi, c)
		ma = max(ma, c)
	}

	return team != 0 && (counts[team] != ma || ma == mi)
}

ents_is_authoritative :: proc(ents: ^Ents) -> bool {
	return ents.spawn_seq != nil
}

angle_of :: proc(v: Vec) -> f32 {
	return linalg.atan2(v.y, v.x)
}

vec_of :: proc(ang: f32) -> Vec {
	return {math.cos(ang), math.sin(ang)}
}

input_movement_dir :: proc(keys: Client_Input_Keys) -> Vec {
	dir := Vec{0, 0}

	if .Up in keys do dir += {0, -1}
	if .Down in keys do dir += {0, 1}
	if .Left in keys do dir += {-1, 0}
	if .Right in keys do dir += {1, 0}

	if dir != {} do dir = linalg.normalize(dir)

	return dir
}

ents_is_unwinding :: proc(ents: ^Ents, eid: Ent_ID) -> bool {
	e := ents_get(ents, eid)
	s := ents_stats_get(ents, e.stats)
	return e.reload > s.reload
}

ents_integrate_input :: proc(
	ents: ^Ents,
	e: Ent_ID,
	rtt: f32,
	input: ^Input_State,
) {
	e := ents_get(ents, e)
	if e == NIL_ENT do return

	s := ents_stats_get(ents, e.stats)

	e.vel += input_movement_dir(input.keys) * s.speed * ents.delta

	e.objective.pos = e.pos + input.relative_mouse_pos

	if !ents_is_unwinding(ents, e.id) && ents_is_authoritative(ents) {
		e.rot = angle_of(input.relative_mouse_pos)
	}

	ents_attack(
		ents,
		e.id,
		e.pos + input.relative_mouse_pos,
		.Click_Left in input.keys,
		rtt,
		&input.next_net_id,
	)

	ents_parry(
		ents,
		e.id,
		e.pos + input.relative_mouse_pos,
		.Click_Right in input.keys,
		rtt,
		&input.next_net_id,
	)
}

ents_attack_low :: proc(
	ents: ^Ents,
	e: Ent_ID,
	s: Ent_Stats_Attack,
	pos: Vec,
	next_net_id: ^Ent_Net_ID,
) {
	if s.bullet.id == 0 do return

	e := ents_get(ents, e)

	e.vel -= linalg.normalize(pos - e.pos) * s.recoil

	if next_net_id == nil do return

	if s.shots_per_reload_minus_one > e.counter {
		e.reload = s.shot_spacing
		e.counter += 1
	} else {
		e.counter = 0
	}

	state: rand.PCG_Random_State
	context.random_generator = rand.pcg_random_generator(&state)
	rt.random_generator_reset_u64(
		context.random_generator,
		transmute(u64)(next_net_id^),
	)

	for i in 0 ..< s.bullets_per_shot_minus_one + 1 {
		bs := ents_stats_get(ents, s.bullet.id)

		if bs.kind == .Laser && !ents_is_authoritative(ents) do return

		be := ents_add(ents, next_net_id)
		if be == NIL_ENT do break

		be.stats = s.bullet.id
		be.pos = e.pos
		be.team = e.team
		be.parent = e.id
		be.parent_net_id = e.net_id

		if bs.kind == .Shell {
			target :=
				e.pos +
				linalg.normalize(pos - e.pos) *
					min(bs.speed * bs.lifetime, linalg.distance(e.pos, pos))

			target +=
				vec_of(rand.float32() * math.TAU) *
				(math.tan(s.innaccuracy) * linalg.distance(e.pos, target))

			be.vel = (target - e.pos) / bs.lifetime
		} else {
			dir_offset :=
				s.spread * f32(i) -
				s.spread * f32(s.bullets_per_shot_minus_one) / 2

			dir :=
				angle_of(pos - e.pos) +
				rand.float32() * s.innaccuracy -
				s.innaccuracy / 2 +
				dir_offset

			be.vel = vec_of(dir) * bs.speed
		}
	}
}

ents_parry :: proc(
	ents: ^Ents,
	e: Ent_ID,
	pos: Vec,
	parrying: bool,
	rtt: f32,
	next_net_id: ^Ent_Net_ID,
) {
	e := ents_get(ents, e)
	s := ents_stats_get(ents, e.stats)

	if e.parry_progress < 0 && parrying {
		e.parry_progress =
			s.parry.cooldown +
			s.parry.duration +
			s.parry.attack.unwind +
			s.parry.invincibility
	}

	if step_crosses(
		e.parry_progress,
		ents.delta,
		s.parry.cooldown + s.parry.duration + s.parry.attack.unwind,
	) {
		e.parry_progress = s.parry.cooldown - ESP
	}

	if step_crosses(e.parry_progress, ents.delta, s.parry.cooldown) {
		e.parry_progress = -ESP
	}

	if e.parried {
		e.parried = false
		ents_attack_low(ents, e.id, s.parry.attack, pos, next_net_id)
	}
}

ents_attack :: proc(
	ents: ^Ents,
	e: Ent_ID,
	pos: Vec,
	shooting: bool,
	rtt: f32,
	next_net_id: ^Ent_Net_ID,
) {
	e := ents_get(ents, e)
	s := ents_stats_get(ents, e.stats)

	if e.reload < 0 && shooting {
		e.reload = s.reload + max(0, s.unwind - rtt)
	}

	if step_crosses(e.reload, ents.delta, s.reload) {
		ents_attack_low(ents, e.id, s.attack, pos, next_net_id)
	}
}

Laser_Iter :: struct {
	vel: Vec,
	pos: Vec,
	t:   f32,
}

laser_iter_next :: proc(
	iter: ^Laser_Iter,
	mapa: ^Map,
) -> (
	step: Vec,
	ok: bool,
) {
	if iter.t >= 1 do return

	tm, normal, new_tile := map_wall_collision(
		mapa,
		iter.pos,
		iter.vel * (1 - iter.t),
		true,
	)

	if tm == 0 do return

	step = iter.vel * tm * (1 - iter.t)
	iter.pos += step
	iter.pos = map_clamp_to_tile(iter.pos, new_tile)

	if tm != 1 {
		iter.vel *= normal
	}
	iter.t += tm

	ok = true
	return
}

ents_step :: proc(ents: ^Ents, e: ^Ent) {
	s := ents_stats_get(ents, e.stats)
	if s.kind not_in COLLIDES_WITH_OTHERS do return
	radius := ents_radius(ents, e.id)

	overscan := radius / linalg.length(e.vel)

	inv_v := 1.0 / e.vel

	step_x := int(math.sign(e.vel.x))
	step_y := int(math.sign(e.vel.y))

	tDelta := TILE_SIZE * linalg.abs(inv_v)

	tolerance: f32 = min(abs(tDelta.x), abs(tDelta.y))

	p1 := e.pos + linalg.orthogonal(linalg.normalize(e.vel) * radius)
	p2 := e.pos - linalg.orthogonal(linalg.normalize(e.vel) * radius)

	cursor1 := map_vec_to_pos(p1)
	cursor2 := map_vec_to_pos(p2)

	prevc1, prevc2: Map_Pos

	tile_min1 := linalg.floor(p1 * TILE_RECIPRO) * TILE_SIZE
	tile_max1 := tile_min1 + TILE_SIZE

	tile_min2 := linalg.floor(p2 * TILE_RECIPRO) * TILE_SIZE
	tile_max2 := tile_min2 + TILE_SIZE

	next_boundary1 := Vec {
		tile_max1.x if step_x >= 0 else tile_min1.x,
		tile_max1.y if step_y >= 0 else tile_min1.y,
	}
	next_boundary2 := Vec {
		tile_max2.x if step_x >= 0 else tile_min2.x,
		tile_max2.y if step_y >= 0 else tile_min2.y,
	}

	tMax1 := (next_boundary1 - p1) * inv_v
	tMax2 := (next_boundary2 - p2) * inv_v

	t1, t2: f32

	pstate := &ents.pstate[e.id.index]

	best_t := pstate.fuel
	best_normal := linalg.orthogonal(e.vel)

	for (t1 - tolerance - overscan <= best_t ||
		    t2 - tolerance - overscan <= best_t) &&
	    abs(step_x) + abs(step_y) != 0 {

		opts := [?]Map_Pos{cursor1, cursor2}
		for cursor in opts {
			if !map_tile_is_solid(ents, cursor) do continue

			tile_min := Vec{f32(cursor.x), f32(cursor.y)} * TILE_SIZE
			tile_max := tile_min + TILE_SIZE

			corners := [?]Vec {
				tile_min,
				{tile_max.x, tile_min.y},
				tile_max,
				{tile_min.x, tile_max.y},
			}

			for c in corners {
				t := circle_collision(c, e.pos, 0, e.vel, 0, radius)
				if 0 <= t && t < best_t {
					best_t = t
					best_normal = linalg.normalize0(e.pos - c)
				}
			}

			for b in ([?]Vec{tile_min, tile_max}) {
				d := b - e.pos

				tx := math.copy_sign(abs(d.x) - radius, d.x) * inv_v.x
				ty := math.copy_sign(abs(d.y) - radius, d.y) * inv_v.y

				projy := e.pos.y + tx * e.vel.y
				projx := e.pos.x + ty * e.vel.x

				inx := tile_min.y <= projy && projy < tile_max.y
				iny := tile_min.x <= projx && projx < tile_max.x

				if 0 <= tx && tx < best_t && inx {
					best_t = tx
					best_normal = {math.copy_sign(1.0, -e.vel.x), 0}
				}

				if 0 <= ty && ty < best_t && iny {
					best_t = ty
					best_normal = {0, math.copy_sign(1.0, -e.vel.y)}
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
	vel_estimate := e.vel * best_t
	movement_range := radius * 2 + linalg.length2(vel_estimate)
	iter := ents_query(ents, e.pos + vel_estimate / 2, movement_range)
	for oent in ents_query_next(&iter) {
		if oent == e do continue
		oradius := ents_radius(ents, oent.id)
		os := ents_stats_get(ents, oent.stats)
		if os.kind not_in COLLIDES_WITH_OTHERS do continue

		min_dist := radius + oradius
		if linalg.length2(e.pos - oent.pos) < min_dist * min_dist - 1 {
			continue
		}

		t := circle_collision(
			e.pos,
			oent.pos,
			e.vel,
			oent.vel,
			radius,
			oradius,
		)

		opstate := ents.pstate[oent.id.index]

		if ESP <= t && t < best_t && t <= opstate.fuel {
			ot, _, _ := map_wall_collision(ents, oent.pos, oent.vel * t)
			if ot != 1 do continue

			best_t = t
			collider = int(oent.id.index)
		}
	}

	e.pos += e.vel * best_t

	if collider >= 0 {
		ce := &ents.slots[collider]
		cpstate := &ents.pstate[ce.id.index]

		ce.pos += ce.vel * best_t
		cpstate.fuel -= best_t

		ents_trade_forces(ents, e, ce)
	} else {
		e.vel = linalg.reflect(e.vel, best_normal)
	}

	pstate.no_change_streak += u32(best_t < ESP)
	pstate.fuel -= best_t

	return
}

ents_trade_forces :: proc(ents: ^Ents, e: ^Ent, ce: ^Ent) {
	s := ents_stats_get(ents, e.stats)
	cs := ents_stats_get(ents, ce.stats)

	norm := linalg.normalize(ce.pos - e.pos)

	if s.kind == .Building {
		ce.vel = linalg.reflect(ce.vel, norm)
	} else if cs.kind == .Building {
		e.vel = linalg.reflect(e.vel, norm)
	} else {
		cradius := ents_radius(ents, ce.id)
		radius := ents_radius(ents, e.id)

		amass := radius * radius * math.PI * (1 + s.mass_mult_minus_one)
		bmass := cradius * cradius * math.PI * (1 + s.mass_mult_minus_one)

		p :=
			2.0 *
			(linalg.dot(e.vel, norm) - linalg.dot(ce.vel, norm)) /
			(amass + bmass)

		ap := p * bmass * (1 - s.absorbtion)
		bp := p * amass * (1 - cs.absorbtion)

		e.vel -= ap * norm
		ce.vel += bp * norm
	}

	ents_collision(ents, e, ce)
	ents_collision(ents, ce, e)
}

ents_move :: proc(ents: ^Ents, delta: f32) {
	worklist: queue.Queue(^Ent)
	{context.allocator = context.temp_allocator
		ents.quad_tree = {}
		spatial_map_init(&ents.spatial_map, ents.width, ents.height)
		ents.pstate = make([]PState, len(ents.slots))
		ents.buildings = make([]u32, ents.width * ents.height)
		queue.init(&worklist, len(ents.slots))

		config := Quad_Config {
			quad_size = i32(map_quad_size(&ents.mapa)),
		}

		index_iter := ents_iter(ents)
		for e in ents_iter_next(&index_iter) {
			s := ents_stats_get(ents, e.stats)
			if s.kind not_in COLLIDES_WITH_OTHERS do continue
			pstate := &ents.pstate[e.id.index]
			pstate^ = {
				fuel = delta,
				ent  = e,
			}

			radius := ents_radius(ents, e.id)
			pstate.quad.rect = quad_rect_square(e.pos, radius)
			quad_tree_add(&ents.quad_tree, &pstate.quad, config)
			pos := map_vec_to_pos(e.pos)
			spatial_map_insert(&ents.spatial_map, pos, &pstate.spatial)

			queue.append(&worklist, e)

			if s.kind == .Building {
				pos := map_vec_to_pos(e.pos)
				if pos.x < 0 || pos.x >= ents.width do continue
				if pos.y < 0 || pos.y >= ents.height do continue
				slot := &ents.buildings[pos.x + pos.y * ents.width]
				ents_queue_remove(ents, ents.slots[slot^].id)
				slot^ = e.id.index
			}
		}
	}

	for ent in queue.pop_front_safe(&worklist) {
		pstate := &ents.pstate[ent.id.index]
		if pstate.fuel <= ESP do continue
		mpos := map_vec_to_pos(ent.pos)
		if map_tile_is_solid(ents, mpos) do continue

		ents_step(ents, ent)

		if pstate.fuel > ESP && pstate.no_change_streak <= 1 {
			queue.append(&worklist, ent)
		}
	}

	OVERLAP_ELIM_ROUNDS :: 4

	for _ in 0 ..< OVERLAP_ELIM_ROUNDS {
		iter := ents_iter(ents)
		for e in ents_iter_next(&iter) {
			eliminate_overlap(ents, e)
		}
	}
}

eliminate_overlap :: proc(ents: ^Ents, e: ^Ent) {
	s := ents_stats_get(ents, e.stats)
	if s.kind not_in COLLIDES_WITH_OTHERS do return
	radius := ents_radius(ents, e.id)

	iter := ents_query(ents, e.pos, radius)
	for oent in ents_query_next(&iter) {
		if e == oent do continue
		os := ents_stats_get(ents, oent.stats)

		if os.kind not_in COLLIDES_WITH_OTHERS do continue

		oradius := ents_radius(ents, oent.id)

		min_dist := oradius + radius

		if linalg.length2(e.pos - oent.pos) > min_dist * min_dist {
			continue
		}

		normal: Vec
		if oent.pos == e.pos {
			normal = vec_of(f32((int(oent.id.index) << 32) | int(e.id.index)))
		} else {
			normal = linalg.normalize(oent.pos - e.pos)
		}

		contact_point := (oent.pos + e.pos) / 2

		if (radius > oradius || s.kind == .Building) && os.kind != .Building {
			oent.pos = e.pos + normal * (oradius + radius + DIST_ESP)
		} else {
			e.pos = oent.pos - normal * (radius + oradius + DIST_ESP)
		}

		//ents_trade_forces(ents, e, oent)
	}

	min_tile := map_vec_to_pos(e.pos - radius)
	max_tile := map_vec_to_pos(e.pos + radius)

	best_normal: Vec
	best_contact_point: Vec

	collide: for y in min_tile.y ..= max_tile.y {
		for x in min_tile.x ..= max_tile.x {
			normal, contact_point := map_tile_collide(
				ents,
				{x, y},
				e.pos,
				radius,
			)

			if linalg.length2(e.pos - contact_point) <
			   linalg.length2(e.pos - best_contact_point) {
				best_contact_point = contact_point
				best_normal = normal
			}
		}
	}

	if best_contact_point != {} {
		e.pos = best_contact_point + best_normal * (radius + DIST_ESP)
		e.vel = linalg.reflect(e.vel, best_normal)
	}

	tile := map_vec_to_pos(e.pos)

	if map_tile_is_solid(ents, tile) {
		tile := map_tile_find_empty(ents, tile)

		tile_min := Vec{f32(tile.x), f32(tile.y)} * TILE_SIZE
		tile_max := tile_min + TILE_SIZE

		e.pos = linalg.clamp(e.pos, tile_min + 1, tile_max - 1)
	}
}

ents_update :: proc(ents: ^Ents) {
	ents_move(ents, ents.delta)

	for &e in ents_iter(ents) {
		s := ents_stats_get(ents, e.stats)

		e.vel -= e.vel * ents.delta * s.friction
		if abs(e.vel.x) + abs(e.vel.y) < 0.1 do e.vel = {}
		e.age += ents.delta
		e.reload -= ents.delta
		e.parry_progress -= ents.delta
		e.parent_net_id = ents_get(ents, e.parent).net_id
		e.rot += ents.delta * s.spin
	}

	Coll :: struct {
		t:    f32,
		a, b: ^Ent,
	}

	update_iter := ents_iter(ents)
	for e in ents_iter_next(&update_iter) {
		s := ents_stats_get(ents, e.stats)
		sradius := ents_radius(ents, e.id)

		p := ents_get(ents, e.parent)
		ps := ents_stats_get(ents, p.stats)
		p_coff, _, _ := map_wall_collision(ents, e.pos, p.pos - e.pos)
		if (linalg.distance(p.pos, e.pos) > ps.bind_range || p_coff != 1) &&
		   s.kind in DRAWS_ENERGY {
			e.parent = {}
		}

		reconnect_iter := ents_query(ents, e.pos, s.bind_range)
		for oe in ents_query_next(&reconnect_iter) {
			os := ents_stats_get(ents, oe.stats)
			if oe.parent == {} && os.kind in AUTO_RECONNECT {
				oe_coff, _, _ := map_wall_collision(
					ents,
					e.pos,
					oe.pos - e.pos,
				)

				if linalg.distance(oe.pos, e.pos) < s.bind_range &&
				   e.team == oe.team &&
				   oe_coff == 1 {
					oe.parent = e.id
				}
			}
		}

		shoot: if s.range > 0 {
			best: Ent_ID
			target_iter := ents_query(ents, e.pos, s.range)
			for tar in ents_query_next(&target_iter) {
				star := ents_stats_get(ents, tar.stats)
				bt := ents_get(ents, best)
				st := ents_stats_get(ents, bt.stats)
				if tar.id == e.id do continue
				if tar.team == e.team do continue
				tm, _, _ := map_wall_collision(ents, e.pos, tar.pos - e.pos)
				if tm != 1 do continue
				tdist := linalg.distance(tar.pos, e.pos)
				if tdist > s.range do continue
				bdist := linalg.distance(bt.pos, e.pos)
				if bt.pos == {} ||
				   ((bdist > tdist && st.kind == star.kind) ||
						   star.kind in TARGETABLE) {
					best = tar.id
				}
			}

			t := ents_get(ents, best)
			if t == NIL_ENT do break shoot

			bs := ents_stats_get(ents, s.bullet.id)
			pred_target := predict_target(e.pos, t.pos, t.vel, bs.speed)
			dir := angle_of(pred_target - e.pos)

			e.turret_rot = move_towards_angle(
				e.turret_rot,
				dir,
				s.aim_speed * ents.delta,
			)
			e.turret_rot = normalize_angle(e.turret_rot)

			ents_attack(
				ents,
				e.id,
				pred_target,
				abs(e.turret_rot - dir) < 0.1,
				0,
				ents.spawn_seq,
			)
		}

		su := ents_stats_get(ents, s.spawn_unit.id)
		suradius := su.radius
		spawn: if su != NIL_STATS {
			if e.energy_consumed > 0 do break spawn

			ne := ents_add(ents, ents.spawn_seq)
			if ne == NIL_ENT do break spawn

			e.energy_consumed += su.energy
			ne.pos = e.pos
			ne.vel =
				vec_of(math.PI * 2 * rand.float32()) * (sradius + suradius) * 2
			ne.stats = s.spawn_unit.id
			ne.parent_net_id = e.net_id
			ne.parent = e.id
			ne.team = e.team
		}

		follow_objective: if e.objective.gen != 0 {
			ce := ents_get(ents, e.objective.commander)
			if ce.objective.gen != e.objective.gen {
				break follow_objective
			}

			switch e.objective.cmd {
			case .Move:
				e.vel +=
					linalg.normalize(e.objective.pos - e.pos) *
					min(
						s.speed * ents.delta,
						linalg.distance(e.objective.pos, e.pos),
					)

				facing := angle_of(e.objective.pos - e.pos)

				e.rot = move_towards_angle(
					e.rot,
					facing,
					s.aim_speed * ents.delta,
				)

				if linalg.distance(e.objective.pos, e.pos) < 100 {
					e.objective = {}
				}
			case .Attack:
				panic("TODO")
			}
		}

		if s.kind == .Laser {
			liter: Laser_Iter
			liter.pos = e.pos
			liter.vel = e.vel

			ents_queue_remove(ents, e.id)

			ents->on_laser(e)

			for step in laser_iter_next(&liter, &ents.mapa) {
				lcenter := liter.pos - step / 2
				lradius := linalg.length(step) / 2

				q := ents_query(ents, lcenter, lradius)
				for oe in ents_query_next(&q) {
					os := ents_stats_get(ents, oe.stats)
					oradius := ents_radius(ents, oe.id)
					if oe.team == e.team do continue

					collided := circle_line_collision(
						oe.pos,
						oradius,
						liter.pos,
						liter.pos - step,
					)
					if !collided do continue

					ents_collision(ents, e, oe)
				}
			}
		}

		if s.kind == .Beam {
			step := vec_of(p.rot) * s.speed

			col, t := ents_find_beam_collider(ents, e.team, p.pos, step)
			ents_collision(ents, e, col)
			e.pos = p.pos + step * t
		}

		if s.kind == .Rocket && p != NIL_ENT {
			target := p.objective.pos
			e.vel +=
				linalg.normalize0(target - e.pos) * ps.speed * ents.delta * 2
			e.vel =
				linalg.normalize(e.vel) *
				max(linalg.length(e.vel), ps.speed / 2)
		}

		if s.lifetime > 0 && e.age > s.lifetime {
			ents_queue_remove(ents, e.id)
		}
	}

	flow_energy: if ents_is_authoritative(ents) {
		context.allocator = context.temp_allocator

		Energy_Extra :: struct {
			depth: int,
			group: int,
		}

		Group :: struct {
			energy_drain: f32,
			root:         ^Ent,
		}

		groups: [dynamic]Group
		append(&groups, Group{0, NIL_ENT})
		extra := make([]Energy_Extra, ents.len)
		seen := packer.bit_set_init(ents.len)

		gather_iter := ents_iter(ents)
		for e in ents_iter_next(&gather_iter) {
			if packer.bit_set_contains(seen, e.id.index) do continue

			group: Group

			depth := 0
			cursor := e
			for cursor != NIL_ENT {
				group.root = cursor
				depth += 1
				if packer.bit_set_contains(seen, cursor.id.index) do break
				packer.bit_set_set(seen, cursor.id.index)
				stats := ents_stats_get(ents, cursor.stats)
				group.energy_drain += stats.energy_drain
				if cursor.energy_consumed > 0 &&
				   ents_get(ents, cursor.parent) != NIL_ENT {

					group.energy_drain += stats.recharge_speed
				}
				cursor = ents_get(ents, cursor.parent)
			}

			if extra[group.root.id.index].group == 0 {
				extra[group.root.id.index].group = len(groups)
				append(&groups, group)
			} else {
				depth += extra[group.root.id.index].depth
				groups[extra[group.root.id.index].group].energy_drain +=
					group.energy_drain
			}

			cursor = e
			for cursor != group.root {
				depth -= 1
				extra[cursor.id.index] = Energy_Extra {
					depth,
					extra[group.root.id.index].group,
				}
				cursor = ents_get(ents, cursor.parent)
			}
		}

		ptrs := make([]u32, ents.len)
		for i in 0 ..< len(ptrs) do ptrs[i] = u32(i)

		{
			context.user_ptr = &extra
			sort.quick_sort_proc(ptrs, compare_energy_priority)
		}

		compare_energy_priority :: proc(a: u32, b: u32) -> int {
			extra := (^[]Energy_Extra)(context.user_ptr)^
			group_cmp := sort.compare_ints(extra[a].group, extra[b].group)
			if group_cmp != 0 do return group_cmp

			// NOTE: we specifically want to shift the core to have the lowest
			// priority
			depth_cmp := sort.compare_u32s(
				u32(extra[a].depth) - 1,
				u32(extra[b].depth) - 1,
			)
			if depth_cmp != 0 do return depth_cmp

			return sort.compare_u32s(a, b)
		}

		#reverse for ptr in ptrs {
			ex := extra[ptr]
			group := &groups[ex.group]
			root := group.root
			e := &ents.slots[ptr]

			if group.energy_drain < 0 do continue

			consumption: f32
			if root == e {
				consumption = group.energy_drain
			} else {
				consumption = group.energy_drain * 0.5
			}

			group.energy_drain -= consumption
			e.energy_consumed += consumption * ents.delta
		}

		for ptr in ptrs {
			ex := extra[ptr]
			group := &groups[ex.group]
			e := &ents.slots[ptr]
			s := ents_stats_get(ents, e.stats)

			if group.energy_drain >= 0 do continue

			recharge := min(s.recharge_speed, -group.energy_drain)
			frame_recharge := min(recharge * ents.delta, e.energy_consumed)
			group.energy_drain +=
				recharge -
				(recharge * ents.delta - frame_recharge) / ents.delta
			e.energy_consumed -= frame_recharge
		}

		apply_recharge_iter := ents_iter(ents)
		for e in ents_iter_next(&apply_recharge_iter) {
			s := ents_stats_get(ents, e.stats)
			extra := extra[e.id.index]
			group := &groups[extra.group]

			if e.energy_consumed > 0 && e != group.root {
				e.energy_consumed -= s.recharge_speed * ents.delta
				e.energy_consumed = max(e.energy_consumed, 0)
			}

			if s.energy > 0 && e.energy_consumed > s.energy {
				ents_queue_remove(ents, e.id)
			}
		}
	}

	for e in ents_remove_next(ents) {
		s := ents_stats_get(ents, e.stats)

		if s.explosion.radius > 0 {
			hit_iter := ents_query(ents, e.pos, s.explosion.radius)
			for oe in ents_query_next(&hit_iter) {
				min_dist := ents_radius(ents, oe.id) + s.explosion.radius
				if linalg.length2(e.pos - oe.pos) > min_dist * min_dist do continue

				ents_collision(
					ents,
					e,
					oe,
					1 + s.explosion.damage_multiplier_minus_one,
				)
			}
		}

		if ents.on_remove != nil do ents->on_remove(e)

		ent_reset(e)
	}
}

ents_find_beam_collider :: proc(
	ents: ^Ents,
	team: Ent_Team_ID,
	pos: Vec,
	step: Vec,
) -> (
	ent: ^Ent = NIL_ENT,
	t: f32,
) {
	t, _, _ = map_wall_collision(&ents.mapa, pos, step)

	lcenter := pos + step * t / 2
	lradius := linalg.length(step * t) / 2

	query := ents_query(ents, lcenter, lradius)
	for e in ents_query_next(&query) {
		s := ents_stats_get(ents, e.stats)
		if e.team == team do continue

		it, collided := circle_line_intersection(
			e.pos,
			s.radius,
			pos,
			pos + step,
		)
		if !collided do continue
		if it > t do continue
		t = it
		ent = e
	}

	return
}

ents_collision :: proc(
	ents: ^Ents,
	e: ^Ent,
	target: ^Ent,
	damage_mult: f32 = 1,
) {
	if target == NIL_ENT do return

	s := ents_stats_get(ents, e.stats)
	ts := ents_stats_get(ents, target.stats)

	apply_damage: {
		sbody_damage := ents_damage(ents, e.id) * damage_mult
		if sbody_damage == 0 do break apply_damage
		if e.team == target.team do break apply_damage

		if target.parry_progress >
		   ts.parry.cooldown + ts.parry.duration + ts.parry.attack.unwind {
			target.parry_progress =
				ts.parry.cooldown +
				ts.parry.duration +
				ts.parry.attack.unwind -
				ESP
			e.team = target.team
			target.parried = true

			break apply_damage
		}

		if ents_is_authoritative(ents) {
			target.energy_consumed += sbody_damage
		}

		if s.explosion.on_contact {
			ents_queue_remove(ents, e.id)
		}
	}
}

Ents_Query :: union #no_nil {
	Quad_Iter,
	Spatial_Iter,
}

ents_query :: proc(ents: ^Ents, pos: Vec, radius: f32) -> Ents_Query {
	context.allocator = context.temp_allocator

	if radius <= TILE_SIZE {
		return Spatial_Iter {
			mapa = &ents.spatial_map,
			pos = map_vec_to_pos(pos),
		}
	}

	config := Quad_Config {
		quad_size = i32(map_quad_size(&ents.mapa)),
	}

	return quad_iter(&ents.quad_tree, quad_rect_square(pos, radius), config)
}

ents_query_next :: proc(query: ^Ents_Query) -> (e: ^Ent, ok: bool) {
	switch &q in query^ {
	case Quad_Iter:
		ent := quad_iter_next(&q) or_return
		return (^PState)(uintptr(ent) - offset_of(PState, quad)).ent, true
	case Spatial_Iter:
		ent := spatial_iter_next(&q) or_return
		return (^PState)(uintptr(ent) - offset_of(PState, spatial)).ent, true
	case:
		return nil, false
	}
}

ents_iter :: proc(ents: ^Ents) -> []Ent {
	return ents.slots[1:ents.len]
}

ents_iter_next :: proc(iter: ^[]Ent) -> (^Ent, bool) {
	for {
		if len(iter) == 0 do return nil, false
		defer iter^ = iter[1:]
		if ent_is_alive(&iter[0]) do return &iter[0], true
	}
}

dummy_teams := [2]Ent_Team{{color = 0xFF0000FF}, {color = 0x00FF00FF}}

ents_reserve :: proc(ents: ^Ents, capacity: int) {
	err: rt.Allocator_Error
	ents.slots, err = make([]Ent, capacity)
	log.assertf(err == nil, "failed to allocate ents slots: %v", err)
	ents.len += 1
}

ents_destroy :: proc(ents: ^Ents) {
	delete(ents.slots)
	delete(ents.stats)
}

ents_clear :: proc(ents: ^Ents) {
	remove_iter := ents_iter(ents)
	for e in ents_iter_next(&remove_iter) {
		e.next_free = ents.free
		ents.free = e
		ent_reset(e)
	}
	ents.mapa = {}
}

ents_add :: proc(ents: ^Ents, net_id: ^Ent_Net_ID) -> ^Ent {
	if net_id == nil do return NIL_ENT

	slot := ents.free

	if slot == nil {
		if len(ents.slots) == ents.len do return NIL_ENT

		// NOTE: we assume initial zeroed out state
		slot = &ents.slots[ents.len]
		slot^ = {
			id = {index = u32(ents.len)},
		}
		ents.len += 1
	}

	ents.free = slot.next_free

	net_id.seq += 1
	slot^ = {
		id     = slot.id,
		net_id = net_id^,
	}
	slot.id.gen += 1

	assert(ent_is_alive(slot))

	return slot
}

ents_queue_remove :: proc(
	ents: ^Ents,
	id: Ent_ID,
	loc := #caller_location,
) -> bool {
	e := ents_get(ents, id)
	if e != NIL_ENT && !e.queued_remove {
		e.next_queued_remove = ents.queued_remove
		ents.queued_remove = e
		e.queued_remove = true
	}
	return e != NIL_ENT
}

ents_remove_next :: proc(ents: ^Ents) -> (res: ^Ent, ok: bool) {
	res = ents.queued_remove
	ok = res != nil
	if ok {
		ents.queued_remove = res.next_queued_remove
		res.next_free = ents.free
		ents.free = res
	}
	return
}

ents_get :: proc(ents: ^Ents, id: Ent_ID) -> ^Ent {
	if ents.slots[id.index].id.gen != id.gen ||
	   id.index == 0 ||
	   id.gen % 2 == 0 {
		return NIL_ENT
	}
	return &ents.slots[id.index]
}

ents_building_get :: proc(ents: ^Ents, pos: Map_Pos) -> ^Ent {
	if pos.x < 0 || pos.x >= ents.width do return NIL_ENT
	if pos.y < 0 || pos.y >= ents.height do return NIL_ENT
	slot := ents.buildings[pos.x + pos.y * ents.width]
	if slot == 0 do return NIL_ENT
	return &ents.slots[slot]
}

ents_is_valid :: proc(ents: ^Ents, id: Ent_ID) -> bool {
	return ents_get(ents, id) != NIL_ENT
}

ents_stats_get :: proc(ents: ^Ents, id: Ent_Stats_ID) -> ^Ent_Stats {
	if id <= 0 || int(id) >= len(ents.stats) do return NIL_STATS
	return &ents.stats[id]
}

ents_team_get :: proc(ents: ^Ents, id: Ent_Team_ID) -> ^Ent_Team {
	if id <= 0 || int(id) >= len(ents.teams) do return NIL_TEAM
	return &ents.teams[id]
}

move_towards_angle :: proc(from: f32, to: f32, max_step: f32) -> f32 {
	delta := to - from
	delta += math.PI
	for delta > math.TAU do delta -= math.TAU
	for delta < 0 do delta += math.TAU
	delta -= math.PI
	delta = math.clamp(delta, -max_step, max_step)
	return from + delta
}

normalize_angle :: proc(angle: f32) -> f32 {
	return move_towards_angle(0, angle, math.PI)
}

clamp_vec_to_radius :: proc(v: Vec, radius: f32) -> Vec {
	return linalg.normalize(v) * min(linalg.length(v), radius)
}

circle_line_collision :: proc(
	center: Vec,
	radius: f32,
	line_start, line_end: Vec,
) -> bool {
	d := line_start - line_end
	if abs(d.x) + abs(d.y) <= math.F32_EPSILON {
		return linalg.length2(line_start - center) < radius * radius
	}
	dotp :=
		linalg.dot(center - line_start, line_end - line_start) /
		linalg.length2(d)
	dotp = clamp(dotp, 0, 1)
	closest := line_start - dotp * d
	distance2 := linalg.length2(closest - center)
	return distance2 <= radius * radius
}

predict_target :: proc(
	turret: Vec,
	target: Vec,
	target_vel: Vec,
	bullet_speed: f32,
) -> Vec {
	rel := target - turret
	a := linalg.dot(target_vel, target_vel) - bullet_speed * bullet_speed
	if a == 0 do return target
	b := 2 * linalg.dot(target_vel, rel)
	c := linalg.dot(rel, rel)
	d := b * b - 4 * a * c
	if d < 0 do return {}
	t := (-b - math.sqrt(d)) / (2 * a)
	return target + target_vel * t
}

circle_collision :: proc(
	ap: Vec,
	bp: Vec,
	av: Vec,
	bv: Vec,
	ar: f32,
	br: f32,
) -> f32 {
	radius_sum := ar + br

	d := ap - bp
	dv := av - bv

	a := linalg.dot(dv, dv)
	b := 2 * linalg.dot(dv, d)
	c := linalg.dot(d, d) - radius_sum * radius_sum

	disc := b * b - 4 * a * c

	if disc <= 0 do return math.inf_f32(-1)

	t1 := (-b + math.sqrt(disc)) / (2 * a)
	t2 := (-b - math.sqrt(disc)) / (2 * a)
	t := t1 < 0 ? t2 : t2 < 0 ? t1 : min(t1, t2)

	return t
}

circle_line_intersection :: proc(
	center: Vec,
	radius: f32,
	line_start, line_end: Vec,
) -> (
	t: f32,
	ok: bool,
) {
	d := line_end - line_start
	f := line_start - center

	a := linalg.dot(d, d)
	b := 2 * linalg.dot(f, d)
	c := linalg.dot(f, f) - radius * radius

	if a <= math.F32_EPSILON {
		if abs(c) <= math.F32_EPSILON {
			return 0, true
		}
		return {}, false
	}

	discriminant := b * b - 4 * a * c
	if discriminant < 0 {
		return {}, false
	}

	sqrt_disc := math.sqrt(discriminant)
	t1 := (-b - sqrt_disc) / (2 * a)
	t2 := (-b + sqrt_disc) / (2 * a)

	if t1 >= 0 && t1 <= 1 {
		return t1, true
	}
	if t2 >= 0 && t2 <= 1 {
		return t2, true
	}

	return {}, false
}

TRACK_ALLOCATIONS :: #config(TRACK_ALLOCATIONS, false)

tracking_allocator_destroy :: proc(track: ^mem.Tracking_Allocator) {
	if len(track.allocation_map) > 0 {
		fmt.eprintf(
			"=== %v allocations not freed: ===\n",
			len(track.allocation_map),
		)
		for _, entry in track.allocation_map {
			fmt.eprintf("- %v bytes @ %v\n", entry.size, entry.location)
		}
	}
	if len(track.bad_free_array) > 0 {
		fmt.eprintf("=== %v incorrect frees: ===\n", len(track.bad_free_array))
		for entry in track.bad_free_array {
			fmt.eprintf("- %p @ %v\n", entry.memory, entry.location)
		}
	}
	mem.tracking_allocator_destroy(track)
}

user_fmt_handlers: map[typeid]fmt.User_Formatter

register_user_formatters :: proc() {
	fmt.set_user_formatters(&user_fmt_handlers)

	fmt.register_user_formatter(
		Identity,
		proc(info: ^fmt.Info, ty: any, verb: rune) -> bool {
			_, err := io.write_full(
				info.writer,
				transmute([]u8)b58.encode((^Identity)(ty.data)[:]),
			)
			return err == nil
		},
	)
	fmt.register_user_formatter(
		Hash,
		proc(info: ^fmt.Info, ty: any, verb: rune) -> bool {
			_, err := io.write_full(
				info.writer,
				transmute([]u8)b58.encode((^Hash)(ty.data)[:]),
			)
			return err == nil
		},
	)
	fmt.register_user_formatter(
		Player_Name,
		proc(info: ^fmt.Info, ty: any, verb: rune) -> bool {
			_, err := io.write_full(
				info.writer,
				nm.bytes((^Player_Name)(ty.data)),
			)
			return err == nil
		},
	)
}

unregister_user_formatters :: proc() {
	delete(user_fmt_handlers)
	user_fmt_handlers = nil
}

step_crosses :: proc(vl: f32, step: f32, boundary: f32) -> bool {
	return vl - step < boundary && boundary <= vl
}
