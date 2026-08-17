package client

import "../sim"
import "../simt/nbio"
import "../util/arna"
import "../util/hot"
import "../util/packer"
import "../util/sqlite"
import orui "../vendored/orui/src"
import "base:runtime"
import "core:fmt"
import "core:log"
import "core:math"
import "core:math/linalg"
import "core:math/rand"
import "core:os"
import "core:reflect" // marked
import "core:slice"
import "core:strings"
import "core:sync"
import "core:sync/chan"
import "core:thread"
import "core:time"
import "pure"
import rl "vendor:raylib"

MAX_PARTICLES :: 512
HANDSHAKE_STAGE_TIMEOUT :: 500 * time.Millisecond
// TODO(low): compress this
FONT_DATA :: #load("../assets/font.ttf")
FONT_MEDIUM_SIZE :: 16
APP_NAME :: "gam"

PLACEMENT_BUTTON_RADIUS :: 20

font_medium: rl.Font

get_color :: #force_inline proc(color: sim.Color) -> rl.Color {
	return rl.GetColor(auto_cast color)
}

Particle :: struct {
	pos:         sim.Vec,
	vel:         sim.Vec,
	age:         f32,
	color:       rl.Color,
	radius:      f32,
	using stats: sim.Particle_Stats,
}

Particles :: pure.Retained_Array(Particle)

Client :: struct {
	using pure:            pure.Client,
	camera:                rl.Camera2D,
	using ui:              UI_Reactor,
	particles:             Particles,
	input_display_texture: rl.RenderTexture2D,
}

client_mouse_pos :: proc(client: ^Client) -> sim.Vec {
	return rl.GetScreenToWorld2D(rl.GetMousePosition(), client.camera)
}

invert_color :: proc(color: rl.Color) -> rl.Color {
	return {0xff - color.r, 0xff - color.g, 0xff - color.a, 0xff}
}

client_selection_rect :: proc(client: ^Client) -> rl.Rectangle {
	if client.ui.control_selection_pivot == {} do return {}

	mouse_pos := client_mouse_pos(client)
	area_min := linalg.min(client.ui.control_selection_pivot, mouse_pos)
	area_max :=
		linalg.max(client.ui.control_selection_pivot, mouse_pos) - area_min
	return {area_min.x, area_min.y, area_max.x, area_max.y}
}

client_query_rect :: proc(
	client: ^Client,
	rect: rl.Rectangle,
) -> sim.Ents_Query {
	center := (sim.Vec{rect.x, rect.y} + {rect.width, rect.height}) / 2
	radius := max(rect.width, rect.height) / 2
	return sim.ents_query(&client.ents, center, radius)
}

client_limit_place_position :: proc(
	client: ^Client,
	radius: f32,
	source: sim.Vec,
	dest: sim.Vec,
) -> (
	target_pos: sim.Vec,
) {
	rel_pos := dest - source
	target_pos = source + sim.clamp_vec_to_radius(rel_pos, radius - 1)
	coll_coff, _, tile := sim.map_wall_collision(
		&client.ents,
		source,
		target_pos - source,
	)
	target_pos = source + (target_pos - source) * coll_coff
	target_pos = sim.map_clamp_to_tile(target_pos, tile)

	return
}

client_draw_input :: proc(client: ^Client) {
	input := client.current_input

	mouse_pos := client_mouse_pos(client)

	he := client_find_hovered_building(client, mouse_pos)
	hs := sim.ents_stats_get(&client.ents, he.stats)
	hsradius := sim.ents_radius(&client.ents, he.id)
	ht := sim.ents_team_get(&client.ents, he.team)

	se := sim.ents_get(&client.ents, client.bs.src_building)
	ss := sim.ents_stats_get(&client.ents, se.stats)
	ssradius := sim.ents_radius(&client.ents, se.id)
	st := sim.ents_team_get(&client.ents, se.team)

	de := sim.ents_get(&client.ents, client.bs.dst_building)
	ds := sim.ents_stats_get(&client.ents, de.stats)
	dsradius := sim.ents_radius(&client.ents, de.id)
	dt := sim.ents_team_get(&client.ents, de.team)

	{
		if client.input_display_texture.texture.width != rl.GetScreenWidth() ||
		   client.input_display_texture.texture.height !=
			   rl.GetScreenHeight() {
			rl.UnloadRenderTexture(client.input_display_texture)
			client.input_display_texture = rl.LoadRenderTexture(
				rl.GetScreenWidth(),
				rl.GetScreenHeight(),
			)
		}

		rl.BeginTextureMode(client.input_display_texture)
		rl.ClearBackground(rl.BLANK)
		rl.BeginMode2D(client.camera)

		color := get_color(st.color)

		if he != sim.NIL_ENT && se == sim.NIL_ENT {
			rl.DrawRectangleRec(
				square(he.pos, hsradius * 0.6),
				get_color(ht.color),
			)
		}

		if !has_valid_bs(client) {
			color = invert_color(color)
		}

		if se != sim.NIL_ENT {
			rl.DrawRectangleRec(square(se.pos, ssradius * 0.8), color)

			THICKNESS :: 5

			pos := mouse_pos

			if de != sim.NIL_ENT {
				rl.DrawRectangleRec(square(de.pos, dsradius * 0.8), color)
				pos = de.pos
			} else if ps, ok := client.bs.place_pos.?; ok {
				pos = sim.map_pos_to_vec(ps)
				rl.DrawRectangleRec(map_tile_rect(ps), color)
			} else {
				pos = snap_to_tile(pos)
				rl.DrawRectangleRec(square(pos, 32), color)
			}

			pos = snap_to_tile(pos)

			rl.DrawLineEx(pos, se.pos, THICKNESS, color)
		}

		square :: proc(pos: sim.Vec, radius: f32) -> rl.Rectangle {
			return {pos.x - radius, pos.y - radius, radius * 2, radius * 2}
		}

		rl.EndMode2D()
		rl.EndTextureMode()

		rl.DrawTextureRec(
			client.input_display_texture.texture,
			{0, 0, f32(rl.GetScreenWidth()), f32(-rl.GetScreenHeight())},
			{},
			rl.ColorAlpha(rl.WHITE, 0.8),
		)
	}
}

client_compute_input :: proc(client: ^Client) {
	if client.connection_stage != .Connected do return

	prev_input := client.current_input
	input := &client.current_input
	input.inner = {
		seq = input.seq + 1,
	}

	ui := &client.ui
	mouse_pos := client_mouse_pos(client)

	if is_key_down(ui, .Up) do input.keys |= {.Up}
	if is_key_down(ui, .Down) do input.keys |= {.Down}
	if is_key_down(ui, .Left) do input.keys |= {.Left}
	if is_key_down(ui, .Right) do input.keys |= {.Right}

	if is_key_down(ui, .Shoot) do input.keys |= {.Shoot}
	if is_key_down(ui, .Parry) do input.keys |= {.Parry}
	if is_key_down(ui, .Dash) do input.keys |= {.Dash}

	input.relative_mouse_pos =
		mouse_pos - sim.ents_get(&client.ents, client.ent).pos

	if prev_input.inner.state != client.current_input.inner.state {
		pure.udp_send(client, client.current_input.inner)
		client.current_input.inner.seq += 1
	}
}

ui_build_selection_update :: proc(client: ^Client) {
	ui := &client.ui
	mouse_pos := client_mouse_pos(client)

	e := sim.ents_get(&client.ents, client.ent)
	s := sim.ents_stats_get(&client.ents, e.stats)
	t := sim.ents_team_get(&client.ents, e.team)

	he := client_find_hovered_building(client, mouse_pos)
	he_is_friendly := he.team == e.team || client.map_editing.expanded

	se := sim.ents_get(&client.ents, client.bs.src_building)
	de := sim.ents_get(&client.ents, client.bs.dst_building)

	if is_key_pressed(ui, .Build_Select_Start) {
		if he != se &&
		   (he_is_friendly || he == sim.NIL_ENT) &&
		   client.bs.place_pos == nil {
			append(&client.captured_key_binds, MousetButton.LEFT)
			client.bs.src_building = he.id
		}
	}

	select_dst: if is_key_released(ui, .Build_Select_End) {
		if has_valid_bs(client) {
			if he_is_friendly {
				if se != sim.NIL_ENT && he != sim.NIL_ENT {
					client.bs.dst_building = he.id
					break select_dst
				}
			}

			tile := sim.map_vec_to_pos(mouse_pos)
			stile := sim.map_vec_to_pos(se.pos)

			if se != sim.NIL_ENT &&
			   de == sim.NIL_ENT &&
			   tile != stile &&
			   !sim.map_tile_is_solid(&client.ents, tile) &&
			   client.bs.place_pos == nil {
				client.bs.place_pos = tile
				break select_dst
			}
		}

		client.bs = {}
	}

	if is_key_pressed(ui, .Build_Select_Clear) {
		if se != sim.NIL_ENT {
			append(&client.captured_key_binds, MousetButton.RIGHT)
			client.bs = {}
		}
	}
}

has_valid_bs :: proc(client: ^Client) -> bool {
	if sim.ents_is_valid(&client.ents, client.bs.dst_building) ||
	   client.bs.place_pos != nil {return true}

	se := sim.ents_get(&client.ents, client.bs.src_building)
	ss := sim.ents_stats_get(&client.ents, se.stats)

	pos := client_mouse_pos(client)
	tile := sim.map_vec_to_pos(pos)
	snapped_pos := sim.map_pos_to_vec(tile)

	if !sim.can_connect(&client.ents, se.id, snapped_pos) do return false

	be := sim.ents_building_get(&client.ents, tile)

	if sim.ent_is_alive(be) && be.team != se.team do return false

	return true
}

client_handle_playable_ent :: proc(client: ^Client, e: ^sim.Ent) {
	assert(e != sim.NIL_ENT)

	mouse_pos := client_mouse_pos(client)
	s := sim.ents_stats_get(&client.ents, e.stats)
	sradius := sim.ents_radius(&client.ents, e.id)

	x := pure.client_ent_extra_get(client, e.id)
	pos := e.pos + x.pos_smoothing

	rl.DrawCircleLinesV(pos, sradius + 5, rl.RED)

	target_pos := client_limit_place_position(
		client,
		s.bind_range,
		pos,
		mouse_pos,
	)

	he := client_find_hovered_ent(client, mouse_pos)
	hs := sim.ents_stats_get(&client.ents, he.stats)
	hsradius := sim.ents_radius(&client.ents, he.id)
	hx := pure.client_ent_extra_get(client, he.id)
	hpos := he.pos + hx.pos_smoothing

	if linalg.distance(hpos, mouse_pos) < hsradius &&
	   linalg.distance(e.pos, he.pos) <= s.bind_range {
		target_pos = he.pos
	}
}

client_find_hovered_building :: proc(
	client: ^Client,
	pos: sim.Vec,
) -> (
	b: ^sim.Ent,
) {
	tile := sim.map_vec_to_pos(pos)
	b = sim.ents_building_get(&client.ents, tile)

	if b == sim.NIL_ENT {
		query := sim.ents_query(&client.ents, pos, 0)
		for e in sim.ents_query_next(&query) {
			s := sim.ents_stats_get(&client.ents, e.stats)
			if linalg.distance(e.pos, pos) < s.radius {
				return e
			}
		}
	}

	return
}

client_find_hovered_ent :: proc(client: ^Client, pos: sim.Vec) -> ^sim.Ent {
	hover_iter := sim.ents_query(&client.ents, pos, 0)
	for e in sim.ents_query_next(&hover_iter) {
		s := sim.ents_stats_get(&client.ents, e.stats)
		sradius := sim.ents_radius(&client.ents, e.id)
		x := pure.client_ent_extra_get(client, e.id)
		if linalg.distance(e.pos + x.pos_smoothing, pos) <= sradius {
			return e
		}
	}

	return sim.NIL_ENT
}

client_on_remove :: proc(ents: ^sim.Ents, e: ^sim.Ent) {
	client := (^Client)(uintptr(ents) - offset_of(Client, ents))
	s := sim.ents_stats_get(ents, e.stats)

	if s.explosion.radius > 0 {
		p := pure.retained_add(&client.particles)
		if p != nil {
			p.pos = e.pos
			p.radius = s.explosion.radius
			p.color = client_ent_color(client, e.id)
			p.stats.lifetime = 0.3
		}

		for _ in 0 ..< s.explosion.particle_quantity {
			p := pure.retained_add(&client.particles)
			if p == nil do break

			p.pos =
				e.pos +
				sim.vec_of(rand.float32() * math.TAU) *
					rand.float32() *
					s.explosion.radius
			p.radius =
				(1 - s.explosion.particle.one_minus_radius_ratio) *
				s.explosion.radius
			p.stats = s.explosion.particle
			p.color = client_ent_color(client, e.id)
			p.age +=
				rand.float32() * s.explosion.particle.lifetime_variation -
				s.explosion.particle.lifetime_variation / 2
		}
	}
}

@(export)
client_init :: proc(
	hr: ^hot.Reloader,
	config: ^pure.Client_Config,
) -> (
	client: ^Client,
) {
	context.allocator = hr.init_allocator

	pure.client_init(client, hr, config)

	client.camera.zoom = 1
	client.particles.slots = make([]Particle, MAX_PARTICLES)

	for &hsv, vl in client.ui.colors.picker_hsvs {
		if vl not_in EDITABLE_COLORS do continue

		name, _ := reflect.enum_name_from_value(vl)
		serr, s := sqlite.query_one(
			client.select_theme_color,
			hsv.values,
			name,
		)
		if serr == .DONE {
			hsv.hsv = ui_color_to_hsv(UI_COLORS_DEFAULT[vl])
		} else {
			sqlite.assert_ok(client.select_theme_color, serr)
		}
		sqlite.reset(s)
	}

	orui.init(&client.orui_ctx)

	client.orui_ctx.default_font = rl.LoadFontFromMemory(
		".ttf",
		raw_data(FONT_DATA),
		i32(len(FONT_DATA)),
		FONT_MEDIUM_SIZE,
		nil,
		0,
	)

	return
}

refresh_sheet :: proc(client: ^Client) {
	prev_assets := slice.clone(client.assets[:], context.temp_allocator)
	clear(&client.assets)
	append(&client.assets, 0)

	query, stmt := sqlite.query(
		client.get_server_assets,
		Saved_Asset,
		client.hctx.sh.id,
	)
	for asset in sqlite.query_next(&query) {
		if asset.type != .Sprite do continue
		append(&client.assets, asset.id)
	}
	sqlite.reset(stmt)

	if slice.equal(prev_assets, client.assets[:]) {
		return
	}

	packer.sheet_destroy(client.sheet)

	images := make([]rl.Image, len(client.assets), context.temp_allocator)
	defer for i in images do rl.UnloadImage(i)

	has_missing := false
	for s, i in client.assets {
		if s == 0 do continue

		name := pure.asset_path(client, s)
		images[i] = rl.LoadImage(
			strings.clone_to_cstring(name, context.temp_allocator),
		)
		if images[i] == {} {
			_, res := sqlite.exec(client.delete_asset, s)
			sqlite.assert_ok(client.delete_asset, res)
			has_missing = true

			log.warn("encountered missin image, inconsistent cache", name)
		}
	}

	client.sheet = packer.pack_into_sheet(images)

	for sprite, i in client.assets {
		if i == 0 do continue

		asset: Saved_Asset
		res, stmt := sqlite.query(client.get_asset, asset, sprite)
		if res == .DONE {
			has_missing = true
			log.warn("sprite is in the cache but not in db", sprite)
			continue
		}
		sqlite.assert_ok(stmt, res)
		sqlite.reset(stmt)
		client.sheet.frames[i].name = asset.name
	}

	if has_missing do pure.fetch_all_assets(client)
}

@(export)
client_update :: proc(hr: ^hot.Reloader, client: ^Client) {
	client.ents.delta = 1.0 / 60
	client.ents.on_remove = client_on_remove
	client.rtt = sync.atomic_load(&client.shared_rtt)
	client.on_sheet_refresh = refresh_sheet

	mouse_pos := client_mouse_pos(client)

	sim.ents_update(&client.ents)

	ui_map_editor_sync(client)

	iter: pure.Retained_Iter_State
	for p in pure.retained_iter(&client.particles, &iter) {
		ps := p.stats
		p.pos += p.vel * client.ents.delta
		p.age += client.ents.delta
	}

	iter = {}
	for l in pure.retained_iter(&client.lasers, &iter) {
		l.age += client.ents.delta
	}

	font_medium = client.orui_ctx.default_font
	client.camera.offset =
		{f32(rl.GetScreenWidth()), f32(rl.GetScreenHeight())} / 2

	pe := sim.ents_get(&client.ents, client.ent)
	if pe != sim.NIL_ENT {
		client.camera.target =
			pe.pos +
			pure.client_ent_extra_get(client, client.ent).pos_smoothing
	}

	rl.BeginDrawing()

	ui_build(client)

	ui_build_selection_update(client)
	if client.map_editing.expanded {
		ui_map_editor_update(client)
	}

	client_compute_input(client)

	rl.BeginMode2D(client.camera)
	rl.ClearBackground(rl.DARKGRAY)

	if rl.IsKeyPressed(.F1) do client.debug_on = !client.debug_on

	input_slot := client.free_deffered_inputs
	if input_slot != nil {
		input_slot.inner = client.current_input
		client.free_deffered_inputs = input_slot.next_free
		nbio.timeout_poly2(
			auto_cast (f64(client.rtt) * f64(time.Second)),
			client,
			input_slot,
			on_input_apply,
			l = client.l,
		)

		on_input_apply :: proc(
			op: ^nbio.Operation,
			client: ^Client,
			input: ^pure.Deffered_Client_Input,
		) {
			client.applied_input.inner = input.inner
			input.next_free = client.free_deffered_inputs
			client.free_deffered_inputs = input
		}
	}

	input_integration: {
		look_dir := sim.angle_of(client.applied_input.relative_mouse_pos)
		x := pure.client_ent_extra_get(client, client.ent)
		if x == pure.NIL_ENT_EXTRA do break input_integration

		if is_key_pressed(client, .Abandon_Ship) {
			pure.tcp_send(client, sim.Client_Cmd{type = .Abandon})
		}

		prev_vel := sim.ents_get(&client.ents, client.ent).vel
		sim.ents_integrate_input(
			&client.ents,
			client.ent,
			client.rtt,
			&client.applied_input,
		)
		curr_vel := sim.ents_get(&client.ents, client.ent).vel
		if linalg.distance(prev_vel, curr_vel) > 100 {
			client.last_inpulse = time.now()
		}
	}

	for &x, i in client.ent_extra {
		e := sim.ents_get(&client.ents, {x.gen, u32(i)})
		s := sim.ents_stats_get(&client.ents, e.stats)
		pos_mult: f32 = 4
		if s.kind == .Beam do pos_mult = 16
		x.pos_smoothing -= x.pos_smoothing * client.ents.delta * pos_mult
		x.rot_smoothing -=
			min(abs(x.rot_smoothing), client.ents.delta * math.PI * 3.5) *
			math.sign(x.rot_smoothing)
		x.energy_smoothing -= max(
			x.energy_smoothing * client.ents.delta * 4,
			min(x.energy_smoothing, client.ents.delta * 4),
		)
		x.trail_cooldown -= client.ents.delta
		t := sim.ents_team_get(&client.ents, e.team)
		sradius := sim.ents_radius(&client.ents, e.id)

		if s.kind == .Beam {
			px := pure.client_ent_extra_get(client, e.parent)
			it := sim.beam_walk_init(&client.ents, e.id, px.rot_smoothing)
			for pp in sim.beam_walk_next(&client.ents, &it) {}
			t = sim.ents_team_get(&client.ents, e.team)
			x.pos_smoothing = 0
		}

		pos := e.pos + x.pos_smoothing

		if x.trail_cooldown < 0 {
			x.trail_cooldown = s.trail.spacing
			spec := &s.trail.particle

			for _ in 0 ..< s.trail.quantity_per_tick {
				p := pure.retained_add(&client.particles)
				if p == nil do break

				p.pos =
					pos +
					sim.vec_of(rand.float32() * math.TAU) *
						rand.float32() *
						s.trail.spawn_innaccuracy
				p.radius = (1 - spec.one_minus_radius_ratio) * sradius
				p.stats = spec^
				p.color = get_color(t.color)
			}
		}
	}

	for p in client.players {
		e := sim.ents_get(&client.ents, p.ent)
		s := sim.ents_stats_get(&client.ents, e.stats)
		t := sim.ents_team_get(&client.ents, e.team)
		sradius := sim.ents_radius(&client.ents, e.id)
		x := pure.client_ent_extra_get(client, p.ent)
		if e == sim.NIL_ENT do continue

		pos := e.pos + x.pos_smoothing

		boost_dir := sim.input_movement_dir(p.input)

		ang := e.rot

		if boost_dir != {} {
			dirs := [?]sim.Vec{{0, -1}, {-1, 0}, {0, 1}, {1, 0}}

			for d in dirs {
				rotated_dir := sim.vec_of(sim.angle_of(d) + ang)

				offset := linalg.angle_between(boost_dir, rotated_dir)

				if offset >= math.PI / 2.5 {
					continue
				}

				emit_pos := pos - rotated_dir * sradius * 0.8

				off := offset / (math.PI / 2.0)
				intensity := 15.0 * (1.0 - off * off)

				for _ in 0 ..< 3 {
					p := pure.retained_add(&client.particles)
					if p == nil do break

					p.pos = emit_pos + e.vel * client.ents.delta
					p.vel =
						sim.vec_of(rand.float32() * math.TAU) * 100 +
						rotated_dir * -150
					p.stats.lifetime = (0.1 - rand.float32() * 0.04)
					p.radius = intensity
					p.color = get_color(t.color)
				}
			}
		}
	}

	map_draw(client)

	for p in pure.retained_active(&client.particles) {
		s := p.stats
		if p.age > s.lifetime do continue
		lifetime_coff := p.age / p.stats.lifetime
		radius := math.lerp(
			p.radius,
			p.radius * s.end_radius_ratio,
			lifetime_coff,
		)
		color := rl.ColorLerp(p.color, get_color(s.end_color), lifetime_coff)

		rl.DrawCircleV(p.pos, radius, color)
		//rl.DrawRectangleRec({p.pos.x - radius, p.pos.y - radius, radius * 2, radius * 2}, color)
	}

	for l in pure.retained_active(&client.lasers) {
		ls := sim.ents_stats_get(&client.ents, l.stats)
		lt := sim.ents_team_get(&client.ents, l.team)
		color := get_color(lt.color)
		radius := ls.radius * max(0, 1 - l.age / l.lifetime)

		liter: sim.Laser_Iter
		liter.pos = l.pos
		liter.vel = ls.speed * sim.vec_of(l.dir)
		for step in sim.laser_iter_next(&liter, &client.ents.mapa) {
			rl.DrawCircleV(liter.pos, radius, color)
			rl.DrawLineEx(liter.pos, liter.pos - step, radius * 2, color)
		}
	}

	draw_link_iter := sim.ents_iter(&client.ents)
	for e in sim.ents_iter_next(&draw_link_iter) {
		s := sim.ents_stats_get(&client.ents, e.stats)
		x := pure.client_ent_extra_get(client, e.id)
		pos := e.pos + x.pos_smoothing
		t := sim.ents_team_get(&client.ents, e.team)

		is_hovered := e.pos == snap_to_tile(mouse_pos)

		if e.id == client.bs.src_building || is_hovered {
			rl.DrawCircleLinesV(
				pos,
				max(s.bind_range, s.range),
				rl.ColorAlpha(get_color(t.color), 0.5),
			)
		}

		parent := sim.ents_get(&client.ents, e.parent)
		if parent != sim.NIL_ENT {
			if s.kind in sim.DRAWS_ENERGY {
				parent_pos :=
					parent.pos +
					pure.client_ent_extra_get(client, e.parent).pos_smoothing
				rl.DrawLineEx(parent_pos, pos, 5, get_color(t.color))

				if s.guards {
					for i in 0 ..< 2 {
						sign := -1 + f32(2 * i)
						offset :=
							linalg.orthogonal(
								linalg.normalize0(parent_pos - pos),
							) *
							sign *
							10
						rl.DrawLineEx(
							parent_pos + offset,
							pos + offset,
							5,
							get_color(t.color),
						)
					}
				}
			}

			beam: if s.kind == .Beam {
				pe := sim.ents_get(&client.ents, e.parent)
				ps := sim.ents_stats_get(&client.ents, pe.stats)
				px := pure.client_ent_extra_get(client, e.parent)
				if pe == sim.NIL_ENT do break beam

				rad := s.radius * f32((math.sin(rl.GetTime() * 50) + 5) / 6)

				it := sim.beam_walk_init(&client.ents, e.id, px.rot_smoothing)
				t = sim.ents_team_get(&client.ents, e.team)
				for pp in sim.beam_walk_next(&client.ents, &it) {
					rl.DrawCircleV(pp, rad, get_color(t.color))

					rl.DrawLineEx(pp, e.pos, rad * 2, get_color(t.color))
					t = sim.ents_team_get(&client.ents, e.team)
				}

			}
		}

		if sim.ents_is_unwinding(&client.ents, e.id) {
			p := pure.retained_add(&client.particles)
			p.radius = s.radius * (1 - (e.reload - s.reload) / s.unwind) * 0.8
			p.pos = e.pos + sim.vec_of(e.rot) * (s.radius + p.radius * 0.3)
			p.lifetime = 0.1
			p.color = rl.ColorLerp(
				invert_color(get_color(t.color)),
				get_color(t.color),
				0.5,
			)
			p.end_color = t.color
		}
	}

	draw_iter := sim.ents_iter(&client.ents)
	for e in sim.ents_iter_next(&draw_iter) {
		s := sim.ents_stats_get(&client.ents, e.stats)
		sradius := sim.ents_radius(&client.ents, e.id)
		t := sim.ents_team_get(&client.ents, e.team)
		x := pure.client_ent_extra_get(client, e.id)
		tcolor := client_ent_color(client, e.id)

		pos := e.pos + x.pos_smoothing

		if s.sprite != 0 {
			sradius := sradius * (1 + s.sprite_factor_minus_one)
			texture, region := ui_get_sprite(&client.ui, s.sprite)
			rl.DrawTexturePro(
				texture,
				region,
				{pos.x, pos.y, sradius * 2, sradius * 2},
				{sradius, sradius},
				(e.rot + x.rot_smoothing) / math.PI / 2 * 360,
				rl.WHITE,
			)
		} else {
			rl.DrawCircleV(pos, sradius, tcolor)
		}

		if s.cannon != 0 {
			texture, region := ui_get_sprite(&client.ui, s.cannon)
			rl.DrawTexturePro(
				texture,
				region,
				{pos.x, pos.y, sradius * 2, sradius * 2},
				{sradius, sradius},
				e.turret_rot / math.PI / 2 * 360,
				rl.WHITE,
			)
		}

		if client.debug_on {
			rl.DrawCircleV(e.pos, 10, rl.RED)
		}

		if s.energy != 0 {
			fullness_cof :=
				1 - ((e.energy_consumed + x.energy_smoothing) / s.energy)

			rl.DrawRing(
				pos,
				sradius + 10,
				sradius + 15,
				0,
				fullness_cof * 360,
				i32(fullness_cof * 100),
				get_color(t.color),
			)

			if fullness_cof > 1 {
				rl.DrawRing(
					pos,
					sradius + 10,
					sradius + 15,
					360,
					fullness_cof * 360,
					i32(fullness_cof * 100),
					invert_color(get_color(t.color)),
				)
			}
		}

		if e.parry_progress >= 0 {
			coff: f32
			color: rl.Color
			if e.parry_progress < s.parry.cooldown {
				coff = e.parry_progress / s.parry.cooldown
				color = rl.RED
			} else if e.parry_progress <
			   s.parry.cooldown + s.parry.duration + s.parry.attack.unwind {
				coff =
					(e.parry_progress - s.parry.cooldown) /
					(s.parry.duration + s.parry.attack.unwind)
				color = rl.WHITE
			} else {
				coff =
					(e.parry_progress -
						s.parry.cooldown -
						s.parry.duration -
						s.parry.attack.unwind) /
					s.parry.invincibility
				color = rl.ORANGE
			}

			rl.DrawRing(
				pos,
				sradius + 15,
				sradius + 20,
				0,
				coff * 360,
				i32(coff * 100),
				color,
			)
		}

		if e.dash_cooldown >= 0 {
			coff := e.dash_cooldown / s.dash.cooldonw
			rl.DrawRing(
				pos,
				sradius + 20,
				sradius + 25,
				0,
				coff * 360,
				i32(coff * 100),
				rl.YELLOW,
			)
		}
	}

	t := sim.ents_team_get(&client.ents, pe.team)
	highlight_color := rl.ColorAlpha(get_color(t.color), 0.5)

	if client.ui.control_selection_pivot != {} {
		rect := client_selection_rect(client)
		rl.DrawRectangleRec(rect, rl.ColorAlpha(highlight_color, 0.3))

		highlight_iter := client_query_rect(client, rect)
		for qe in sim.ents_query_next(&highlight_iter) {
			qs := sim.ents_stats_get(&client.ents, qe.stats)
			qsradius := sim.ents_radius(&client.ents, qe.id)
			qx := pure.client_ent_extra_get(client, qe.id)
			qpos := qe.pos + qx.pos_smoothing
			if rl.CheckCollisionPointRec(qpos, rect) && qs.kind == .Unit {
				rl.DrawCircleV(qpos, qsradius, highlight_color)
			}
		}
	}

	for sid in client.ui.selected_units {
		se := sim.ents_get(&client.ents, sid)
		ss := sim.ents_stats_get(&client.ents, se.stats)
		seradius := sim.ents_radius(&client.ents, sid)
		sx := pure.client_ent_extra_get(client, sid)
		spos := se.pos + sx.pos_smoothing
		rl.DrawCircleV(spos, seradius, highlight_color)
	}

	if client.debug_on {
		radius := f32(sim.map_quad_size(&client.ents.mapa))

		draw_quad_tree(&client.ents.quad_tree, {radius, radius}, radius)

		draw_quad_tree :: proc(
			quad: ^sim.Quad_Tree,
			pos: sim.Vec,
			radius: f32,
		) {
			if quad.children != nil {
				rl.DrawLineV(pos - {0, radius}, pos + {0, radius}, rl.RED)
				rl.DrawLineV(pos - {radius, 0}, pos + {radius, 0}, rl.RED)

				next_radius := radius * 0.5

				offsets := [4][2]f32 {
					{-next_radius, -next_radius},
					{next_radius, -next_radius},
					{-next_radius, next_radius},
					{next_radius, next_radius},
				}

				for i in 0 ..< 4 {
					draw_quad_tree(
						&quad.children[i],
						pos + offsets[i],
						next_radius,
					)
				}
			}
		}
	}

	rl.EndMode2D()

	client_draw_input(client)
	ui_render()

	rl.EndDrawing()
}

client_shutdown :: proc(client: ^Client) {
	sim.tcp_connection_kill(&client.hctx.tcp, client.l)
	sim.udp_connection_kill(&client.udp, client.l)

	hot.sip.io_remove(client.tick_interval)
	hot.sip.io_remove(client.ping_interval)

	for e in client.servers.server_info_cache do server_info_close(e)
	server_info_close(&client.servers.create_fetcher)

	io_res := hot.sip.io_run(client.l)
	assert(io_res == nil)

	chan.close(client.rtt_worker_reqs)
	thread.join(client.rtt_worker)
}

@(export)
client_deinit :: proc(hr: ^hot.Reloader, client: ^Client) {
	client_shutdown(client)

	delete(client.map_buf)
	delete(client.players)
	delete(client.assets)

	delete(client.ents.stats)
	packer.sheet_destroy(client.sheet)
	ui_destroy(client)

	sqlite.finalize(client.ui_statements)
	db_res := sqlite.close(client.db)
	sqlite.assert_ok(client.db, db_res)
}

client_ent_color :: proc(client: ^Client, eid: sim.Ent_ID) -> rl.Color {
	e := sim.ents_get(&client.ents, eid)
	s := sim.ents_stats_get(&client.ents, e.stats)
	t := sim.ents_team_get(&client.ents, e.team)

	color := get_color(t.color)
	inv_color := invert_color(color)
	damage_ratio := s.body_damage / max(1, sim.ents_damage(&client.ents, eid))

	return rl.ColorLerp(inv_color, color, damage_ratio)
}

@(export)
client_memory_size :: proc() -> (sum: int) {
	for t in sim.HOT_TYPES do sum += size_of(t)
	sum += size_of(Client)
	sum += size_of(pure.Player)
	sum += size_of(Particle)
	sum += size_of(pure.Laser)

	return
}

@(export)
client_static_init :: proc(params: hot.Static_Init_Params) {
	sim.register_user_formatters()
	hot.sip = params
}

@(export)
client_static_deinit :: proc() {
	sim.unregister_user_formatters()
}

client_config_default :: proc() -> (cc: pure.Client_Config) {
	data_dir, data_dir_err := os.user_data_dir(context.temp_allocator)
	if data_dir_err != nil {
		log.error("failed to resolve the data dir:", data_dir_err)
	}

	our_section, _ := os.join_path({data_dir, APP_NAME}, context.allocator)

	mkerr := os.mkdir_all(our_section)
	if mkerr != nil && mkerr != .Exist {
		log.errorf(
			"failed to create all directories (%s): %v",
			our_section,
			mkerr,
		)
		delete(our_section)
		our_section = ""
	}

	cache_dir, _ := os.join_path(
		{our_section, pure.ASSET_CACHE},
		context.temp_allocator,
	)

	mkerr = os.mkdir_all(cache_dir)
	if mkerr != nil && mkerr != .Exist {
		log.errorf(
			"failed to create all directories (%s): %v",
			cache_dir,
			mkerr,
		)
	}

	cc.data_dir = our_section
	log.debug("selected data dir:", cc.data_dir)

	db_path, db_path_err := os.join_path(
		{cc.data_dir, "db.db"},
		context.temp_allocator,
	)
	assert(db_path_err == nil)

	sconn, sconn_open_err := sqlite.open(db_path)
	sqlite.assert_ok(sconn, sconn_open_err)

	cc.db = sconn

	return
}

when ODIN_BUILD_MODE == .Executable || ODIN_BUILD_MODE == .Object {
	main :: proc() {
		main_proc()
	}
}

main_proc :: proc() {
	CHUNK_SIZE :: 1024 * 1024 * 16
	TEMP_SIZE :: 1024 * 1024 * 64
	INIT_SIZE :: 1024 * 1024 * 16

	temp_arna: arna.Allocator
	temp_arna.reserved = TEMP_SIZE
	global_arna: arna.Allocator
	global_arna.reserved = CHUNK_SIZE * 8
	init_arna: arna.Allocator
	init_arna.reserved = INIT_SIZE

	arna_err := arna.bulk_init(&temp_arna, &global_arna, &init_arna)
	log.assertf(arna_err == nil, "failed to initialize arenas: %v", arna_err)

	context.assertion_failure_proc = hot.init_trace()
	context.temp_allocator = arna.allocator(&temp_arna)
	context.allocator = sim.global_allocator_create(
		arna.allocator(&global_arna),
		CHUNK_SIZE,
	)
	context.logger = log.create_console_logger(
		allocator = arna.allocator(&global_arna),
	)

	hr: hot.Reloader
	hr.module_name = "client"
	hr.watch_dirs = {"client", "sim"}
	hr.extra_args = {
		"-define:TRACK_ALLOCATIONS=true",
		"-define:RAYLIB_SHARED=true",
		"-define:SQLITE_SHARED=true",
	}
	hr.dyn_defs = {{"LATENCY", sim.LATENCY}, {"LOCAL", sim.LOCAL}}
	hr.lib = {
		memory_size = client_memory_size,
		static_init = client_static_init,
		init        = auto_cast client_init,
		update      = auto_cast client_update,
		deinit      = auto_cast client_deinit,
	}
	hr.init_allocator = arna.allocator(&init_arna)

	config: pure.Client_Config
	{context.allocator = arna.allocator(&global_arna)
		config = client_config_default()}
	hr.config = &config

	l, err := nbio.create_event_loop()
	fmt.assertf(err == nil, "failed to acquire thread event loop:", err)
	hr.l = l

	client_static_init(hot.sip)

	rl.SetConfigFlags({.WINDOW_RESIZABLE})
	rl.InitWindow(800, 600, "gam")
	rl.SetTargetFPS(0)

	core_time: Frame_Timer
	core_time.target = 1.0 / 60
	core_time.get_time = auto_cast rl.GetTime

	for !rl.WindowShouldClose() {
		_ = hot.reload(&hr, {})

		hot.update(&hr)

		frame_end(&core_time, hr.l)

		free_all(context.temp_allocator)
	}

	if sim.TRACK_ALLOCATIONS {
		hot.deinit(&hr)
		nbio.destroy_event_loop(l)
		context.logger = {}
		client_static_deinit()
		sim.global_allocator_destroy(context.allocator)
		hot.unload_libraries(&hr)
		arna.bulk_destroy(&temp_arna, &global_arna, &init_arna)
	}
}

Frame_Timer :: struct {
	get_time: proc() -> f64,
	target:   f64,
	previous: f64,
}

frame_end :: proc(t: ^Frame_Timer, l: ^nbio.Event_Loop) {
	current := t.get_time()
	wait_time := current - t.previous
	t.previous = current
	frame := wait_time

	for frame < t.target {
		runerr := nbio.tick(
			l,
			time.Duration((t.target - frame) * f64(time.Second)),
		)
		assert(runerr == nil)

		current = t.get_time()
		wait_time := current - t.previous
		t.previous = current
		frame += wait_time
	}
}
