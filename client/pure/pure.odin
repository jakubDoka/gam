package pure_client

import "../../sim"
import "../../simt/nbio"
import "../../util/arna"
import "../../util/bit_arr"
import "../../util/hot"
import "../../util/nm"
import "../../util/rtt"
import "../../util/sqlite"
import "base:runtime"
import "core:sort"
import "core:sync/chan"
import "core:thread"
import "core:time"

MAX_LASERS :: 512
ASSET_CACHE :: "asset-cache"
SELECTED_PROFILE_CID :: 0

Config :: struct {
	db:             sqlite.Connection,
	data_dir:       string,
	predefined_rtt: Maybe(f32),
}

Player :: struct {
	using inner: sim.Player,
	ent:         sim.Ent_ID,
	input:       sim.Client_Input_Keys,
}

Deffered_Client_Input :: struct {
	inner:     sim.Client_Input,
	next_free: ^Deffered_Client_Input,
}

get_selected_user :: proc(r: ^Client) -> (profile: Profile) {
	selected_profile: sim.Player_Name
	serr, s := sqlite.query(
		r.load_input_content,
		selected_profile,
		SELECTED_PROFILE_CID,
	)
	if serr != .DONE do sqlite.assert_ok(s, serr)
	sqlite.reset(s)

	serr, s = sqlite.query(
		r.select_profile_by_name,
		profile,
		nm.str(&selected_profile),
	)
	if serr != .DONE do sqlite.assert_ok(s, serr)
	sqlite.reset(s)

	return
}

Client_Build_State :: struct {
	src_building: sim.Ent_ID,
	dst_building: sim.Ent_ID,
	place_pos:    Maybe(sim.Map_Pos),
}

Laser :: struct {
	age:      f32,
	lifetime: f32,
	pos:      sim.Vec,
	dir:      f32,
	team:     sim.Ent_Team_ID,
	stats:    sim.Ent_Stats_ID,
}

Lasers :: Retained_Array(Laser)

@(rodata)
NIL_ENT_EXTRA_MEM := Ent_Extra{}
NIL_ENT_EXTRA := &NIL_ENT_EXTRA_MEM

Ent_Extra :: struct {
	pos_smoothing:    sim.Vec,
	rot_smoothing:    f32,
	energy_smoothing: f32,
	gen:              u32,
	trail_cooldown:   f32,
}

Client :: struct {
	using hctx:            sim.Handshake,
	using config:          ^Config,
	using statements:      Statements,
	did_shutdown:          bool,
	has_dirty_config:      bool,
	upload:                Upload_State,
	messages:              Chat_Ring,
	ip_error:              string,
	conn_id:               int,
	last_inpulse:          time.Time,
	udp:                   sim.UDP_Connection,
	connection_stage:      Connection_State,
	last_server_packet:    time.Time,
	shared_rtt:            f32,
	rtt:                   f32,
	rtt_worker:            ^thread.Thread,
	rtt_worker_reqs:       chan.Chan(Rtt_Worker_Request, .Send),
	tps:                   int,
	ents:                  sim.Ents,
	ent:                   sim.Ent_ID,
	ent_extra:             []Ent_Extra,
	current_input:         sim.Input_State,
	applied_input:         sim.Input_State,
	map_buf:               []u8,
	players:               [dynamic]Player,
	free_deffered_inputs:  ^Deffered_Client_Input,
	last_cold_state_hash:  sim.Hash,
	debug_on:              bool,
	config_allocator:      arna.Allocator,
	input_pool:            []Deffered_Client_Input,
	tick_interval:         ^nbio.Operation,
	ping_interval:         ^nbio.Operation,
	lasers:                Lasers,
	bs:                    Client_Build_State,
	asset_loader:          ^Req,
	asset_uploader:        ^Req,
	player_idx:            int,
	last_app:              time.Time,
	assets_to_fetch:       [dynamic]sim.Asset_ID,
	inflight_assets:       int,
	inflight_asset_cursor: int,
	on_sheet_refresh:      proc(_: ^Client),
}

client_ent_extra_get :: proc(client: ^Client, id: sim.Ent_ID) -> ^Ent_Extra {
	if sim.ents_get(&client.ents, id) == sim.NIL_ENT do return NIL_ENT_EXTRA

	extra := &client.ent_extra[id.index]
	if extra.gen != id.gen do extra^ = {
		gen = id.gen,
	}
	return extra
}

REWIRE_TABLE := [?]rawptr {
	rawptr(client_on_tcp_kill),
	rawptr(client_on_tcp_packet),
	rawptr(client_on_udp_kill),
	rawptr(client_on_udp_packet),
	rawptr(client_decrypt_packet),
	rawptr(client_on_tick),
	rawptr(client_on_ping),
}

@(export)
client_rewire :: proc(hr: ^hot.Reloader, client: ^Client) {
	rw: hot.Rewireing
	rw.hr = hr
	append(&rw.table, ..REWIRE_TABLE[:])
	defer hot.rewire_apply(rw)

	hot.rewire(&rw, client.cleanup)
	hot.rewire(&rw, client.host.on_packet)
	hot.rewire(&rw, client.udp.host.on_kill)
	hot.rewire(&rw, client.udp.host.on_packet)
	hot.rewire(&rw, client.udp.host.decrypt)

	hot.rewire(&rw, sim.interval_rewire_slot(client.tick_interval))
	hot.rewire(&rw, sim.interval_rewire_slot(client.ping_interval))
}

// NOTE: the actual client can be a superclass so no alocation here
client_init :: proc(client: ^Client, hr: ^hot.Reloader, config: ^Config) {
	context.allocator = hr.init_allocator
	append(&hr.rewire_table, ..REWIRE_TABLE[:])

	client.config = config
	client.l = hr.l
	client.player_idx = -1
	client.udp.recv_buf = make([]u8, 1 << 16)
	sim.packet_buffer_reserve(&client.udp.send_buf, 16)
	sim.ents_reserve(&client.ents, sim.MAX_ENTS_PER_GAME)
	client.lasers.slots = make([]Laser, MAX_LASERS)
	client.ent_extra = make([]Ent_Extra, sim.MAX_ENTS_PER_GAME)
	client.config_allocator = arna.init_from_buffer(make([]u8, 1 << 16))
	client.upload.arena = arna.init_from_buffer(make([]u8, 1 << 14))
	client.assets_to_fetch.allocator = hr.init_allocator

	client.input_pool = make([]Deffered_Client_Input, 64)
	for &ci in client.input_pool {
		ci.next_free = client.free_deffered_inputs
		client.free_deffered_inputs = &ci
	}

	sqlite.exec(client.db, #load("../schema.sql", cstring))
	sqlite.prepare(client.db, client.statements)

	chat_ring_init(&client.messages, make([]u8, 1024 * 64))

	sim.interval_poly(
		sim.PING_INTERVAL,
		client,
		client_on_ping,
		&client.ping_interval,
		client.l,
	)

	sim.interval_poly(
		sim.TICK_INTERVAL,
		client,
		client_on_tick,
		&client.tick_interval,
		client.l,
	)

	if p, ok := config.predefined_rtt.?; ok {
		client.shared_rtt = p
	} else {
		reqs, _ := chan.create_buffered(
			chan.Chan(Rtt_Worker_Request, .Both),
			16,
			context.allocator,
		)
		client.rtt_worker = rtt_worker_run(
			{rt = &client.shared_rtt, reqs = chan.as_recv(reqs)},
		)
		client.rtt_worker_reqs = chan.as_send(reqs)
	}

	return
}

client_deinit :: proc(hr: ^hot.Reloader, client: ^Client) {
	client_shutdown(client)

	delete(client.map_buf)
	delete(client.players)

	delete(client.ents.stats)

	sqlite.finalize(client.statements)
}

client_shutdown :: proc(client: ^Client) {
	if client.did_shutdown do return
	client.did_shutdown = true

	sim.tcp_connection_kill(&client.hctx.tcp, client.l)
	sim.udp_connection_kill(&client.udp, client.l)

	hot.sip.io_remove(client.tick_interval)
	hot.sip.io_remove(client.ping_interval)

	io_res := hot.sip.io_run(client.l)
	assert(io_res == nil)

	if client.rtt_worker != nil {
		chan.close(client.rtt_worker_reqs)
		thread.join(client.rtt_worker)
	}
}

find_spawn_parent :: proc(
	client: ^Client,
	selected_team: sim.Ent_Team_ID,
) -> ^sim.Ent {
	spawn_parent := sim.NIL_ENT
	spawn_iter := sim.ents_iter(&client.ents)
	for e in sim.ents_iter_next(&spawn_iter) {
		s := sim.ents_stats_get(&client.ents, e.stats)
		if !s.can_spawn_player do continue
		if e.team != selected_team do continue
		spawn_parent = e
	}

	return spawn_parent
}

compute_team_params :: proc(
	client: ^Client,
) -> (
	counts: []int,
	alives: []bool,
) {
	counts = make([]int, len(client.ents.teams), context.temp_allocator)
	for p in client.players {
		e := sim.ents_get(&client.ents, p.ent)
		if int(e.team) >= len(counts) do continue
		counts[e.team] += 1
	}

	alives = make([]bool, len(client.ents.teams), context.temp_allocator)
	iter := sim.ents_iter(&client.ents)
	for e in sim.ents_iter_next(&iter) {
		s := sim.ents_stats_get(&client.ents, e.stats)
		if int(e.team) >= len(counts) do continue
		alives[e.team] |= s.can_spawn_player
	}

	return
}

Map_Edit_State :: struct {
	changed_terrain: bit_arr.Bit_Set,
	teams:           [dynamic]sim.Ent_Team,
	width:           int,
	height:          int,
}

map_export :: proc(client: ^Client, ctx: ^Map_Edit_State) -> (mapa: sim.Map) {
	context.allocator = context.temp_allocator

	mapa.width = client.ents.width
	mapa.height = client.ents.height
	mapa.sprites = client.ents.sprites

	mapa.tiles = make(
		[]int,
		min(
			sim.map_tile_storage_size(mapa.width, mapa.height),
			bit_arr.mask_len(ctx.changed_terrain.bit_length),
		),
	)

	for i in 0 ..< len(mapa.tiles) {
		mapa.tiles[i] =
			client.ents.mapa.tiles[i] ~ int(ctx.changed_terrain.masks[i])
	}

	if mapa.width != ctx.width || mapa.height != ctx.height {
		old_tiles := bit_arr.Bit_Set {
			raw_data(mapa.tiles),
			mapa.width * mapa.height,
		}
		new_tiles := bit_arr.init(ctx.width * ctx.height)
		for y in 0 ..< min(mapa.height, ctx.height) {
			for x in 0 ..< min(mapa.width, ctx.width) {
				vl := bit_arr.contains_unbounded(old_tiles, y * mapa.width + x)
				bit_arr.set(new_tiles, y * ctx.width + x, vl)
			}
		}
		mapa.width = ctx.width
		mapa.height = ctx.height
		len := sim.map_tile_storage_size(mapa.width, mapa.height)
		mapa.tiles = new_tiles.masks[:len]
	}

	ents: [dynamic]sim.Map_Ent
	append(&ents, sim.Map_Ent{})
	map_ent_to_ent: [dynamic]^sim.Ent
	append(&map_ent_to_ent, sim.NIL_ENT)

	ent_iter := sim.ents_iter(&client.ents)
	o: for e in sim.ents_iter_next(&ent_iter) {
		s := sim.ents_stats_get(&client.ents, e.stats)
		if s.kind != .Building do continue
		pos := sim.map_vec_to_pos(e.pos)
		if pos.x >= mapa.width do continue
		if pos.y >= mapa.height do continue
		append(&map_ent_to_ent, e)
		append(&ents, sim.Map_Ent{stat = e.stats, team = e.team, pos = pos})
	}

	Ctx :: struct {
		map_ents: []sim.Map_Ent,
		ents:     []^sim.Ent,
	}

	ctx_len :: proc(id: sort.Interface) -> int {
		return len(((^Ctx)(id.collection)).ents)
	}

	ctx_swap :: proc(id: sort.Interface, a: int, b: int) {
		cx := (^Ctx)(id.collection)
		cx.ents[a], cx.ents[b] = cx.ents[b], cx.ents[a]
		cx.map_ents[a], cx.map_ents[b] = cx.map_ents[b], cx.map_ents[a]
	}

	ctx_less :: proc(id: sort.Interface, a: int, b: int) -> bool {
		cx := (^Ctx)(id.collection)
		return transmute(u64)cx.ents[a].pos < transmute(u64)cx.ents[b].pos
	}

	cx := Ctx {
		ents     = map_ent_to_ent[:],
		map_ents = ents[:],
	}

	sort.sort(
		sort.Interface {
			len = ctx_len,
			swap = ctx_swap,
			less = ctx_less,
			collection = &cx,
		},
	)

	ent_to_map_ent := make([]int, len(client.ents.slots))

	for e, i in map_ent_to_ent {
		ent_to_map_ent[e.id.index] = i
	}

	for &me, i in ents {
		e := map_ent_to_ent[i]
		if !sim.ents_is_valid(&client.ents, e.parent) {
			continue
		}
		me.parent = ent_to_map_ent[e.parent.index]
	}

	mapa.ents = ents[:]
	mapa.chargers = client.ents.mapa.chargers[:]
	mapa.teams = ctx.teams[:]

	return
}
