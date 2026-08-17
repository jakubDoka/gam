package pure_client

import "../../sim"
import "../../simt/nbio"
import "../../util/arna"
import "../../util/hot"
import "../../util/nm"
import "../../util/rtt"
import "../../util/sqlite"
import "base:runtime"
import "core:sync/chan"
import "core:thread"
import "core:time"

MAX_LASERS :: 512
ASSET_CACHE :: "asset-cache"
SELECTED_PROFILE_CID :: 0

Client_Config :: struct {
	db:       sqlite.Connection,
	data_dir: string,
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
	if serr != .DONE do sqlite.assert_ok(r.load_input_content, serr)
	sqlite.reset(s)

	serr, s = sqlite.query(
		r.select_profile_by_name,
		profile,
		nm.str(&selected_profile),
	)
	if serr != .DONE do sqlite.assert_ok(r.select_profile_by_name, serr)
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
	using config:          ^Client_Config,
	using statements:      Statements,
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
client_init :: proc(
	client: ^Client,
	hr: ^hot.Reloader,
	config: ^Client_Config,
) {
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

	reqs, _ := chan.create_buffered(
		chan.Chan(Rtt_Worker_Request, .Both),
		16,
		context.allocator,
	)
	client.rtt_worker = rtt_worker_run(
		{rt = &client.shared_rtt, reqs = chan.as_recv(reqs)},
	)
	client.rtt_worker_reqs = chan.as_send(reqs)

	return
}
