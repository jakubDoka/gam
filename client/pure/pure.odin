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
import "core:sync/chan"
import "core:thread"
import "core:time"

MAX_LASERS :: 512
ASSET_CACHE :: "asset-cache"
SELECTED_PROFILE_CID :: 0

Profile :: struct {
	name: sim.Player_Name,
	pk:   sim.Private_Key,
}

Connection_State :: enum {
	Disconnected,
	Connecting,
	Connected,
	Disconnecting,
}

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

Upload_State :: struct {
	error:    string,
	arena:    arna.Allocator,
	arena_rc: int,
	gen:      int,
	assets:   #soa[dynamic]Dropped_Asset,
	inflight: int,
	cursor:   int,
}

Dropped_Asset :: struct {
	base:     sim.Asset,
	path:     string,
	issue:    string,
	uploaded: bool,
}

Statements :: struct {
	save_input_content:     sqlite.Statement `
		INSERT INTO text_input VALUES (?, ?)
			ON CONFLICT (id) DO UPDATE SET content = ?2
	`,
	load_input_content:     sqlite.Statement `
		SELECT content FROM text_input WHERE id = ?
	`,
	delete_input_content:   sqlite.Statement `
		DELETE FROM text_input WHERE id = ?
	`,
	save_profile:           sqlite.Statement `
		INSERT INTO profile VALUES (?, ?)
	`,
	load_profiles:          sqlite.Statement `
		SELECT * FROM profile
	`,
	count_profiles:         sqlite.Statement `
		SELECT COUNT(*) FROM profile
	`,
	delete_profile:         sqlite.Statement `
		DELETE FROM profile WHERE name = ?
	`,
	edit_profile:           sqlite.Statement `
		UPDATE profile SET name = ? WHERE name = ?
	`,
	select_profile_by_name: sqlite.Statement `
		SELECT * FROM profile WHERE name = ?
	`,
	select_theme_color:     sqlite.Statement `
		SELECT hue, saturation, brightness, alpha FROM theme WHERE name = ?
	`,
	save_theme_color:       sqlite.Statement `
		INSERT INTO theme VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (name) DO UPDATE SET
				hue = ?2, saturation = ?3, brightness = ?4, alpha = ?5
	`,
	save_server:            sqlite.Statement `
		INSERT INTO server VALUES (?, ?, ?)
			ON CONFLICT (nick_name) DO UPDATE SET
				conn_string = ?2, pk = ?3
	`,
	load_server:            sqlite.Statement `
		SELECT * FROM server WHERE nick_name = ?
	`,
	load_servers:           sqlite.Statement `
		SELECT * FROM server
	`,
	delete_server:          sqlite.Statement `
		DELETE FROM server WHERE nick_name = ?
	`,
	save_asset:             sqlite.Statement `
		INSERT INTO asset VALUES (?, ?, ?, ?)
			ON CONFLICT (id, server) DO UPDATE SET name = ?3, type = ?4
	`,
	get_server_assets:      sqlite.Statement `
		SELECT * FROM asset WHERE server = ?
	`,
	get_asset:              sqlite.Statement `
		SELECT * FROM asset WHERE id = ?
	`,
	delete_asset:           sqlite.Statement `
		DELETE FROM Asset WHERE id = ?
	`,
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

Saved_Text_Input :: struct {
	id:      int,
	content: string,
}

Saved_Server :: struct {
	nick_name:   string,
	conn_string: string,
	pk:          sim.Identity,
}

Saved_Asset :: struct {
	pk:   sim.Identity,
	id:   sim.Asset_ID,
	name: nm.Name,
	type: sim.Asset_Type,
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
