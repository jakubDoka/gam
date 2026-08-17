package pure_client

import "../../sim"
import "../../simt/nbio"
import "../../util/arna"
import "../../util/b58"
import "../../util/bit_arr"
import "../../util/nm"
import "../../util/rtt"
import "../../util/sqlite"
import "base:runtime"
import "core:fmt"
import "core:log"
import "core:mem"
import "core:net"
import "core:reflect"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:sync/chan"
import "core:thread"
import "core:time"

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
	using ui_statements:   Statements,
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
