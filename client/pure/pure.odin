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
import "core:net"
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

UI_Color :: enum {
	UNSET,
	NONE,
	PRIMARY,
	PRIMARY_FAINT,
	SECONDARY,
	SECONDARY_FAINT,
	SUCCESS,
	FOREGROUND,
	SLOT1,
	SLOT2,
	SLOT3,
}

UI_Event_Kind :: enum {
	Select_Stat,
	Select_Team,
	Delete_Team,
	Select_Profile,
	Disconnect,
	Quit_Content_Editor,
	Open_Content_Editor,
	Close_Stat_Editor,
	Save_Content_Changes,
	Open_Map_Editor,
	Close_Map_Editor,
	Focus,
	Apply_Content_Changes,
	Reset_Color,
	Select_Color,
	Connect,
	Connect_To_Server,
	Delete_Server,
	Refresh_Server_Identity,
	Fetch_Server_Info,
	Save_Server_Id,
	Delete_Profile,
	Rename_Profile,
	Create_Profile,
	Download_All_Assets,
	Save_Map,
	Spawn_Ship,
	Build,
	Delete_Building,
	Rewire,
	Create_Stat,
	Upload_Assets,
	Clear_Assets,
	Select_Brush,
	Select_Map_Team,
	Close_Team_Editor,
	Add_Team,
	Send_Chat,
}

Key_Bind :: enum {
	Nil,
	Exit,
	Toggle_Chat,
	Abandon_Ship,
	Up,
	Down,
	Left,
	Right,
	Shoot,
	Parry,
	Dash,
	Map_Place,
	Map_Erase,
	Build_Select_Start,
	Build_Select_End,
	Build_Select_Clear,
	Open_Content_Editor,
	Open_Map_Editor,
	Save,
	Select_Finder,
}

UI_Map_Editor_Brush :: enum int {
	Wall,
	Floor,
	Charger,
	Building,
}

UI_Event :: struct {
	kind:                 UI_Event_Kind,
	team:                 sim.Ent_Team_ID,
	team_idx:             int,
	name:                 nm.Name,
	priority:             int,
	bind:                 Key_Bind,
	target:               orui.Id,
	carret_index:         int,
	stats:                sim.Ent_Stats_ID,
	color:                UI_Color,
	endpoint:             net.Endpoint,
	ent:                  sim.Ent_Net_ID,
	parent:               sim.Ent_Net_ID,
	pos:                  sim.Vec,
	text:                 string,
	identity:             sim.Identity,
	brush:                UI_Map_Editor_Brush,
	saved_server:         Saved_Server,
	server_info_listener: ^UI_Server_Info_Listener,
}

Client :: struct {
	using hctx:            sim.Handshake,
	using config:          ^Client_Config,
	using ui_statements:   Statements,
	captured_key_binds:    [dynamic; 16]Key_Or_Mouse,
	events:                [dynamic]UI_Event,
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
	sqlite.prepare(client.db, client.ui_statements)

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

execute_ui_event :: proc(client: ^Client) {
	winning_kb_events: [Key_Bind]UI_Event

	for &ev in client.events {
		if ev.bind != .Nil {
			append(
				&client.captured_key_binds,
				key_or_mouse_from_key(BIND_TO_KEY[ev.bind]),
			)
		}

		switch ev.kind {
		case .Disconnect,
		     .Quit_Content_Editor,
		     .Open_Content_Editor,
		     .Save_Content_Changes,
		     .Close_Stat_Editor,
		     .Close_Map_Editor,
		     .Open_Map_Editor,
		     .Apply_Content_Changes,
		     .Focus:
			assert(ev.bind != .Nil)
			slot := &winning_kb_events[ev.bind]
			if slot.priority < ev.priority {
				slot^ = ev
			}
		case .Select_Stat:
			ctx := &client.content_editor

			stats := sim.ents_stats_get(&client.ents, ev.stats)

			ctx.selected = ev.stats
			clear(&ctx.edit_name.buf)
			append(&ctx.edit_name.buf, nm.str(&stats.name))
			ctx.stat_edit_state = stats^
			client.bs = {}
		case .Select_Team:
			client.selected_team = ev.team
		case .Delete_Team:
			ordered_remove(&client.map_editing.teams, ev.team_idx)
			client.map_editing.team = 0
		case .Select_Profile:
			_, save_err := sqlite.exec(
				client.save_input_content,
				pure.SELECTED_PROFILE_CID,
				nm.str(&ev.name),
			)
			sqlite.assert_ok(client.save_input_content, save_err)
			client.profiles.editing = false
		case .Reset_Color:
			hsv := &client.ui.colors.picker_hsvs[ev.color]
			hsv.hsv = ui_color_to_hsv(UI_COLORS_DEFAULT[ev.color])
			client.colors.selected = .NONE
		case .Select_Color:
			client.colors.selected = ev.color
		case .Connect:
			pure.client_connect(client, ev.endpoint)
		case .Connect_To_Server:
			pure.client_connect(client, ev.endpoint)
		case .Delete_Server:
			_, delete_err := sqlite.exec(client.delete_server, ev.text)
			sqlite.assert_ok(client.delete_server, delete_err)
		case .Refresh_Server_Identity:
			entry := ev.server_info_listener
			entry.expected_identity = {}
		case .Fetch_Server_Info:
			fetch_server_info(ev.server_info_listener, ev.endpoint, client.l)
		case .Save_Server_Id:
			new_server := ev.saved_server

			_, res := sqlite.exec(
				client.save_server,
				new_server.nick_name,
				new_server.conn_string,
				new_server.pk,
			)
			sqlite.assert_ok(client.save_server, res)
		case .Delete_Profile:
			_, delete_err := sqlite.exec(
				client.delete_profile,
				nm.str(&ev.name),
			)
			sqlite.assert_ok(client.delete_profile, delete_err)
		case .Rename_Profile:
			cnt, save_err := sqlite.exec(
				client.edit_profile,
				ev.text,
				nm.str(&ev.name),
			)
			client.profiles.editing_error = ""
			if save_err == .CONSTRAINT {
				client.profiles.editing_error = "name already taken"
			} else {
				sqlite.assert_ok(client.edit_profile, save_err)
				assert(cnt == 1)
			}
		case .Create_Profile:
			pk: sim.Private_Key
			crypto.rand_bytes(pk[:])

			client.profiles.creation_error = ""
			if ev.text == "" {
				client.profiles.creation_error = "name cannot be empty"
			} else {
				_, res := sqlite.exec(client.save_profile, ev.text, pk)
				if res == .CONSTRAINT {
					client.profiles.creation_error = "name already taken"
				} else {
					sqlite.assert_ok(client.save_profile, res)
				}
			}
		case .Download_All_Assets:
			pure.fetch_all_assets(client)
		case .Save_Map:
			mapa := ui_map_export(client)
			pure.tcp_send(client, sim.Client_Map_Edit{mapa = mapa})
		case .Spawn_Ship:
			pure.tcp_send(
				client,
				sim.Client_Cmd {
					type = .Spawn,
					parent = ev.parent,
					id = ev.stats,
				},
			)
		case .Build:
			pure.tcp_send(
				client,
				sim.Client_Cmd {
					type = .Build,
					pos = ev.pos,
					id = ev.stats,
					parent = ev.parent,
					team = ev.team,
				},
			)
			client.bs = {}
		case .Delete_Building:
			pure.tcp_send(client, sim.Client_Cmd{type = .Delete, ent = ev.ent})
			client.bs = {}
		case .Rewire:
			pure.tcp_send(
				client,
				sim.Client_Cmd {
					type = .Rewire,
					parent = ev.parent,
					ent = ev.ent,
				},
			)
			client.bs = {}
		case .Create_Stat:
			stats: sim.Ent_Stats
			stats.name = nm.from_str(ev.text)
			pure.tcp_send(
				client,
				sim.Client_Content_Action{type = .Create, stats = stats},
			)
		case .Upload_Assets:
			client.upload.cursor = 0
			pure.upload_assets(client)
		case .Clear_Assets:
			client.upload.assets = {}
		case .Select_Brush:
			ctx := &client.map_editing
			ctx.editing_brush = ctx.brush == ev.brush
			ctx.brush = ev.brush
		case .Select_Map_Team:
			ctx := &client.map_editing
			ctx.editing_team = ctx.team == ev.team
			ctx.team = ev.team
			team := &ctx.teams[ev.team]
			ctx.color_state.hsv = ui_color_to_hsv(get_color(team.color))
		case .Close_Team_Editor:
			client.map_editing.team = 0
		case .Add_Team:
			append(
				&client.map_editing.teams,
				sim.Ent_Team{color = sim.Color(rand.uint32() | 0x000000FF)},
			)
		case .Send_Chat:
			selected_profile := pure.get_selected_user(client)
			pure.tcp_send(
				client,
				sim.Broadcast_Packet(
					sim.Chat_Msg {
						name = selected_profile.name,
						id = client.handshake.ch.id,
						content = ev.text,
					},
				),
			)
		}
	}
	clear(&client.events)

	for &ev in winning_kb_events {
		if ev.priority == 0 do continue
		#partial switch ev.kind {
		case .Disconnect:
			pure.client_clear_state(client, "manual disconnect")
		case .Quit_Content_Editor:
			client.ui.content_editor.expanded = false
		case .Open_Content_Editor:
			client.ui.content_editor.expanded = true
		case .Save_Content_Changes:
			pure.tcp_send(client, sim.Client_Content_Action{type = .Save})
		case .Close_Stat_Editor:
			client.content_editor.selected = 0
		case .Open_Map_Editor:
			client.ui.map_editing.expanded = true
		case .Close_Map_Editor:
			client.ui.map_editing.expanded = false
		case .Focus:
			orui.current_context.focus_id = ev.target
			orui.current_context.caret_index = ev.carret_index
		case .Apply_Content_Changes:
			pure.tcp_send(
				client,
				sim.Client_Content_Action {
					type = .Edit,
					stats = client.content_editor.stat_edit_state,
				},
			)
		case:
			log.warn("unhandled keybing event:", ev)
		}
	}
}
