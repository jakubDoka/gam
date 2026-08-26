package server

import "../sim"
import "../simt/nbio"
import "../util/arna"
import "../util/bit_arr"
import "../util/hot"
import "../util/nm"
import "../util/rtt"
import "../util/sqlite"
import "base:runtime"
import "core:container/lru"
import "core:fmt"
import "core:log"
import "core:math/linalg"
import "core:mem"
import "core:os"
import "core:reflect"
import "core:sort"
import "core:strings"
import "core:time"
import "core:unicode/utf8"

BUNDLE_PATH :: "bundle.bin"
CONFIG_PATH :: "config/stats.yaml"
CONFIG_PATH_EDITED :: "config/stats.edited.yaml"
SERVER_DB_PATH: cstring : "config/db.db"
SERVER_KEY_PATH :: "config/key.bin"
CONNECTION_TIMEOUT :: 3 * time.Second
HANDSHAKE_STAGE_TIMEOUT :: 500 * time.Millisecond
MAX_CONNECTIONS :: 16
MAX_ACTIVE_PINGS :: MAX_CONNECTIONS * 2
MAX_IP_SIGHTINGS :: 16
MAX_IP_VIOLATIONS :: 8
BANNED_IP_LRU_SIZE :: 1 //1024 * 4
FRAME_TARGET :: time.Second / 60

Default_Map :: struct {
	name, spec: string,
}

@(rodata)
DEFAULT_MAPS := [?]Default_Map {
	{
		"turrets",
		"wwwwwwwwwwwww\n" +
		"w     0     w\n" +
		"w           w\n" +
		"w    www    w\n" +
		"w  w     w  w\n" +
		"w     t     w\n" +
		"w  w     w  w\n" +
		"w    www    w\n" +
		"w  w     w  w\n" +
		"w     t     w\n" +
		"w  w     w  w\n" +
		"w    www    w\n" +
		"w           w\n" +
		"w     1     w\n" +
		"wwwwwwwwwwwww\n",
	},
	{
		"area",
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
		"wwwwwwwwwwwww\n",
	},
}

Connection :: struct {
	using hctx:              sim.Handshake,
	observed_ticks:          int,
	tcp_endpoint:            nbio.Endpoint,
	udp_endpoint:            nbio.Endpoint,
	last_packet:             time.Time,
	input:                   sim.Input_State,
	ent:                     sim.Ent_ID,
	rtt:                     rtt.Estimator,
	using player:            sim.Player,
	next_free:               ^Connection,
	resolving_udp:           bit_arr.DL_Node,
	listener:                bit_arr.DL_Node,
	in_game:                 bit_arr.DL_Node,
	game:                    ^Game,
	last_info:               sim.Server_Info,
	list_stmt:               sqlite.Query(sim.Asset),
	pauses_game_progression: bool,
}

Game :: struct {
	using server:         ^Server,
	players:              bit_arr.DL_List,
	ents:                 sim.Ents,
	net_id:               sim.Ent_Net_ID,
	map_index:            int,
	last_cold_state_hash: sim.Hash,
	last_stats_hash:      sim.Hash,
	clean_stats_hash:     sim.Hash,
	last_map_hash:        sim.Hash,
}

player_next :: proc(cursor: ^bit_arr.DL_Iter) -> (^Connection, bool) {
	return bit_arr.dl_iter_next(
		cursor,
		Connection,
		offset_of(Connection, in_game),
	)
}

game_add_player :: proc(game: ^Game, conn: ^Connection) {
	conn.game = game

	bit_arr.dl_push(&game.players, &conn.in_game)
}

game_tick :: proc(game: ^Game) {
	server := game.server
	game.ents.delta = 1.0 / 60
	game.ents.spawn_seq = &game.net_id
	game.ents.on_laser = on_laser

	on_laser :: proc(ents: ^sim.Ents, l: ^sim.Ent) {
		game := (^Game)(uintptr(ents) - offset_of(Game, ents))
		server := game.server

		cursor := bit_arr.dl_iter(&game.players)
		for p in player_next(&cursor) {
			server_tcp_send(
				server,
				p,
				sim.Server_Cmd {
					type = .Laser,
					pos = l.pos,
					team = l.team,
					stats = l.stats,
					dir = sim.angle_of(l.vel),
				},
			)
		}
	}

	pause_game_progression := false
	cursor := bit_arr.dl_iter(&game.players)
	for p in player_next(&cursor) {
		rtt := rtt.smoothed(&p.rtt)
		sim.ents_integrate_input(&game.ents, p.ent, rtt, &p.input)
		p.observed_ticks += 1
		pause_game_progression |= p.pauses_game_progression
	}

	sim.ents_update(&game.ents)

	if !pause_game_progression {
		alives := make([]bool, len(game.ents.teams), context.temp_allocator)
		iter := sim.ents_iter(&game.ents)
		for e in sim.ents_iter_next(&iter) {
			s := sim.ents_stats_get(&game.ents, e.stats)
			if int(e.team) >= len(alives) do continue
			alives[e.team] |= s.can_spawn_player
		}

		active_teams := 0
		for a in alives do active_teams += int(a)

		if active_teams <= 1 {
			game_load_next_map(game)
		}
	}

	// NOTE: we do a immediate mode synchronization -> check if hash of a
	// packet changed and send it. Nice property of this is that we dont need
	// to remember to sync on mutation although we trade extra computation.
	//
	// Its to be evaluated if that is an actuall performance problem.

	{
		players := make([dynamic]sim.Player, context.temp_allocator)

		cursor := bit_arr.dl_iter(&game.players)
		for c in player_next(&cursor) {
			e := sim.ents_get(&game.ents, c.ent)
			c.player.net_ent = e.net_id
			append(&players, c.player)
		}

		packet := sim.Server_Cold_State {
			players = players[:],
		}

		ensure_up_to_date_hash(
			game,
			&game.last_cold_state_hash,
			packet,
			"cold state",
		)
	}

	{
		map_buf := sim.cc_encode_to_bytes(
			game.ents.mapa,
			context.temp_allocator,
		)
		packet := sim.Server_Map{game.ents.map_name, map_buf}
		ensure_up_to_date_hash(game, &game.last_map_hash, packet, "map")
	}

	{
		stat_buf := sim.cc_encode_to_bytes(
			game.ents.stats[:],
			context.temp_allocator,
		)
		packet := sim.Server_Stats {
			stats = stat_buf,
		}

		ensure_up_to_date_hash(game, &game.last_stats_hash, packet, "stats")

		if game.clean_stats_hash == {} {
			game.clean_stats_hash = game.last_stats_hash
		}
	}

	ensure_up_to_date_hash :: proc(
		game: ^Game,
		hash: ^sim.Hash,
		packet: sim.Server_Packet,
		subject: string,
	) {
		buf := sim.serialize_to_bytes(packet, context.temp_allocator)

		new_hash: sim.Hash
		sim.hash(buf, &new_hash)

		cursor := bit_arr.dl_iter(&game.players)
		for c in player_next(&cursor) {
			if new_hash != hash^ || c.observed_ticks == 1 {
				sim.tcp_connection_send(&c.hctx, buf, game.l)
			}
		}
		hash^ = new_hash
	}
}

game_destroy :: proc(game: ^Game) {
	sim.ents_destroy(&game.ents)
}

Ip_Sighting :: struct {
	user_id:      int,
	ip_lo, ip_hi: i64,
}

Saved_IP :: struct {
	ip_lo, ip_hi: i64,
}

ip_to_integers :: proc(ip: nbio.Address) -> Saved_IP {
	switch i in ip {
	case nbio.IP4_Address:
		return {i64(transmute(i32)i) | 0x0000FFFF00000000, 0}
	case nbio.IP6_Address:
		return transmute(Saved_IP)i
	case:
		panic("unknown address type")
	}
}

Saved_Asset :: struct {
	using base: sim.Asset,
	id:         sim.Asset_ID,
}

Server_Statements :: struct {
	insert_user:         sqlite.Statement `
		INSERT INTO user (name, pk, permissions) VALUES (?, ?, ?) RETURNING id
	`,
	select_user_by_pk:   sqlite.Statement `
		SELECT * FROM user WHERE pk = ?
	`,
	update_user_name:    sqlite.Statement `
		UPDATE user SET name = ? WHERE id = ?
	`,
	select_users:        sqlite.Statement `
		SELECT * FROM user
	`,
	insert_ip_sighting:  sqlite.Statement `
		INSERT INTO ip_sighting (user_id, ip_hi, ip_lo) VALUES (?, ?, ?)
	`,
	count_ip_sightings:  sqlite.Statement `
		SELECT COUNT(*) FROM ip_sighting WHERE ip_hi = ? AND ip_lo = ?
	`,
	select_ip_sightings: sqlite.Statement `
		SELECT * FROM ip_sighting
	`,

	// NOTE: we dont repopulate assets, the client cache identifies the assets
	// by thie id between connections
	save_asset:          sqlite.Statement `
		INSERT INTO asset (id, name, hash, size, type, visited)
		VALUES (?, ?, ?, ?, ?, 1)
		ON CONFLICT (name, type) DO UPDATE
			SET id = ?1, hash = ?3, size = ?4, visited = 1
	`,
	count_assets:        sqlite.Statement `
		SELECT count(*) FROM asset
	`,
	select_assets:       sqlite.Statement `
		SELECT * FROM asset
	`,
	get_asset_by_name:   sqlite.Statement `
		SELECT * FROM asset WHERE name = ? AND type = ?
	`,
	get_asset:           sqlite.Statement `
		SELECT * FROM asset WHERE id = ?
	`,
	delete_asset:        sqlite.Statement `
		DELETE FROM asset WHERE name = ? AND type = ? RETURNING id
	`,
	prune_assets:        sqlite.Statement `
		DELETE FROM asset WHERE visited = 0
	`,
}

Banned_Ip_Entry :: struct {
	violation_count: int,
}

Ping_Entry_Stage :: enum u8 {
	Queued,
	Sent,
	Recvd,
}

Ping_Entry :: struct {
	arrival: time.Time,
	stage:   Ping_Entry_Stage,
	nonce:   u8,
	secret:  sim.Secret_Key,
	conn:    ^Connection,
}

Config :: struct {
	endpoint: nbio.Endpoint,
	cwd:      string,
	db:       sqlite.Connection,
}

Server :: struct {
	active_pings:            lru.Cache(sim.Ping_ID, Ping_Entry),
	banned_ips:              lru.Cache(Saved_IP, Banned_Ip_Entry),
	free_conns:              ^Connection,
	connections:             map[nbio.Endpoint]^Connection,
	pk:                      sim.Private_Key,
	ping_seq:                int,
	udp:                     sim.UDP_Connection,
	tcp:                     nbio.TCP_Socket,
	acceptor:                ^nbio.Operation,
	ping_interval:           ^nbio.Operation,
	tick_interval:           ^nbio.Operation,
	last_udp_conn:           ^Connection,
	resolving_udp:           bit_arr.DL_List,
	listeners:               bit_arr.DL_List,
	lobby:                   Game,
	next_frame:              time.Time,
	next_peer_id:            u32,
	content_spec:            sim.Content_Spec,
	tps:                     int,
	frames_since_tps_sample: int,
	frame_sample_time:       time.Time,
	using statements:        Server_Statements,
	conn_buf:                []Connection,
	lru_pool:                arna.Allocator,
	map_load_arna:           arna.Allocator,
	l:                       ^nbio.Event_Loop,
	hr:                      ^hot.Reloader,
	did_shutdown:            bool,
	last_ping:               time.Time,
	using config:            ^Config,
}

server_add_violation :: proc(server: ^Server, ip: Saved_IP) {
	entry, ok := lru.get_ptr(&server.banned_ips, ip)
	if ok {
		entry.violation_count += 1
		return
	}
	lru.set(&server.banned_ips, ip, Banned_Ip_Entry{violation_count = 1})
}

server_is_banned :: proc(server: ^Server, ip: Saved_IP) -> bool {
	entry, ok := lru.get_ptr(&server.banned_ips, ip)
	return ok && entry.violation_count >= MAX_IP_VIOLATIONS
}

server_clear_violations :: proc(server: ^Server, ip: Saved_IP) {
	v, _ := lru.get_ptr(&server.banned_ips, ip)
	if v != nil do v.violation_count = 0
}

server_handle_packet :: proc(
	server: ^Server,
	from: ^sim.TCP_Connection,
	packet_bytes: []u8,
) -> (
	ok: bool,
) {
	#assert(offset_of(Connection, hctx) == 0)
	#assert(offset_of(sim.Handshake, tcp) == 0)

	packet := sim.unmarshall_as(sim.Client_Packet, packet_bytes) or_return

	reason := ""
	defer if !ok do log.warn("invalid packet from client (", reason, ")")

	from := (^Connection)(from)
	game := from.game

	assert(game != nil)

	from.last_packet = nbio.now(server.l)

	// TODO: as of right now custom client can fuck us
	switch &p in packet {
	case sim.Client_Input:
		if from.input.seq < p.seq {
			from.input.inner = p
			e := sim.ents_get(&game.ents, from.ent)

			players := make(
				[dynamic]sim.Client_Input_Keys,
				context.temp_allocator,
			)
			cursor := bit_arr.dl_iter(&game.players)
			for p in player_next(&cursor) {
				append(&players, p.input.keys)
			}

			server_udp_send(
				server,
				from,
				sim.Server_State {
					tps = server.tps,
					you = e.net_id,
					your_next_net_id = from.input.next_net_id,
					ents = {value = {&game.ents, encode_state}},
					map_hash = game.last_map_hash,
					players = players[:],
				},
			)

			encode_state :: proc(data: rawptr, e: ^sim.Encoder) -> bool {
				ents := (^sim.Ents)(data)
				iter := sim.ents_iter(ents)
				for ent in sim.ents_iter_next(&iter) {
					assert(ent.team >= 0)
					sim.ent_synced_encode(ent, ents, e) or_return
				}
				return true
			}
		}
	case sim.Client_Cmd:
		switch p.type {
		case .Abandon:
			sim.ents_queue_remove(&game.ents, from.ent)
		case .Build:
			parent := game_ent_by_net_id(game, p.parent)

			team := p.team
			if parent.team != 0 do team = parent.team

			reason = "building outside bind range"
			ps := sim.ents_stats_get(&game.ents, parent.stats)
			if parent != sim.NIL_ENT {
				if linalg.distance(p.pos, parent.pos) > ps.bind_range {
					return
				}
			}

			reason = "building over something elese"
			tile := sim.map_vec_to_pos(p.pos)
			for it := sim.ents_iter(&game.ents); e in sim.ents_iter_next(&it) {
				s := sim.ents_stats_get(&game.ents, e.stats)
				if tile == sim.map_vec_to_pos(e.pos) && s.kind == .Building {
					return
				}
			}

			reason = "placing into solid terrain"
			if sim.map_tile_is_solid(&game.ents, tile) do return

			e := sim.ents_add(&game.ents, &game.net_id)
			if e == sim.NIL_ENT do break
			s := sim.ents_stats_get(&game.ents, p.id)
			e.energy_consumed = s.energy - 0.1
			e.pos = sim.map_pos_to_vec(tile)
			e.stats = p.id
			e.parent = parent.id
			e.team = team
		case .Delete:
			e := game_ent_by_net_id(game, p.ent)
			s := sim.ents_stats_get(&game.ents, e.stats)
			parent := sim.ents_get(&game.ents, e.parent)
			if parent != sim.NIL_ENT {
				parent.energy_consumed -= s.energy - e.energy_consumed
			}
			sim.ents_queue_remove(&game.ents, e.id)
		case .Rewire:
			e := game_ent_by_net_id(game, p.ent)

			if e != sim.NIL_ENT {
				ep := game_ent_by_net_id(game, p.parent)
				e.parent = ep.id
				e.parent_net_id = ep.net_id
			}
		case .Spawn:
			reason = "already spawned"
			if sim.ents_is_valid(&game.ents, from.ent) do return

			counts := make([]int, len(game.ents.teams), context.temp_allocator)

			cursor := bit_arr.dl_iter(&game.players)
			for p in player_next(&cursor) {
				e := sim.ents_get(&game.ents, p.ent)
				counts[e.team] += 1
			}

			c := game_ent_by_net_id(game, p.parent)

			reason = "invalid team to spawn"
			if !sim.team_spawnable(c.team, counts) do return

			e := sim.ents_add(&game.ents, &game.net_id)
			if e == sim.NIL_ENT do break

			s := sim.ents_stats_get(&game.ents, p.id)

			e.energy_consumed = s.energy
			e.pos = c.pos
			e.stats = p.id
			e.team = c.team
			e.parent = c.parent
			from.ent = e.id
		}
	case sim.Client_Control:
		e := sim.ents_get(&game.ents, from.ent)
		if e != sim.NIL_ENT {
			e.objective.gen += 1
			for eid in p.ents {
				ce := game_ent_by_net_id(game, eid)
				if ce == sim.NIL_ENT do continue
				ce.objective = p.objective
				ce.objective.commander = from.ent
				ce.objective.gen = e.objective.gen
			}
		}
	case sim.Client_Cold_State:
		name := nm.str(&p.username)

		from.pauses_game_progression = p.pause_game_progression

		login: if len(name) != 0 {
			ip := ip_to_integers(from.tcp_endpoint.address)
			query_res, s := sqlite.query(
				server.select_user_by_pk,
				from.player,
				from.pk,
			)
			defer sqlite.reset(s)

			if query_res != .DONE {
				sqlite.assert_ok(server.select_user_by_pk, query_res)
				break login
			}

			log.info("encountered new user:", from.pk)

			count: int
			sighting_res, ss := sqlite.query(
				server.count_ip_sightings,
				count,
				ip.ip_hi,
				ip.ip_lo,
			)
			sqlite.assert_ok(server.count_ip_sightings, sighting_res)
			sqlite.reset(ss)

			if count >= MAX_IP_SIGHTINGS {
				server_add_violation(server, ip)
				log.warn(
					"ip sighting limit reached:",
					from.tcp_endpoint.address,
				)
				return
			}

			id: int
			insert_res, is := sqlite.query(
				server.insert_user,
				id,
				name,
				from.pk,
				-1,
			)
			sqlite.assert_ok(server.insert_user, insert_res)
			sqlite.reset(is)

			_, insert_res = sqlite.exec(
				server.insert_ip_sighting,
				id,
				ip.ip_hi,
				ip.ip_lo,
			)
			sqlite.assert_ok(server.insert_ip_sighting, insert_res)

			query_res, s = sqlite.query(
				server.select_user_by_pk,
				from.player,
				from.pk,
			)
			sqlite.assert_ok(server.select_user_by_pk, query_res)
			sqlite.reset(s)

			server_clear_violations(server, ip)
		}

	case sim.Client_Content_Action:
		switch p.type {
		case .Create:
			stats := p.stats
			stats.id = auto_cast len(game.ents.stats)

			sim.validate(
				stats,
				{stat_count = len(game.ents.stats) + 1},
			) or_return

			append(&game.ents.stats, stats)
		case .Edit:
			reason = "id out of bounds"
			if p.stats.id < 0 || int(p.stats.id) >= len(game.ents.stats) do return
			stats := p.stats

			reason = "validation failed"
			sim.validate(stats, {stat_count = len(game.ents.stats)}) or_return

			game.ents.stats[stats.id] = stats

			reason = ""
		case .Delete_Stat:
			reason = "id out of bounds"
			if p.stats.id < 0 || int(p.stats.id) >= len(game.ents.stats) do return

			ordered_remove(&game.ents.stats, p.stats.id)
			for &stat, i in game.ents.stats do stat.id = auto_cast i

			for it := sim.ents_iter(&game.ents); e in sim.ents_iter_next(&it) {
				if e.stats == p.stats.id {
					sim.ents_queue_remove(&game.ents, e.id)
				} else if e.stats > p.stats.id {
					e.stats -= 1
				}
			}
		case .Switch:
			name := nm.str(&p.switch_to)

			reason = "invalid asset name to switch to"
			if !sim.validate_asset_name(name) do return

			asset := sim.Asset {
				name = p.switch_to,
				type = .Map,
			}
			path := asset_path(&asset, context.temp_allocator)

			content, err := nbio.read_entire_file(
				server.l,
				path,
				context.temp_allocator,
			)
			reason = "nonexistent asset name to switch to"
			if err != nil {
				log.warn("failed to load stat group to switch to:", err)
				return
			}

			d := sim.Decoder{content}
			mapa, ok := sim.cc_decode_single_alloc(
				sim.Map,
				&d,
				&server.map_load_arna,
			)
			reason = "invalid map file in our saves, dang"
			if !ok do return

			game_set_map(game, p.switch_to, mapa)
		case .Save_Map:
			name := nm.str(&p.create_as)

			reason = "invalid asset name to create"
			if !sim.validate_asset_name(name) do return

			mapa := game.ents.mapa
			mapa.asoc_stats = game.ents.stats[:]
			buf := sim.cc_encode_to_bytes(mapa, context.temp_allocator)

			asset := sim.Asset {
				name = p.create_as,
				type = .Map,
				size = len(buf),
			}
			sim.hash(buf, &asset.hash)

			path := asset_path(&asset, context.temp_allocator)

			err := nbio.make_directory_all(nbio.dir(path))
			fmt.assertf(
				err == nil || err == .Exist,
				"failed to create parents of stat group: %v",
				err,
			)

			err = nbio.write_entire_file(server.l, path, buf)
			assert(err == nil)

			save_asset(server, &asset)

			game.ents.map_name = p.create_as
		case .Delete_Map:
			name := nm.str(&p.delete_the)

			reason = "invalid asset name to delete"
			if !sim.validate_asset_name(name) do return

			delete_asset(server, p.delete_the, .Map)
		}
	case sim.Client_Map_Edit:
		asset := sim.Asset {
			name = game.ents.map_name,
			type = .Map,
		}

		d := sim.Decoder{p.mapa}
		mapa, ok := sim.cc_decode_single_alloc(
			sim.Map,
			&d,
			&server.map_load_arna,
			context.allocator,
		)

		reason = "invalid map file sent"
		if !ok do return

		game_set_map(game, game.ents.map_name, mapa)

		asset.size = len(p.mapa)
		sim.hash(p.mapa, &asset.hash)

		map_path := asset_path(&asset, context.temp_allocator)
		err := nbio.write_entire_file(server.l, map_path, p.mapa)
		log.assertf(err == nil, "failed to write the map: %v", err)

		save_asset(server, &asset)
	case sim.Broadcast_Packet:
		cursor := bit_arr.dl_iter(&game.players)
		for player in player_next(&cursor) {
			server_tcp_send(server, player, p)
		}
	}

	return true
}

server_get_asset :: proc(
	server: ^Server,
	id: sim.Asset_ID,
) -> (
	ass: Saved_Asset,
	ok: bool,
) {
	res, stmt := sqlite.query(server.get_asset, ass, id)
	sqlite.reset(stmt)
	if res == .DONE do return
	sqlite.assert_ok(stmt, res)

	ok = true
	return
}

game_ent_by_net_id :: proc(game: ^Game, id: sim.Ent_Net_ID) -> ^sim.Ent {
	// TODO(low): build a net id index instead, this is a strain on the server
	// low: because a single game has very little entities, it might actually
	// be contraproductive
	// maybe better use of time is u8 hash as a parallel array
	iter := sim.ents_iter(&game.ents)
	for e in sim.ents_iter_next(&iter) {
		if e.net_id == id {
			return e
		}
	}
	return sim.NIL_ENT
}

pick_map :: proc(
	l: ^nbio.Event_Loop,
	index: int,
	temp_allocator: runtime.Allocator,
) -> (
	string,
	nm.Name,
) {
	map_entries, map_entries_err := nbio.read_all_directory_by_path(
		l,
		sim.MAP_DIR,
		temp_allocator,
	)
	log.assertf(
		map_entries_err == nil,
		"failed to read maps: %v",
		map_entries_err,
	)

	sort.merge_sort_proc(map_entries, compare_file_entries)

	compare_file_entries :: proc(a: nbio.File_Info, b: nbio.File_Info) -> int {
		return sort.compare_strings(a.name, b.name)
	}

	choosen := map_entries[index % len(map_entries)]

	full_path, fperr := nbio.join_path(
		{sim.MAP_DIR, choosen.name},
		temp_allocator,
	)
	assert(fperr == nil)

	// TODO(low): dont panic here and actually validate

	return full_path, nm.from_str(
		choosen.name[:len(choosen.name) - len(sim.MAP_EXT)],
	)
}

game_load_next_map :: proc(game: ^Game) {
	temp_allocator := context.temp_allocator

	map_path, name := pick_map(game.l, game.map_index, temp_allocator)
	game.map_index += 1

	map_bytes, map_bytes_err := nbio.read_entire_file(
		game.l,
		map_path,
		context.temp_allocator,
	)
	assert(map_bytes_err == nil)

	d := sim.Decoder{map_bytes}
	mapa, ok := sim.cc_decode_single_alloc(
		sim.Map,
		&d,
		&game.server.map_load_arna,
	)
	assert(ok)

	game_set_map(game, name, mapa)
}

// takes ownership of buf
game_set_map :: proc(game: ^Game, name: nm.Name, mapa: ^sim.Map) {
	sim.ents_clear(&game.ents)
	sim.ents_set_map(&game.ents, mapa)
	game.ents.map_name = name

	sim.ents_load_stats(&game.ents, game.ents.asoc_stats)

	map_ent_to_ent := make(
		[]^sim.Ent,
		len(game.ents.mapa.ents),
		context.temp_allocator,
	)

	if len(map_ent_to_ent) != 0 {
		map_ent_to_ent[0] = sim.NIL_ENT
	}

	prefix := min(1, len(game.ents.mapa.ents))

	for ent, i in game.ents.mapa.ents[prefix:] {
		e := sim.ents_add(&game.ents, &game.net_id)
		if e == sim.NIL_ENT do break
		e.pos = sim.map_pos_to_vec(ent.pos)
		e.stats = ent.stat
		e.team = ent.team
		map_ent_to_ent[prefix + i] = e
	}

	for ent, i in game.ents.mapa.ents[prefix:] {
		e := map_ent_to_ent[prefix + i]
		p := map_ent_to_ent[ent.parent]
		e.parent = p.id
	}
}

server_on_accept :: proc(op: ^nbio.Operation, server: ^Server) {
	assert(op.accept.err == nil)

	log.debug("got connection:", op.accept)

	kill := true
	defer if kill do nbio.close(op.accept.client, l = server.l)

	server.acceptor = nbio.accept_poly(
		op.accept.socket,
		server,
		server_on_accept,
		l = op.l,
	)

	ip := ip_to_integers(op.accept.client_endpoint.address)
	if server_is_banned(server, ip) {
		log.warn("ip is banned:", op.accept)
		return
	}

	if server.free_conns == nil {
		log.warn("connection capacity reached, dropping")
		return
	}

	conn := server.free_conns
	server.free_conns = conn.next_free

	assert(op.accept.client != 0)

	conn^ = {}
	conn.l = op.l
	conn.tcp_endpoint = op.accept.client_endpoint
	conn.last_packet = nbio.now(server.l)
	conn.hctx.sock = op.accept.client
	conn.hctx.host.asoc_data = server
	conn.hctx.cleanup = server_on_tcp_kill
	conn.hctx.on_boot = on_boot
	conn.hctx.get_pk = get_pk

	nbio.set_lable(server.l, conn.sock, "init")

	conn_id := int(
		(uintptr(conn) - uintptr(raw_data(server.conn_buf))) /
		size_of(Connection),
	)
	(^sim.Server_Init_Data)(raw_data(&conn.sh.payload))^ = {
		conn_id = conn_id,
	}

	sim.hctx_connect_server(&conn.hctx, server.l)

	kill = false

	get_pk :: proc(conn: ^Connection) -> sim.Private_Key {
		return conn.xpk
	}

	on_boot :: proc(conn: ^Connection) -> bool {
		assert(conn.tcp.sock != 0)

		server := (^Server)(conn.hctx.host.asoc_data)
		request := (^sim.Client_Request_Header)(&conn.ch.payload)

		REQUIRES_AUTH :: ~bit_set[sim.Client_Request_Type] {
			.Play,
			.Watch_Server_Info,
		}

		if request.kind in REQUIRES_AUTH {
			if request.conn_id >= len(server.conn_buf) {
				return sim.hctx_fail(conn, "oob request conn id")
			}

			other := &server.conn_buf[request.conn_id]
			if other.ch.id == {} {
				return sim.hctx_fail(
					conn,
					"trying to referece invalid connection",
				)
			}

			// NOTE: we are comparing publick key material so time attacks
			// should not be a problem? We are signed.
			if other.ch.id != conn.ch.id {
				return sim.hctx_fail(conn, "identity mismatch for the request")
			}
		}

		Handler_Proc :: #type proc(
			_: ^Server,
			_: ^Connection,
			_: ^sim.Client_Request_Header,
		) -> bool

		handlers := [sim.Client_Request_Type]Handler_Proc {
			.Download_Content  = send_asset,
			.Play              = boot_player,
			.Watch_Server_Info = stream_server_info,
			.Upload_Content    = recv_asset,
			.List_Assets       = list_assets,
		}

		if len(handlers) <= int(request.kind) {
			return sim.hctx_fail(
				conn,
				"received out of range Client_Request_Type",
				request.kind,
			)
		}

		h := handlers[request.kind]
		if h != nil {
			nbio.set_lable(
				server.l,
				conn.sock,
				reflect.enum_name_from_value(request.kind) or_else panic(""),
			)

			return h(server, conn, request)
		}

		return sim.hctx_fail(conn, "unimplemented handler", request.kind)
	}
}

stream_server_info :: proc(
	server: ^Server,
	conn: ^Connection,
	request: ^sim.Client_Request_Header,
) -> bool {
	log.debug("registering info listener")

	sim.tcp_connection_boot(&conn.hctx, 0, 512, l = server.l)
	bit_arr.dl_push(&server.listeners, &conn.listener)

	return true
}

boot_player :: proc(
	server: ^Server,
	conn: ^Connection,
	request: ^sim.Client_Request_Header,
) -> bool {
	log.debug("connection authenticated")
	sim.tcp_connection_boot(
		&conn.hctx,
		sim.SERVER_RECV_BUF_SIZE,
		sim.CLIENT_RECV_BUF_SIZE,
		l = server.l,
	)

	conn.hctx.tcp.host.on_packet = server_on_tcp_packet

	server.next_peer_id += 1
	conn.input.next_net_id.peer = server.next_peer_id
	conn.pk = conn.hctx.ch.id

	bit_arr.dl_push(&server.resolving_udp, &conn.resolving_udp)

	game_add_player(&server.lobby, conn)

	return true
}

recv_asset :: proc(
	server: ^Server,
	conn: ^Connection,
	request: ^sim.Client_Request_Header,
) -> bool {
	conn.asset_path = asset_path_
	conn.cleanup = on_kill

	sim.fetch_asset(conn)
	return conn->on_boot()

	asset_path_ :: proc(conn: ^Connection) -> string {
		return asset_path(&conn.fetch.asset_meta, context.allocator)
	}

	on_kill :: proc(conn: ^Connection) {
		server := (^Server)(conn.host.asoc_data)

		if conn.last_error == "" {
			save_asset(server, &conn.fetch.asset_meta)
		}

		server_on_tcp_kill(conn)
	}
}

save_asset :: proc(server: ^Server, asset: ^sim.Asset, broadcast := true) {
	_, sares := sqlite.exec(
		server.save_asset,
		sim.hash_prefix(&asset.hash),
		nm.str(&asset.name),
		asset.hash,
		asset.size,
		asset.type,
	)
	sqlite.assert_ok(server.save_asset, sares)

	if broadcast {
		for _, conn in server.connections {
			if .Edit_Content in conn.permissions {
				server_tcp_send(server, conn, asset^)
			}
		}
	}
}

delete_asset :: proc(server: ^Server, name: nm.Name, type: sim.Asset_Type) {
	id: sim.Asset_ID
	deres, s := sqlite.query(server.delete_asset, id, name, type)
	if deres == .DONE {
		log.warn("deleteing asset that is not in the db:", name, type)
		return
	}
	sqlite.assert_ok(s, deres)
	sqlite.reset(s)

	asset := sim.Asset {
		name = name,
		type = type,
	}

	path := asset_path(&asset, context.temp_allocator)

	err := nbio.delete_file(server.l, path)
	if err != nil {
		log.warn("Failed to delete the asset file it self:", name, type, err)
	}

	for _, conn in server.connections {
		if .Edit_Content in conn.permissions {
			server_tcp_send(
				server,
				conn,
				sim.Server_Asset_Deleted{id = id, name = name},
			)
		}
	}
}

list_assets :: proc(
	server: ^Server,
	conn: ^Connection,
	request: ^sim.Client_Request_Header,
) -> bool {
	stmt: sqlite.Statement
	sqlite.prepare(
		&stmt,
		sqlite.db_handle(server.statements.select_assets),
		string(sqlite.sql(server.statements.select_assets)),
	)

	conn.list_stmt, _ = sqlite.query(stmt, sim.Asset)
	conn.tcp.send_buf = make([]u8, sim.ASSET_BUF_SIZE)

	do_progress(conn)
	return true

	do_progress :: proc(conn: ^Connection) {
		if conn.list_stmt.stmt == {} {
			sim.tcp_connection_kill(conn, l = conn.l)
			return
		}

		buf := sim.tcp_connection_send_buffer(conn)
		elems := mem.slice_data_cast([]sim.Asset_ID, buf)
		cnt := 0
		for asset in sqlite.query_next_iter(&conn.list_stmt) {
			if cnt >= len(elems) do break
			elems[cnt] = sim.hash_prefix(&asset.hash)
			cnt += 1
		}

		if cnt != len(elems) {
			sqlite.finalize(&conn.list_stmt.stmt)
		}

		sim.tcp_connection_send_filled(
			conn,
			size_of(sim.Asset_ID) * cnt,
			on_sent,
			l = conn.l,
		)
	}

	on_sent :: proc(op: ^nbio.Operation, sock: ^Connection) {
		sock.tcp.sender = nil
		sim.hctx_fail_guard(sock, "failed to send asset chunk", op.send.err)
		if op.send.err != nil do return
		do_progress(sock)
		sock.error = ""
	}
}

send_asset :: proc(
	server: ^Server,
	conn: ^Connection,
	request: ^sim.Client_Request_Header,
) -> bool {
	asset := server_get_asset(server, request.download_content.id) or_return
	assert(asset != {})

	conn.send.asset = asset
	conn.asset_path = asset_path_
	sim.send_asset(conn)

	asset_path_ :: proc(conn: ^Connection) -> string {
		return asset_path(&conn.send.asset, context.allocator)
	}

	return true
}

asset_path :: proc(asset: ^sim.Asset, allc: runtime.Allocator) -> string {
	name_str := nm.str(&asset.name)

	// NOTE: it suffices to return null value since subsequent file operations
	// will fail on this
	if strings.contains(name_str, ".") do return ""
	if !utf8.valid_string(name_str) do return ""

	dir := sim.DIR_BY_TYPE[asset.type]
	ext := sim.EXT_BY_TYPE[asset.type]

	name := strings.join({name_str, ext}, "", context.temp_allocator)
	path, _ := nbio.join_path({dir, name}, allc)
	return path
}

server_on_tcp_kill :: proc(conn: ^Connection) {
	server := (^Server)(conn.host.asoc_data)
	game := conn.game

	conn.next_free = server.free_conns
	server.free_conns = conn

	bit_arr.dl_remove(&conn.resolving_udp)
	bit_arr.dl_remove(&conn.listener)
	bit_arr.dl_remove(&conn.in_game)

	delete_key(&server.connections, conn.udp_endpoint)
	delete_key(&server.connections, conn.tcp_endpoint)

	if game != nil {
		sim.ents_queue_remove(&game.ents, conn.ent)
	}

	sqlite.finalize(&conn.list_stmt.stmt)

	log.debug("killed the connection")
}

server_on_tcp_packet :: proc(
	conn: ^sim.TCP_Connection,
	l: ^nbio.Event_Loop,
	bytes: []u8,
) -> bool {
	server := (^Server)(conn.host.asoc_data)
	return server_handle_packet(server, conn, bytes)
}

server_schedule_tick :: proc(server: ^Server) {
	server.next_frame = time.time_add(server.next_frame, FRAME_TARGET)
	diff := time.diff(nbio.now(server.l), server.next_frame)
	server.next_frame = time.time_add(server.next_frame, -min(diff, 0))
	server.tick_interval = nbio.timeout_poly(
		max(diff, 1),
		server,
		server_on_tick,
		l = server.l,
	)

	server.frames_since_tps_sample += 1
	if nbio.since(server.l, server.frame_sample_time) > time.Second {
		server.tps = server.frames_since_tps_sample
		server.frame_sample_time = nbio.now(server.l)
		server.frames_since_tps_sample = 0
	}
}

server_on_tick :: proc(op: ^nbio.Operation, server: ^Server) {
	server.tick_interval = nil

	interrupted := hot.interrupted()

	res := server.hr->reload({skip_full_reload = true})

	if interrupted || res == .Full_Reboot {
		server_shutdown(server)
		server.hr.force_reload = true
		return
	}

	if res == .Refresh do return

	game_tick(&server.lobby)

	server_schedule_tick(server)

	free_all(context.temp_allocator)
}

sync_assets :: proc(server: ^Server) {
	Ctx :: struct {
		server: ^Server,
		type:   sim.Asset_Type,
		allc:   runtime.Allocator,
	}
	ctx: Ctx
	ctx.server = server
	ctx.allc = context.allocator
	context.user_ptr = &ctx

	ctx.type = .Map
	visit_files(server.l, server.cwd, sim.MAP_DIR, sim.MAP_EXT, visit_file)
	ctx.type = .Sprite
	visit_files(
		server.l,
		server.cwd,
		sim.SPRITE_DIR,
		sim.SPRITE_EXT,
		visit_file,
	)

	visit_file :: proc(name: string, content: []u8) {
		ctx := (^Ctx)(context.user_ptr)

		asset: Saved_Asset
		asset.name = nm.from_str(name)
		sim.hash(content, &asset.hash)
		asset.size = len(content)
		asset.type = ctx.type
		delete(content)

		context.allocator = ctx.allc
		save_asset(ctx.server, &asset, broadcast = false)
	}

	_, psres := sqlite.exec(server.prune_assets)
	sqlite.assert_ok(server.prune_assets, psres)
}

load_stats :: proc(server: ^Server, config: string) -> [dynamic]sim.Ent_Stats {
	loader: sim.Asset_Loader
	loader.asoc_data = server
	loader.path = CONFIG_PATH
	loader.source = config
	loader.load_sprite = load_sprite
	sim.load_config(&loader)

	return loader.stats

	load_sprite :: proc(
		loader: ^sim.Asset_Loader,
		name: string,
	) -> (
		sim.Asset_ID,
		string,
	) {
		server := (^Server)(loader.asoc_data)
		asset: Saved_Asset
		res, stmt := sqlite.query(
			server.get_asset_by_name,
			asset,
			name,
			sim.Asset_Type.Sprite,
		)
		sqlite.reset(stmt)
		if res == .DONE {
			return {}, "sprite not found in the assets"
		}
		return asset.id, ""
	}
}

visit_files :: proc(
	l: ^nbio.Event_Loop,
	cwd: string,
	dir: string,
	ext: string,
	visit: proc(_: string, _: []u8),
) -> (
	count: int,
) {
	context.allocator = context.temp_allocator

	dir, dir_err := nbio.join_path({cwd, dir}, context.allocator)
	log.assertf(dir_err == nil, "failed to join path: %v", dir_err)

	// TODO(low): make this recursive
	fifo, fifo_err := nbio.read_all_directory_by_path(l, dir)
	log.assertf(fifo_err == nil, "failed to read dir entries: %v", fifo_err)

	for entry in fifo {
		if entry.type != .Regular do continue
		if !strings.has_suffix(entry.fullpath, ext) do continue

		rel_path := entry.fullpath[len(dir) + 1:]
		rel_path = rel_path[:len(rel_path) - len(ext)]

		data, err := nbio.read_entire_file(
			l,
			entry.fullpath,
			context.allocator,
		)
		log.assertf(err == nil, "failed to read sprite file: %v", err)

		visit(rel_path, data)

		count += 1
	}

	return
}

@(export)
server_memory_size :: proc() -> (sum: int) {
	for t in sim.HOT_TYPES do sum += size_of(t)
	sum += size_of(Server)
	sum += size_of(Connection)

	return
}

@(export)
server_static_init :: proc(params: hot.Static_Init_Params) {
	sim.register_user_formatters()
	hot.sip = params
}

@(export)
server_static_deinit :: proc() {
	sim.unregister_user_formatters()
}

@(export)
server_init :: proc(hr: ^hot.Reloader, config: ^Config) -> (server: ^Server) {
	server = server_init_without_game(hr, config)

	init_world: {
		game := &server.lobby
		game.server = server
		sim.ents_reserve(&game.ents, 128)
		game_load_next_map(game)
	}

	return
}

server_init_without_game :: proc(
	hr: ^hot.Reloader,
	config: ^Config,
) -> (
	server: ^Server,
) {
	context.allocator = hr.init_allocator
	append(&hr.rewire_table, ..REWIRE_TABLE[:])

	server = new(Server)
	server.config = config
	server.l = hr.l
	server.hr = hr

	server.map_load_arna = arna.init_from_buffer(make([]u8, sim.MAX_MAP_SIZE))

	lru.init(
		&server.banned_ips,
		BANNED_IP_LRU_SIZE,
		node_allocator = hr.init_allocator,
	)
	lru.init(
		&server.active_pings,
		MAX_ACTIVE_PINGS,
		node_allocator = hr.init_allocator,
	)

	sqlite.exec(server.db, #load("schema.sql", cstring))
	sqlite.prepare(server.db, server.statements)

	init_resources: {
		sim.packet_buffer_reserve(&server.udp.send_buf, 8)

		server.conn_buf = make([]Connection, MAX_CONNECTIONS)
		for &c in server.conn_buf {
			c.next_free = server.free_conns
			server.free_conns = &c
		}
	}

	init_config: {
		defer free_all(context.temp_allocator)

		{
			if _, err := nbio.stat(
				server.l,
				SERVER_KEY_PATH,
				context.temp_allocator,
			); err != nil {
				sim.private_key_generate(&server.pk)
				err := nbio.write_entire_file(
					server.l,
					SERVER_KEY_PATH,
					server.pk[:],
				)
				log.assertf(
					err == nil,
					"failed to create %v: %v",
					SERVER_KEY_PATH,
					err,
				)
			}

			bytes, err := nbio.read_entire_file(
				server.l,
				SERVER_KEY_PATH,
				context.temp_allocator,
			)
			log.assertf(
				err == nil,
				"failed to open %v: %v",
				SERVER_KEY_PATH,
				err,
			)
			copy(server.pk[:], bytes)
		}

		if _, err := nbio.stat(server.l, sim.MAP_DIR, context.temp_allocator);
		   err != nil {
			create_dir_err := nbio.make_directory_all(sim.MAP_DIR)
			log.assertf(
				create_dir_err == nil,
				"failed to create the maps dir: %v",
				create_dir_err,
			)

			empty_map: sim.Map
			buf := sim.cc_encode_to_bytes(empty_map, context.temp_allocator)

			asset := sim.Asset {
				name = nm.from_str("empty"),
				type = .Map,
			}

			path := asset_path(&asset, context.temp_allocator)

			write_map_err := nbio.write_entire_file(server.l, path, buf)
			log.assertf(
				write_map_err == nil,
				"failed to write map: %v",
				write_map_err,
			)
		}
	}

	sync_assets(server)

	init_net: {
		udp_sock, create_err := nbio.create_udp_socket(.IP4, server.l)
		log.assertf(
			create_err == nil,
			"failed to create udp socket: %v",
			create_err,
		)

		bind_err := nbio.bind(server.l, udp_sock, server.endpoint)
		log.assertf(bind_err == nil, "failed to bind udp socket: %v", bind_err)

		server.udp.sock = udp_sock
		server.udp.recv_buf = make([]u8, 1 << 16)
		server.udp.host = {
			asoc_data = server,
			on_packet = server_on_udp_packet,
			on_ping   = server_on_udp_ping,
			decrypt   = server_decrypt_packet,
		}

		sim.udp_connection_boot(&server.udp, true, server.l)

		tcp_sock, listen_err := nbio.listen_tcp(server.endpoint, l = server.l)
		log.assertf(
			listen_err == nil,
			"failed to listen tcp socket: %v",
			listen_err,
		)

		server.tcp = tcp_sock

		log.info("booting the server")

		server.acceptor = nbio.accept_poly(
			tcp_sock,
			server,
			server_on_accept,
			l = server.l,
		)

		sim.interval_poly(
			sim.PING_INTERVAL,
			server,
			server_on_ping,
			&server.ping_interval,
			l = server.l,
		)
	}

	server.tick_interval = nbio.timeout_poly(
		0,
		server,
		server_on_tick,
		server.l,
	)

	return
}

server_tcp_send :: proc(
	server: ^Server,
	conn: ^Connection,
	packet: sim.Server_Packet,
) {
	sim.tcp_connection_send(&conn.hctx, packet, server.l)
}

server_udp_send :: proc(
	server: ^Server,
	conn: ^Connection,
	packet: sim.Server_Packet,
) {
	if conn.udp_endpoint == {} do return
	ok := sim.udp_connection_send(
		&server.udp,
		conn.udp_endpoint,
		&conn.hctx.secret,
		packet,
		server.l,
	)
	assert(ok)
}

server_on_udp_ping :: proc(
	conn: ^sim.UDP_Connection,
	ping: sim.Ping,
) -> (
	t: sim.Ping_Tag,
	ok: bool,
) {
	defer {
		// TODO: add ip ban so we don't hash needlessly
	}

	server := (^Server)(conn.host.asoc_data)

	entry, oka := server.active_pings.entries[ping.id]
	if !oka {
		log.warn("unknown id", ping.id)
		return
	}
	slot := &entry.value

	prev_tag := sim.compute_next_ping_tag(&slot.secret, slot.nonce)
	slot.nonce += 1
	if prev_tag != ping.tag {
		log.warn("wrong tag")
		return
	}

	t = sim.compute_next_ping_tag(&slot.secret, slot.nonce)
	slot.nonce += 1
	ok = true

	switch slot.stage {
	case .Queued:
		slot.arrival = nbio.now(server.l)
		slot.stage = .Sent
		return
	case .Sent:
		rtts := nbio.since(server.l, slot.arrival) + sim.LATENCY
		rtt.update(&slot.conn.rtt, rtts)
		slot.stage = .Recvd
		ok = false
		return
	case .Recvd:
		fallthrough
	case:
		return {}, false
	}
}

server_on_udp_packet :: proc(
	conn: ^sim.UDP_Connection,
	l: ^nbio.Event_Loop,
	bytes: []u8,
) -> bool {
	server := (^Server)(conn.host.asoc_data)
	return server_handle_packet(server, &server.last_udp_conn.hctx, bytes)
}

server_decrypt_packet :: proc(
	conn: ^sim.UDP_Connection,
	endpoint: nbio.Endpoint,
	packet: []u8,
) -> (
	[]u8,
	sim.Decrypt_Error,
) {
	server := (^Server)(conn.host.asoc_data)

	ip := ip_to_integers(endpoint.address)
	if server_is_banned(server, ip) {
		return {}, .Auth
	}

	server.last_udp_conn = server.connections[endpoint]
	if server.last_udp_conn == nil {
		cursor := bit_arr.dl_iter(&server.resolving_udp)
		caused_decryption := false
		for c in bit_arr.dl_iter_next(
			&cursor,
			Connection,
			offset_of(Connection, resolving_udp),
		) {
			if c.tcp_endpoint.address != endpoint.address do continue

			bytes, err := sim.decrypt_packet(&c.hctx.secret, packet)
			if err != .Ok do continue

			bit_arr.dl_remove(&c.resolving_udp)
			server.last_udp_conn = c
			c.udp_endpoint = endpoint
			server.connections[endpoint] = c
			return bytes, .Ok
		}

		server_add_violation(server, ip)
		log.warn("banned ip:", endpoint)

		return {}, .Auth
	}

	return sim.decrypt_packet(&server.last_udp_conn.hctx.secret, packet)
}

server_on_ping :: proc(server: ^Server) {
	killed_conns: ^Connection

	for _, conn in server.connections {
		if nbio.since(server.l, conn.last_packet) > CONNECTION_TIMEOUT {
			conn.next_free = killed_conns
			killed_conns = conn
			continue
		}

		p: sim.Server_Ping
		nbio.rand_bytes(reflect.as_bytes(p))
		lru.set(
			&server.active_pings,
			p.id,
			Ping_Entry{secret = p.sk, conn = conn},
		)
		server_udp_send(server, conn, p)
	}

	for killed_conns != nil {
		conn := killed_conns
		assert(conn != killed_conns.next_free)
		killed_conns = conn.next_free
		log.warn("connection timed out:", conn.tcp_endpoint)
		sim.tcp_connection_kill(&conn.hctx, server.l)
	}

	info := sim.Server_Info {
		player_count = len(server.connections),
	}

	cursor := bit_arr.dl_iter(&server.listeners)
	for conn in bit_arr.dl_iter_next(
		&cursor,
		Connection,
		offset_of(Connection, listener),
	) {
		if conn.last_info != info {
			conn.last_info = info
			sim.tcp_connection_send(&conn.hctx, info, server.l)
		}
	}

	server.ping_seq += 1
	server.last_ping = nbio.now(server.l)
}

REWIRE_TABLE := [?]rawptr {
	rawptr(server_on_accept),
	rawptr(server_on_ping),
	rawptr(server_on_udp_packet),
	rawptr(server_on_udp_ping),
	rawptr(server_decrypt_packet),
	rawptr(server_on_tcp_packet),
	rawptr(server_on_tcp_kill),
}

@(export)
server_rewire :: proc(hr: ^hot.Reloader, server: ^Server) {
	rw: hot.Rewireing
	rw.hr = hr
	append(&rw.table, ..REWIRE_TABLE[:])
	defer hot.rewire_apply(rw)

	hot.rewire(&rw, sim.op_rewire_slot(server.acceptor))
	hot.rewire(&rw, sim.interval_rewire_slot(server.ping_interval))
	server_schedule_tick(server)

	for _, c in server.connections {
		hot.rewire(&rw, c.hctx.host.on_packet)
		hot.rewire(&rw, c.hctx.cleanup)
	}

	hot.rewire(&rw, server.udp.host.on_packet)
	hot.rewire(&rw, server.udp.host.on_ping)
	hot.rewire(&rw, server.udp.host.decrypt)
}

server_shutdown :: proc(server: ^Server) {
	if server.did_shutdown do return
	server.did_shutdown = true

	hot.sip.io_remove(server.acceptor)
	hot.sip.io_remove(server.ping_interval)

	for _, c in server.connections {
		sim.tcp_connection_kill(&c.hctx, server.l)
	}

	iter := bit_arr.dl_iter(&server.resolving_udp)
	for c in bit_arr.dl_iter_next(
		&iter,
		Connection,
		offset_of(Connection, resolving_udp),
	) {
		sim.tcp_connection_kill(&c.hctx, server.l)
	}

	sim.udp_connection_kill(&server.udp, server.l)
	nbio.close(server.tcp, l = server.l)
}

@(export)
server_deinit :: proc(hr: ^hot.Reloader, server: ^Server) {
	server_shutdown(server)

	res := hot.sip.io_run(hr.l)
	log.assertf(res == nil, "failed to run the io scheduler: %v", res)

	delete(server.connections)

	game_destroy(&server.lobby)

	conn := sqlite.db_handle(server.insert_user)
	sqlite.finalize(server.statements)
}

server_config_default :: proc() -> (sc: Config) {
	sc.endpoint = {nbio.IP4_Any, sim.GAME_PORT}

	db, err := sqlite.open(SERVER_DB_PATH)
	log.assertf(err == nil, "failed to open the db: %v", err)
	sc.db = db

	cwd, cwd_err := os.get_working_directory(context.allocator)
	log.assertf(cwd_err == nil, "failed to get working directory: %v", cwd_err)
	sc.cwd = cwd

	return
}

API :: hot.Api(^Server) {
	memory_size = server_memory_size,
	static_init = server_static_init,
	init        = server_init,
	deinit      = server_deinit,
}

when ODIN_BUILD_MODE == .Executable {

	main :: proc() {
		main_proc()
	}
}

main_proc :: proc() {
	CHUNK_SIZE :: 1024 * 1024 * 128
	TEMP_SIZE :: 1024 * 1024 * 64
	INIT_SIZE :: 1024 * 1024 * 8

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

	server_static_init(hot.sip)

	hr: hot.Reloader
	hr.module_name = "server"
	hr.watch_dirs = {"server", "sim"}
	hr.extra_args = {
		"-define:TRACK_ALLOCATIONS=true",
		"-define:SQLITE_SHARED=true",
	}
	hr.dyn_defs = {{"LATENCY", sim.LATENCY}, {"LOCAL", sim.LOCAL}}
	hr.lib = hot.decl_api(API)
	hr.reload = hot.reload_impl
	hr.init_allocator = arna.allocator(&init_arna)

	config: Config
	{context.allocator = arna.allocator(&global_arna)
		config = server_config_default()}
	hr.config = &config

	l, err := nbio.create_event_loop()
	log.assertf(err == nil, "failed to acquire the event loop: %v", err)
	hr.l = l

	for !hot.interrupted() {
		_ = hr->reload({})

		runerr := nbio.run(hr.l)
		log.assertf(runerr == nil, "failed to run the event loop: %v", runerr)
	}

	if sim.TRACK_ALLOCATIONS {
		hot.deinit(&hr)
		rs := sqlite.close(config.db)
		sqlite.assert_ok(config.db, rs)
		nbio.destroy_event_loop(l)
		context.logger = {}
		server_static_deinit()
		sim.global_allocator_destroy(context.allocator)
		hot.unload_libraries(&hr)
		arna.bulk_destroy(&temp_arna, &global_arna, &init_arna)
	}
}
