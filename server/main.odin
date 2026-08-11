package server

import "../sim"
import "../util/arna"
import "../util/hot"
import "../util/nm"
import "../util/rtt"
import "../util/sqlite"
import rt "base:runtime"
import "core:container/lru"
import "core:crypto"
import "core:crypto/blake2s"
import "core:fmt"
import "core:io"
import "core:log"
import "core:mem"
import "core:mem/tlsf"
import "core:nbio"
import "core:os"
import "core:reflect"
import "core:slice"
import "core:sort"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:time"
import "core:unicode/utf8"

FUZZING :: #config(FUZZING, false)

BUNDLE_PATH :: "bundle.bin"
CONFIG_PATH :: "config/stats.yaml"
CONFIG_PATH_EDITED :: "config/stats.edited.yaml"
SERVER_DB_PATH: cstring : ":memory:" when FUZZING else "config/db.db"
SERVER_KEY_PATH :: "config/key.bin"
CONNECTION_TIMEOUT :: 3 * time.Second
HANDSHAKE_STAGE_TIMEOUT :: 500 * time.Millisecond
MAX_CONNECTIONS :: 16
MAX_ACTIVE_PINGS :: MAX_CONNECTIONS * 2
MAX_IP_SIGHTINGS :: 16
MAX_IP_VIOLATIONS :: 8
BANNED_IP_LRU_SIZE :: 1 //1024 * 4
ASSET_REQUEST_LRU_SIZE :: 8
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

Handshake :: struct {
	using tcp:   sim.TCP_Connection,
	using inner: struct {
		ch:          sim.Client_Hello,
		sh:          sim.Server_Hello,
		ceh:         sim.Client_End_Hello,
		server_info: sim.Server_Info,
		xpk:         sim.Private_Key,
	},
	on_fail:     proc(_: ^Handshake, _: ^Server),
	on_boot:     proc(_: ^Handshake, _: ^Server),
}

Connection :: struct {
	using hctx:    Handshake,
	tcp_endpoint:  nbio.Endpoint,
	udp_endpoint:  nbio.Endpoint,
	last_packet:   time.Time,
	input:         sim.Input_State,
	ent:           sim.Ent_ID,
	rtt:           rtt.Estimator,
	using player:  sim.Player,
	next_free:     ^Connection,
	resolving_udp: sim.DL_Node,
	listener:      sim.DL_Node,
	in_game:       sim.DL_Node,
	game:          ^Game,
	request_state: Connection_Request_State,
}

Connection_Request_State :: struct {
	payload:          []u8,
	requested_assets: []sim.Asset_ID,
	sent_asset_metas: int,
	sent_assets:      int,
	buf:              []u8,
	last_info:        sim.Server_Info,
	assets:           []sim.Asset,
	rcvd_assets:      int,
	written:          int,
	recvd:            int,
	write_file:       nbio.Handle,
	file_hash_ctx:    blake2s.Context,
	requester:        ^Connection,
}

Game :: struct {
	using server:         ^Server,
	players:              sim.DL_List,
	ents:                 sim.Ents,
	net_id:               sim.Ent_Net_ID,
	map_index:            int,
	map_buf:              []u8,
	last_cold_state_hash: sim.Hash,
	last_stats_hash:      sim.Hash,
	clean_stats_hash:     sim.Hash,
}

player_next :: proc(cursor: ^^sim.DL_Node) -> (^Connection, bool) {
	return sim.dl_iter_next(cursor, Connection, offset_of(Connection, in_game))
}

game_add_player :: proc(game: ^Game, conn: ^Connection) {
	conn.game = game

	sim.dl_push(&game.players, &conn.in_game)

	game->tcp_send(conn, sim.Server_Map{game.map_buf})
	stats := game.ents.stats[:]
	game->tcp_send(
		conn,
		sim.Server_Stats{stats = sim.custom_encoding_stats(&stats)},
	)
}

game_tick :: proc(game: ^Game) {
	server := game.server
	game.ents.delta = 1.0 / 60
	game.ents.spawn_seq = &game.net_id
	game.ents.on_laser = on_laser

	on_laser :: proc(ents: ^sim.Ents, l: ^sim.Ent) {
		game := (^Game)(uintptr(ents) - offset_of(Game, ents))
		server := game.server

		cursor := game.players.first
		for p in player_next(&cursor) {
			server->tcp_send(
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

	cursor := game.players.first
	for p in player_next(&cursor) {
		rtt := rtt.smoothed(&p.rtt)
		sim.ents_integrate_input(&game.ents, p.ent, rtt, &p.input)
	}

	sim.ents_update(&game.ents)

	{
		stats := game.ents.stats[:]
		packet := sim.Server_Stats {
			stats = sim.custom_encoding_stats(&stats),
		}

		ensure_up_to_date_hash(game, &game.last_stats_hash, packet, "stats")

		if game.clean_stats_hash == {} {
			game.clean_stats_hash = game.last_stats_hash
		}
	}

	{
		players := make([dynamic]sim.Player, context.temp_allocator)

		cursor := game.players.first
		for c in player_next(&cursor) {
			e := sim.ents_get(&game.ents, c.ent)
			c.player.net_ent = e.net_id
			append(&players, c.player)
		}

		packet := sim.Server_Cold_State {
			dirty_stats = game.last_stats_hash != game.clean_stats_hash,
			players     = players[:],
		}

		ensure_up_to_date_hash(
			game,
			&game.last_cold_state_hash,
			packet,
			"cold state",
		)
	}

	ensure_up_to_date_hash :: proc(
		game: ^Game,
		hash: ^sim.Hash,
		packet: sim.Server_Packet,
		subject: string,
	) {
		enc: sim.Encoder
		sim.server_packet_encode(packet, &enc)

		buf := make([]u8, sim.encoded_len(&enc), context.temp_allocator)
		sim.server_packet_encode(packet, buf)

		new_hash: sim.Hash
		sim.hash(buf, &new_hash)

		if new_hash != hash^ {
			hash^ = new_hash
			cursor := game.players.first
			for c in player_next(&cursor) {
				game->tcp_send_bytes(c, buf)
			}
		}
	}
}

game_destroy :: proc(game: ^Game) {
	delete(game.map_buf)
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
		ON CONFLICT (name) DO UPDATE
			SET id = ?1, hash = ?3, size = ?4, type = ?5, visited = 1
		ON CONFLICT (hash) DO UPDATE SET name = ?2, visited = 1
	`,
	count_assets:        sqlite.Statement `
		SELECT count(*) FROM asset
	`,
	select_assets:       sqlite.Statement `
		SELECT * FROM asset WHERE type = ? AND id > ? ORDER BY id
	`,
	get_asset_by_name:   sqlite.Statement `
		SELECT * FROM asset WHERE name = ? AND type = ?
	`,
	get_asset:           sqlite.Statement `
		SELECT * FROM asset WHERE id = ?
	`,
	delete_asset:        sqlite.Statement `
		DELETE FROM asset WHERE id = ?
	`,
	prune_assets:        sqlite.Statement `
		DELETE FROM asset WHERE visited = 0
	`,
}

Banned_Ip_Entry :: struct {
	violation_count: int,
}

Asset_Request_Kind :: enum {
	Download,
	Upload,
}

Asset_Request :: struct {
	payload: []u8,
	conn:    ^Connection,
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

Server :: struct #align (8) {
	active_pings:            lru.Cache(sim.Ping_ID, Ping_Entry),
	banned_ips:              lru.Cache(Saved_IP, Banned_Ip_Entry),
	free_conns:              ^Connection,
	connections:             map[nbio.Endpoint]^Connection,
	asset_requests:          lru.Cache(sim.Hash, Asset_Request),
	pk:                      sim.Private_Key,
	ping_seq:                int,
	udp:                     sim.UDP_Connection,
	tcp:                     nbio.TCP_Socket,
	file_tcp:                nbio.TCP_Socket,
	acceptor:                ^nbio.Operation,
	ping_interval:           ^nbio.Operation,
	tick_interval:           ^nbio.Operation,
	last_udp_conn:           ^Connection,
	resolving_udp:           sim.DL_List,
	listeners:               sim.DL_List,
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
	hr:                      ^hot.Reloader,
	did_shutdown:            bool,
	last_ping:               time.Time,
	tcp_send:                proc(
		_: ^Server,
		_: ^Connection,
		_: sim.Server_Packet,
	),
	tcp_send_bytes:          proc(_: ^Server, _: ^Connection, _: []u8),
	udp_send:                proc(
		_: ^Server,
		_: ^Connection,
		_: sim.Server_Packet,
	),
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
	#assert(offset_of(Handshake, tcp) == 0)

	packet := sim.client_packet_decode(packet_bytes) or_return

	reason := ""
	defer if !ok do log.warn("invalid packet from client (", reason, "):", packet)

	from := (^Connection)(from)
	game := from.game

	from.last_packet = time.now()

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
			cursor := game.players.first
			for p in player_next(&cursor) {
				append(&players, p.input.keys)
			}

			server->udp_send(
				from,
				sim.Server_State {
					tps = server.tps,
					you = e.net_id,
					your_next_net_id = from.input.next_net_id,
					ents = {value = {&game.ents, encode_state}},
					players = players[:],
				},
			)

			encode_state :: proc(data: rawptr, e: ^sim.Encoder) -> bool {
				ents := (^sim.Ents)(data)
				iter := sim.ents_iter(ents)
				for ent in sim.ents_iter_next(&iter) {
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

			e := sim.ents_add(&game.ents, &game.net_id)
			s := sim.ents_stats_get(&game.ents, p.id)
			e.energy_consumed = s.energy - 0.1
			e.pos = p.pos
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
			counts := make([]int, len(game.ents.teams), context.temp_allocator)

			cursor := game.players.first
			for p in player_next(&cursor) {
				e := sim.ents_get(&game.ents, p.ent)
				counts[e.team] += 1
			}

			c := game_ent_by_net_id(game, p.parent)

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
				{stat_count = len(game.ents.stats) + 1, id = stats.id},
			) or_return

			append(&game.ents.stats, stats)
		case .Edit:
			reason = "id out of bounds"
			if p.stats.id < 0 || int(p.stats.id) >= len(game.ents.stats) do return
			stats := p.stats

			reason = "validation failed"
			sim.validate(
				stats,
				{stat_count = len(game.ents.stats), id = stats.id},
			) or_return

			game.ents.stats[stats.id] = stats

			reason = ""
		case .Save:
			edited_file, edited_file_err := os.open(
				CONFIG_PATH_EDITED,
				{.Create, .Trunc, .Write},
			)
			log.assertf(
				edited_file_err == nil,
				"failed to open the edited config",
			)

			edited_stream := os.to_stream(edited_file)

			ctx: sim.Store_Ctx
			ctx.asoc_data = server
			ctx.sprite_name = proc(ptr: rawptr, id: sim.Asset_ID) -> string {
				server := (^Server)(ptr)

				asset: Saved_Asset
				res, stmt := sqlite.query(server.get_asset, asset, id)
				sqlite.assert_ok(stmt, res)
				sqlite.reset(stmt)

				return strings.clone(
					nm.str(&asset.name),
					context.temp_allocator,
				)
			}
			ctx.stats = game.ents.stats[:]

			sim.store_config(ctx, edited_stream)

			io.close(edited_stream)

			server_bundle_refresh(server)

			game.clean_stats_hash = game.last_stats_hash
		}
	case sim.Client_Map_Edit:
		map_path := pick_map(game.map_index - 1, context.temp_allocator)

		me: sim.Encoder

		okm := sim.map_store(p.mapa, &me)
		assert(okm)
		if sim.encoded_len(&me) > len(packet_bytes) {
			log.warn(
				"map sent from player has overlapping regions:",
				sim.encoded_len(&me),
				"!=",
				len(packet_bytes),
			)
			return
		}

		buf, _ := mem.alloc_bytes(sim.encoded_len(&me), 8)
		me = {buf}
		ok := sim.map_store(p.mapa, &me)
		assert(ok)

		err := os.write_entire_file(map_path, buf)
		log.assertf(err == nil, "failed to write the map: %v", err)

		game_set_map(game, buf)

		server_bundle_refresh(server)
	case sim.Client_Asset_Request:
		token: sim.Hash
		crypto.rand_bytes(token[:])

		payload, _ := mem.alloc_bytes(len(packet_bytes), 8)
		copy(payload, packet_bytes)
		defer delete(payload)

		count := 0
		config_hash_ctx: blake2s.Context
		blake2s.init(&config_hash_ctx)

		if p.inverted {
			new_sprites := make([dynamic]sim.Asset_ID, context.temp_allocator)

			asset_q, stmt := sqlite.query(
				server.select_assets,
				Saved_Asset,
				sim.Asset_Type.Sprite,
				0,
			)
			for asset in sqlite.query_next(&asset_q) {
				_, found := slice.linear_search(p.assets, asset.id)
				if found do continue
				blake2s.update(&config_hash_ctx, asset.hash[:])
				append(&new_sprites, asset.id)
				count += 1
			}
			sqlite.reset(stmt)

			body := sim.Client_Asset_Request {
				assets = new_sprites[:],
			}

			e: sim.Encoder
			sim.client_packet_encode(body, &e)

			delete(payload)
			payload, _ = mem.alloc_bytes(sim.encoded_len(&e), 8)
			e = {payload}

			ok := sim.client_packet_encode(body, &e)
			assert(ok)
		} else {
			count += len(p.assets)
			for s in p.assets {
				asset := server_get_asset(server, s) or_return
				blake2s.update(&config_hash_ctx, asset.hash[:])
			}
		}

		global_hash: sim.Hash
		blake2s.final(&config_hash_ctx, global_hash[:])

		if count > 0 {
			lru.set(
				&server.asset_requests,
				token,
				Asset_Request{payload = payload, conn = from},
			)
		}
		payload = {}

		server_tcp_send(
			server,
			from,
			sim.Server_Cmd {
				type = .Token,
				token = token,
				global_hash = global_hash,
				count = count,
			},
		)
	case sim.Client_Asset_Upload:
		payload, _ := mem.alloc_bytes(len(packet_bytes), 8)
		copy(payload, packet_bytes)

		lru.set(
			&server.asset_requests,
			p.token,
			Asset_Request{payload = payload, conn = from},
		)

		server_tcp_send(
			server,
			from,
			sim.Server_Cmd{type = .Ack, token = p.token},
		)
	case sim.Broadcast_Packet:
		cursor := game.players.first
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
	// TODO: build a net id index instead, this is a strain on the server
	iter := sim.ents_iter(&game.ents)
	for e in sim.ents_iter_next(&iter) {
		if e.net_id == id {
			return e
		}
	}
	return sim.NIL_ENT
}

pick_map :: proc(index: int, temp_allocator: rt.Allocator) -> string {
	map_entries, map_entries_err := os.read_directory_by_path(
		sim.MAP_DIR,
		0,
		temp_allocator,
	)
	log.assertf(
		map_entries_err == nil,
		"failed to read maps: %v",
		map_entries_err,
	)

	sort.merge_sort_proc(map_entries, compare_file_entries)

	compare_file_entries :: proc(a: os.File_Info, b: os.File_Info) -> int {
		return sort.compare_strings(a.name, b.name)
	}

	choosen := map_entries[index % len(map_entries)]

	full_path, fperr := os.join_path(
		{sim.MAP_DIR, choosen.name},
		temp_allocator,
	)
	assert(fperr == nil)

	return full_path
}

game_load_next_map :: proc(game: ^Game) {
	temp_allocator := context.temp_allocator

	map_path := pick_map(game.map_index, temp_allocator)
	game.map_index += 1

	map_bytes, map_bytes_err := os.read_entire_file(
		map_path,
		context.allocator,
	)
	assert(map_bytes_err == nil)

	game_set_map(game, map_bytes)
}

game_set_map :: proc(game: ^Game, buf: []u8) {
	mapa, ok := sim.map_load(buf)
	assert(ok)

	delete(game.map_buf)
	game.map_buf = buf

	sim.ents_clear(&game.ents)
	game.ents.mapa = mapa

	map_ent_to_ent := make(
		[]^sim.Ent,
		len(game.ents.mapa.ents),
		context.temp_allocator,
	)
	map_ent_to_ent[0] = sim.NIL_ENT

	prefix := min(1, len(game.ents.mapa.ents))

	for ent, i in game.ents.mapa.ents[prefix:] {
		e := sim.ents_add(&game.ents, &game.net_id)
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

	cursor := game.players.first
	for c in player_next(&cursor) {
		game.server->tcp_send(c, sim.Server_Map{buf})
	}
}

// TODO: there is no reason for this to be generic
hctx_connect :: proc(hctx: ^Handshake, server: ^Server) {
	nbio.recv_poly2(
		hctx.sock,
		{reflect.as_bytes(hctx.ch)},
		hctx,
		server,
		on_conn_recv_hello,
		all = true,
		timeout = HANDSHAKE_STAGE_TIMEOUT,
		l = server.hr.l,
	)

	on_conn_recv_hello :: proc(
		op: ^nbio.Operation,
		hctx: ^Handshake,
		server: ^Server,
	) {
		kill := true
		defer if kill do hctx->on_fail(server)

		assert(hctx.sock != 0)

		if op.recv.err != nil {
			log.warn("handshake did not arrive:", op.recv.err)
			return
		}

		log.debug("received handshake init from:", op.recv.source)

		if op.recv.received != size_of(sim.Client_Hello) {
			log.warn("received invalid client hello")
			return
		}

		log.debug("sending server hello")
		sim.server_handshake_init(&server.pk, &hctx.xpk, &hctx.ch, &hctx.sh)
		nbio.send_poly2(
			hctx.sock,
			{reflect.as_bytes(hctx.sh)},
			hctx,
			server,
			on_conn_send_hello,
			all = true,
			timeout = HANDSHAKE_STAGE_TIMEOUT,
			l = op.l,
		)
		kill = false
	}

	on_conn_send_hello :: proc(
		op: ^nbio.Operation,
		hctx: ^Handshake,
		server: ^Server,
	) {

		kill := true
		defer if kill do hctx->on_fail(server)

		assert(hctx.sock != 0)

		if op.send.err != nil {
			log.warn("failed to send the server hello:", op.send.err)
			return
		}

		nbio.recv_poly2(
			hctx.sock,
			{reflect.as_bytes(hctx.ceh)},
			hctx,
			server,
			on_conn_recv_end_hello,
			all = true,
			timeout = HANDSHAKE_STAGE_TIMEOUT,
			l = op.l,
		)
		kill = false
	}

	on_conn_recv_end_hello :: proc(
		op: ^nbio.Operation,
		hctx: ^Handshake,
		server: ^Server,
	) {
		kill := true
		defer if kill do hctx->on_fail(server)

		assert(hctx.sock != 0)

		if op.recv.err != nil {
			log.warn("handshake did not arrive:", op.recv.err)
			return
		}

		log.debug("received client hello from:", op.recv.source)

		if op.recv.received != size_of(hctx.ceh) {
			log.warn("received invalid client hello")
			return
		}

		ok := sim.server_handshake_end(
			&server.pk,
			&hctx.xpk,
			&hctx.ch,
			&hctx.sh,
			&hctx.ceh,
			&hctx.secret,
		)
		if !ok do return

		hctx->on_boot(server)

		kill = false
	}
}

server_on_accept :: proc(op: ^nbio.Operation, server: ^Server) {
	assert(op.accept.err == nil)

	log.debug("got connection:", op.accept)

	kill := true
	defer if kill do nbio.close(op.accept.client, l = server.hr.l)

	server.acceptor = nbio.accept_poly(
		op.accept.socket,
		server,
		server_on_accept,
		l = op.l,
	)

	ip := ip_to_integers(op.accept.client_endpoint.address)
	if server_is_banned(server, ip) {
		log.debug("ip is banned:", op.accept)
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
	conn.tcp_endpoint = op.accept.client_endpoint
	conn.last_packet = time.now()
	conn.hctx.sock = op.accept.client
	conn.hctx.host.asoc_data = server
	conn.hctx.host.on_kill = server_on_tcp_kill
	conn.hctx.on_boot = on_boot
	conn.hctx.on_fail = on_fail

	hctx_connect(&conn.hctx, server)

	kill = false

	on_fail :: proc(hctx: ^Handshake, server: ^Server) {
		sim.tcp_connection_kill(&hctx.tcp, server.hr.l)
	}

	on_boot :: proc(conn: ^Connection, server: ^Server) {
		kill := true
		defer if kill do conn->on_fail(server)

		assert(conn.tcp.sock != 0)

		request := (^sim.Client_Request_Header)(&conn.ch.payload)

		Handler_Proc :: proc(
			_: ^Server,
			_: ^Connection,
			_: ^sim.Client_Request_Header,
		) -> bool

		handlers := [sim.Client_Request_Type]Handler_Proc {
			.Download_Content  = send_content,
			.Play              = boot_player,
			.Watch_Server_Info = stream_server_info,
			.Upload_Content    = recv_content,
		}

		if len(handlers) < int(request.kind) {
			log.warn(
				"received out of range Client_Request_Type:",
				request.kind,
			)
			return
		}

		h := handlers[request.kind]
		if h != nil {
			kill = !h(server, conn, request)
		}
	}
}

stream_server_info :: proc(
	server: ^Server,
	conn: ^Connection,
	request: ^sim.Client_Request_Header,
) -> bool {
	log.debug("registering info listener")

	sim.tcp_connection_boot(&conn.hctx, 0, 512, l = server.hr.l)
	sim.dl_push(&server.listeners, &conn.listener)

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
		l = server.hr.l,
	)

	conn.hctx.tcp.host.on_packet = server_on_tcp_packet

	server.next_peer_id += 1
	conn.input.next_net_id.peer = server.next_peer_id
	conn.pk = conn.hctx.ch.id

	sim.dl_push(&server.resolving_udp, &conn.resolving_udp)

	game_add_player(&server.lobby, conn)

	return true
}

send_content :: proc(
	server: ^Server,
	conn: ^Connection,
	request: ^sim.Client_Request_Header,
) -> bool {
	conn.hctx.tcp.timeout = 5 * time.Second

	token: sim.Hash
	copy(token[:], request.inline_body[:])

	ass_req := server.asset_requests.entries[token] or_return
	// TODO: ratelimit this

	payload := ass_req.value.payload
	ass_req.value.payload = {}

	conn.request_state.payload = payload

	any_body := sim.client_packet_decode(payload) or_return
	body := any_body.(sim.Client_Asset_Request)
	conn.request_state.requested_assets = body.assets
	conn.request_state.buf = make([]u8, 4096)

	do_progress(conn)

	return true

	do_progress :: proc(conn: ^Connection) -> bool {
		server := (^Server)(conn.hctx.tcp.host.asoc_data)
		state := &conn.request_state

		assert(len(state.requested_assets) != 0)

		e := sim.Encoder{state.buf}

		log.debug("asset fetch doing progress")

		for s in state.requested_assets[state.sent_asset_metas:] {
			asset, ok := server_get_asset(server, s)
			if !ok {
				log.warn("requested unknown asset:", s)
				return false
			}

			sim.encode(&e, asset.base) or_break
			state.sent_asset_metas += 1
		}

		buff_written := len(state.buf) - len(e.remining)

		if buff_written != 0 {
			log.debug("sending meta")
			nbio.send_poly(
				conn.hctx.sock,
				{state.buf[:buff_written]},
				conn,
				on_meta_sent,
				all = true,
				l = server.hr.l,
			)
			return true
		}

		if state.sent_assets < len(state.requested_assets) {
			log.debug("sending sprite")

			s := state.requested_assets[state.sent_assets]
			state.sent_assets += 1

			asset, ok := server_get_asset(server, s)
			assert(ok)

			path := asset_path(&asset)

			nbio.open_poly(path, conn, on_open, l = server.hr.l)

			return true
		}

		return false
	}

	on_open :: proc(op: ^nbio.Operation, conn: ^Connection) {
		server := (^Server)(conn.hctx.tcp.host.asoc_data)
		state := &conn.request_state

		kill := true
		defer if kill do conn.hctx->on_fail(server)
		defer delete(op.open.path)

		if op.open.err != nil {
			log.error("failed to open", op.open.path, ":", op.open.err)
			return
		}

		nbio.sendfile_poly(
			conn.hctx.tcp.sock,
			op.open.handle,
			conn,
			on_file_sent,
			l = op.l,
		)

		state.write_file = op.open.handle

		kill = false
	}

	on_file_sent :: proc(op: ^nbio.Operation, conn: ^Connection) {
		server := (^Server)(conn.hctx.tcp.host.asoc_data)

		kill := true
		defer if kill do conn.hctx->on_fail(server)
		defer nbio.close(op.sendfile.file, l = op.l)

		if op.sendfile.err != nil {
			log.error("failed to send asset file:", op.sendfile.err)
			return
		}

		kill = !do_progress(conn)
	}

	on_meta_sent :: proc(op: ^nbio.Operation, conn: ^Connection) {
		server := (^Server)(conn.hctx.tcp.host.asoc_data)

		kill := true
		defer if kill do conn.hctx->on_fail(server)

		if op.send.err != nil {
			log.error("fialed to send meta chunk:", op.send.err)
			return
		}

		kill = !do_progress(conn)
	}
}

recv_content :: proc(
	server: ^Server,
	conn: ^Connection,
	request: ^sim.Client_Request_Header,
) -> bool {
	conn.hctx.tcp.timeout = 5 * time.Second

	token: sim.Hash
	copy(token[:], request.inline_body[:])

	ass_req := server.asset_requests.entries[token] or_return
	// TODO: ratelimit this

	payload := ass_req.value.payload
	ass_req.value.payload = {}

	conn.request_state.payload = payload
	any_body := sim.client_packet_decode(payload) or_return
	body := any_body.(sim.Client_Asset_Upload)
	conn.request_state.assets = body.metas
	conn.request_state.buf = make([]u8, sim.UPLOAD_BUFFER_SIZE)
	conn.request_state.requester = ass_req.value.conn

	log.debug("starting content download:", body.metas)

	do_progress(conn)

	return true

	do_progress :: proc(conn: ^Connection) -> bool {
		server := (^Server)(conn.hctx.tcp.host.asoc_data)

		state := &conn.request_state

		for state.rcvd_assets < len(state.assets) {
			curr := &state.assets[state.rcvd_assets]

			remining := curr.size - state.written

			if remining == 0 {
				hash: sim.Hash
				blake2s.final(&state.file_hash_ctx, hash[:])

				if hash != curr.hash {
					log.error(
						"got corrupted file, considering we" +
						" are encrypting, this is a bug",
					)
					return false
				}

				_, sares := sqlite.exec(
					server.save_asset,
					sim.hash_prefix(&curr.hash),
					nm.str(&curr.name),
					curr.hash,
					curr.size,
					curr.type,
				)
				sqlite.assert_ok(server.save_asset, sares)

				if state.write_file != 0 {
					nbio.close(state.write_file, l = server.hr.l)
				}
				state.write_file = 0
				state.written = 0
				state.rcvd_assets += 1

				server->tcp_send(
					state.requester,
					sim.Server_Event{type = .File_Uploaded, hash = curr.hash},
				)

				continue
			}

			if state.write_file == 0 {
				blake2s.init(&state.file_hash_ctx)
				path := asset_path(curr)
				nbio.open_poly(
					path,
					conn,
					on_open,
					{.Write, .Create, .Trunc},
					l = server.hr.l,
				)
				return true
			}

			if state.recvd > 0 {
				tag, source := sim.split_crypt_tag(state.buf, state.recvd)
				fmt.println(len(source))

				ok := sim.decrypt(&conn.tcp.secret, tag, source)
				if !ok {
					log.warn(
						"received corrupted file chunk, deleting the file:",
						source,
					)
					err := os.remove(asset_path(curr))
					if err != nil {
						log.error("failed to delete the corrupt file")
					}
					return false
				}

				blake2s.update(&state.file_hash_ctx, source)

				nbio.write_poly(
					state.write_file,
					state.written,
					source,
					conn,
					on_write,
					all = true,
					l = server.hr.l,
				)
				return true
			}

			nbio.recv_poly(
				conn.tcp.sock,
				{state.buf[:min(remining + size_of(sim.Tag), len(state.buf))]},
				conn,
				on_recv,
				all = true,
				l = server.hr.l,
				timeout = conn.tcp.timeout,
			)
			return true
		}

		return false
	}

	on_open :: proc(op: ^nbio.Operation, conn: ^Connection) {
		server := (^Server)(conn.hctx.tcp.host.asoc_data)

		kill := true
		defer if kill do conn.hctx->on_fail(server)
		defer delete(op.open.path)

		if op.open.err != nil {
			log.warn("failed to create", op.open.path, ":", op.open.err)
			return
		}

		conn.request_state.write_file = op.open.handle
		kill = !do_progress(conn)
	}

	on_recv :: proc(op: ^nbio.Operation, conn: ^Connection) {
		server := (^Server)(conn.hctx.tcp.host.asoc_data)

		kill := true
		defer if kill do conn.hctx->on_fail(server)

		if op.recv.err != nil {
			log.warn("failed to recv from client:", op.recv.err)
			return
		}

		_, source := sim.split_crypt_tag(op.recv.bufs[0])

		conn.request_state.recvd = len(source)
		kill = !do_progress(conn)
	}

	on_write :: proc(op: ^nbio.Operation, conn: ^Connection) {
		server := (^Server)(conn.hctx.tcp.host.asoc_data)

		kill := true
		defer if kill do conn.hctx->on_fail(server)

		if op.write.err != nil {
			log.warn("failed to write to disk:", op.write.err)
			return
		}

		conn.request_state.recvd = 0
		conn.request_state.written += len(op.write.buf)
		kill = !do_progress(conn)
	}
}

asset_path :: proc(asset: ^sim.Asset) -> string {
	name_str := nm.str(&asset.name)

	// NOTE: it suffices to return null value since subsequent file operations
	// will fail on this
	if strings.contains(name_str, ".") do return ""
	if !utf8.valid_string(name_str) do return ""

	dir := sim.DIR_BY_TYPE[asset.type]
	ext := sim.EXT_BY_TYPE[asset.type]

	name := strings.join({name_str, ext}, "", context.temp_allocator)
	path, _ := os.join_path({dir, name}, context.allocator)
	return path
}

server_on_tcp_kill :: proc(conn: ^sim.TCP_Connection, l: ^nbio.Event_Loop) {
	server := (^Server)(conn.host.asoc_data)
	conn := (^Connection)(conn)
	game := conn.game

	conn.next_free = server.free_conns
	server.free_conns = conn

	sim.dl_remove(&conn.resolving_udp)
	sim.dl_remove(&conn.listener)
	sim.dl_remove(&conn.in_game)

	delete_key(&server.connections, conn.udp_endpoint)
	delete_key(&server.connections, conn.tcp_endpoint)

	if game != nil {
		sim.ents_queue_remove(&game.ents, conn.ent)
	}

	delete(conn.request_state.payload)
	delete(conn.request_state.buf)
	if conn.request_state.write_file != 0 {
		nbio.close(conn.request_state.write_file, l = l)
	}

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
	diff := time.diff(time.now(), server.next_frame)
	server.next_frame = time.time_add(server.next_frame, -min(diff, 0))
	server.tick_interval = nbio.timeout_poly(
		max(diff, 1),
		server,
		server_on_tick,
		l = server.hr.l,
	)

	server.frames_since_tps_sample += 1
	if time.since(server.frame_sample_time) > time.Second {
		server.tps = server.frames_since_tps_sample
		server.frame_sample_time = time.now()
		server.frames_since_tps_sample = 0
	}
}

server_on_tick :: proc(op: ^nbio.Operation, server: ^Server) {
	server.tick_interval = nil

	interrupted := sync.atomic_load(hot.sip.interrupted)

	res := hot.reload(
		server.hr,
		{module_name = "server", skip_full_reload = true},
	)

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

server_bundle_refresh :: proc(server: ^Server) {
	cwd, cwd_err := os.get_working_directory(context.temp_allocator)
	log.assertf(cwd_err == nil, "failed to get working directory: %v", cwd_err)

	Ctx :: struct {
		server: ^Server,
		type:   sim.Asset_Type,
	}
	ctx: Ctx
	ctx.server = server
	context.user_ptr = &ctx

	ctx.type = .Map
	visit_files(cwd, sim.MAP_DIR, sim.MAP_EXT, visit_file)
	ctx.type = .Sprite
	visit_files(cwd, sim.SPRITE_DIR, sim.SPRITE_EXT, visit_file)

	visit_file :: proc(name: string, content: []u8) {
		ctx := (^Ctx)(context.user_ptr)

		asset: Saved_Asset
		asset.name = nm.from_str(name)
		sim.hash(content, &asset.hash)
		asset.size = len(content)
		asset.type = ctx.type
		delete(content)

		_, sares := sqlite.exec(
			ctx.server.save_asset,
			sim.hash_prefix(&asset.hash),
			nm.str(&asset.name),
			asset.hash,
			asset.size,
			asset.type,
		)
		sqlite.assert_ok(ctx.server.save_asset, sares)
	}

	_, psres := sqlite.exec(server.prune_assets)
	sqlite.assert_ok(server.prune_assets, psres)

	config: []u8
	config_err: os.Error

	for path in ([]string{CONFIG_PATH_EDITED, CONFIG_PATH}) {
		config, config_err = os.read_entire_file(path, context.temp_allocator)
		if config_err == nil do break
	}
	assert(config_err == nil)

	loader: sim.Asset_Loader
	loader.asoc_data = server
	loader.path = CONFIG_PATH
	loader.source = auto_cast config
	loader.load_sprite = load_sprite
	sim.load_config(&loader)

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

	{
		// TODO: this should be extracted out
		game := &server.lobby

		delete(game.ents.stats)
		game.ents.stats = loader.stats
	}
}

visit_files :: proc(
	cwd: string,
	dir: string,
	ext: string,
	visit: proc(_: string, _: []u8),
) -> (
	count: int,
) {
	context.allocator = context.temp_allocator

	dir, dir_err := os.join_path({cwd, dir}, context.allocator)
	log.assertf(dir_err == nil, "failed to join path: %v", dir_err)

	walker := os.walker_create(dir)
	defer os.walker_destroy(&walker)
	for entry in os.walker_walk(&walker) {
		if entry.type != .Regular do continue
		if !strings.has_suffix(entry.fullpath, ext) do continue

		rel_path := entry.fullpath[len(dir) + 1:]
		rel_path = rel_path[:len(rel_path) - len(ext)]

		data, err := os.read_entire_file(entry.fullpath, context.allocator)
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

init_db :: proc(stmst: ^Server_Statements) {
	db, err := sqlite.open(SERVER_DB_PATH)
	log.assertf(err == nil, "failed to open the db: %v", err)
	sqlite.exec(db, #load("schema.sql", cstring))
	sqlite.assert_ok(db, err)

	sqlite.prepare(db, stmst^)
}

server_init_without_game :: proc(hr: ^hot.Reloader) -> (server: ^Server) {
	context.allocator = hr.init_allocator

	server = new(Server)
	server.hr = hr

	lru_pool_size ::
		size_of(lru.Node(Saved_IP, Banned_Ip_Entry)) * BANNED_IP_LRU_SIZE +
		size_of(lru.Node(sim.Hash, Asset_Request)) * ASSET_REQUEST_LRU_SIZE +
		size_of(lru.Node(sim.Ping_ID, Ping_Entry)) * MAX_ACTIVE_PINGS
	server.lru_pool = arna.init_from_buffer(make([]u8, lru_pool_size))
	lru.init(
		&server.banned_ips,
		BANNED_IP_LRU_SIZE,
		node_allocator = arna.allocator(&server.lru_pool),
	)
	lru.init(
		&server.asset_requests,
		ASSET_REQUEST_LRU_SIZE,
		node_allocator = arna.allocator(&server.lru_pool),
	)
	lru.init(
		&server.active_pings,
		MAX_ACTIVE_PINGS,
		node_allocator = arna.allocator(&server.lru_pool),
	)
	server.asset_requests.on_remove = ass_on_remove

	ass_on_remove :: proc(_: sim.Hash, value: Asset_Request, _: rawptr) {
		delete(value.payload)
	}

	if !FUZZING {
		init_db(&server.statements)
	}

	init_resources: {
		sim.packet_buffer_reserve(&server.udp.send_buf, 8)

		server.conn_buf = make([]Connection, MAX_CONNECTIONS)
		for &c in server.conn_buf {
			c.next_free = server.free_conns
			server.free_conns = &c
		}
	}

	init_config: {
		if FUZZING do break init_config

		defer free_all(context.temp_allocator)

		{
			if _, err := os.stat(SERVER_KEY_PATH, context.temp_allocator);
			   err != nil {
				sim.private_key_generate(&server.pk)
				err := os.write_entire_file(SERVER_KEY_PATH, server.pk[:])
				log.assertf(
					err == nil,
					"failed to create %v: %v",
					SERVER_KEY_PATH,
					err,
				)
			}

			bytes, err := os.read_entire_file(
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

		server_bundle_refresh(server)

		if _, err := os.stat(sim.MAP_DIR, context.temp_allocator); err != nil {
			create_dir_err := os.make_directory_all(sim.MAP_DIR)
			log.assertf(
				create_dir_err == nil,
				"failed to create the maps dir: %v",
				create_dir_err,
			)

			buf: [4096]u8
			for m in DEFAULT_MAPS {
				e := sim.Encoder{buf[:]}
				sim.map_text_to_bin(m.spec, &e, 1)
				final := buf[:len(buf) - len(e.remining)]

				full_path, fperr := os.join_path(
					{sim.MAP_DIR, m.name},
					context.temp_allocator,
				)
				log.assertf(fperr == nil, "failed to join path: %v", fperr)

				full_path_with_ext, fpwerr := os.join_filename(
					full_path,
					"gmap",
					context.temp_allocator,
				)
				log.assertf(
					fpwerr == nil,
					"failed to join filename: %v",
					fpwerr,
				)

				write_map_err := os.write_entire_file_from_bytes(
					full_path_with_ext,
					final,
				)
				log.assertf(
					write_map_err == nil,
					"failed to write map: %v",
					write_map_err,
				)
			}
		}
	}

	init_net: {
		if FUZZING {
			server.tcp_send = proc(
				_: ^Server,
				_: ^Connection,
				_: sim.Server_Packet,
			) {}
			server.tcp_send_bytes = proc(
				_: ^Server,
				_: ^Connection,
				_: []u8,
			) {}
			server.udp_send = proc(
				_: ^Server,
				_: ^Connection,
				_: sim.Server_Packet,
			) {}
			break init_net
		} else {
			server.tcp_send = server_tcp_send
			server.tcp_send_bytes = server_tcp_send_bytes
			server.udp_send = server_udp_send
		}

		udp_sock, create_err := nbio.create_udp_socket(.IP4)
		log.assertf(
			create_err == nil,
			"failed to create udp socket: %v",
			create_err,
		)

		bind_err := nbio.bind(udp_sock, {nbio.IP4_Any, sim.GAME_PORT})
		log.assertf(bind_err == nil, "failed to bind udp socket: %v", bind_err)

		server.udp.sock = udp_sock
		server.udp.recv_buf = make([]u8, 1 << 16)
		server.udp.host = {
			asoc_data = server,
			on_packet = server_on_udp_packet,
			on_ping   = server_on_udp_ping,
			decrypt   = server_decrypt_packet,
		}

		sim.udp_connection_boot(&server.udp, true, server.hr.l)

		tcp_sock, listen_err := nbio.listen_tcp(
			{nbio.IP4_Any, sim.GAME_PORT},
			l = server.hr.l,
		)
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
			l = server.hr.l,
		)

		sim.interval_poly(
			sim.PING_INTERVAL,
			server,
			server_on_ping,
			&server.ping_interval,
			l = server.hr.l,
		)
	}

	if !FUZZING {
		server.tick_interval = nbio.timeout_poly(
			0,
			server,
			server_on_tick,
			server.hr.l,
		)
	}

	return
}

server_tcp_send :: proc(
	server: ^Server,
	conn: ^Connection,
	packet: sim.Server_Packet,
) {
	sim.tcp_connection_send_server(&conn.hctx, packet, server.hr.l)
}

server_tcp_send_bytes :: proc(
	server: ^Server,
	conn: ^Connection,
	packet: []u8,
) {
	sim.tcp_connection_send_arbitrary(&conn.hctx, packet, server.hr.l)
}

server_udp_send :: proc(
	server: ^Server,
	conn: ^Connection,
	packet: sim.Server_Packet,
) {

	if conn.udp_endpoint == {} do return
	assert(
		sim.udp_connection_send_server(
			&server.udp,
			conn.udp_endpoint,
			&conn.hctx.secret,
			packet,
			server.hr.l,
		),
	)
}

@(export)
server_init :: proc(hr: ^hot.Reloader) -> (server: ^Server) {
	server = server_init_without_game(hr)

	init_world: {
		game := &server.lobby
		game.server = server
		sim.ents_reserve(&game.ents, 128)
		if FUZZING {
			game.map_index = 1
		} else {
			game_load_next_map(game)
		}
	}

	return
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
		slot.arrival = time.now()
		slot.stage = .Sent
		return
	case .Sent:
		rtts := time.since(slot.arrival) + sim.LATENCY
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

		cursor := server.resolving_udp.first
		for c in sim.dl_iter_next(
			&cursor,
			Connection,
			offset_of(Connection, resolving_udp),
		) {
			if c.tcp_endpoint.address != endpoint.address do continue

			bytes, err := sim.decrypt_packet(&c.hctx.secret, packet)
			if err != .Ok do continue

			sim.dl_remove(&c.resolving_udp)
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
		if time.since(conn.last_packet) > CONNECTION_TIMEOUT {
			conn.next_free = killed_conns
			killed_conns = conn
			continue
		}

		p: sim.Server_Ping
		crypto.rand_bytes(reflect.as_bytes(p))
		lru.set(
			&server.active_pings,
			p.id,
			Ping_Entry{secret = p.sk, conn = conn},
		)
		server->udp_send(conn, p)
	}

	for killed_conns != nil {
		conn := killed_conns
		assert(conn != killed_conns.next_free)
		killed_conns = conn.next_free
		sim.tcp_connection_kill(&conn.hctx, server.hr.l)
	}

	info := sim.Server_Info {
		player_count = len(server.connections),
	}

	cursor := server.listeners.first
	for conn in sim.dl_iter_next(
		&cursor,
		Connection,
		offset_of(Connection, listener),
	) {
		if conn.request_state.last_info != info {
			conn.request_state.last_info = info
			sim.tcp_connection_send_arbitrary(
				&conn.hctx,
				reflect.as_bytes(info),
				server.hr.l,
			)
		}
	}

	server.ping_seq += 1
	server.last_ping = time.now()
}

@(export)
server_rewire :: proc(server: ^Server) {
	sim.rewire_op(server.acceptor, server_on_accept)
	sim.rewire_interval(server.ping_interval, server_on_ping)
	server_schedule_tick(server)

	for _, c in server.connections {
		c.hctx.host.on_packet = server_on_tcp_packet
		c.hctx.host.on_kill = server_on_tcp_kill
	}

	server.udp.host.on_packet = server_on_udp_packet
	server.udp.host.on_ping = server_on_udp_ping
	server.udp.host.decrypt = server_decrypt_packet

	server.tcp_send = server_tcp_send
	server.udp_send = server_udp_send
}

server_shutdown :: proc(server: ^Server) {
	if server.did_shutdown do return
	server.did_shutdown = true

	hot.sip.io_remove(server.acceptor)
	hot.sip.io_remove(server.ping_interval)

	for _, c in server.connections {
		sim.tcp_connection_kill(&c.hctx, server.hr.l)
	}

	for c in sim.dl_iter_next(
		&server.resolving_udp.first,
		Connection,
		offset_of(Connection, resolving_udp),
	) {
		sim.tcp_connection_kill(&c.hctx, server.hr.l)
	}

	sim.udp_connection_kill(&server.udp, server.hr.l)
	nbio.close(server.tcp, l = server.hr.l)
	nbio.close(server.file_tcp, l = server.hr.l)
}

@(export)
server_deinit :: proc(server: ^Server) {
	server_shutdown(server)

	res := hot.sip.io_run()
	log.assertf(res == nil, "failed to run the io scheduler: %v", res)

	delete(server.connections)

	game_destroy(&server.lobby)

	conn := sqlite.db_handle(server.insert_user)
	sqlite.finalize(server.statements)
	rs := sqlite.close(conn)
	sqlite.assert_ok(conn, rs)
}

when ODIN_BUILD_MODE == .Executable {
	main :: proc() {
		main_proc()
	}
}

main_proc :: proc() {
	context.assertion_failure_proc = hot.init_trace()

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

	context.temp_allocator = arna.allocator(&temp_arna)

	allc: tlsf.Allocator
	allc_err := tlsf.init_from_allocator(
		&allc,
		arna.allocator(&global_arna),
		CHUNK_SIZE,
		CHUNK_SIZE,
	)
	log.assertf(
		allc_err == nil,
		"could not get the initial allc page: %v",
		allc_err,
	)
	context.allocator = tlsf.allocator(&allc)

	when sim.TRACK_ALLOCATIONS {
		track: mem.Tracking_Allocator
		mem.tracking_allocator_init(&track, context.allocator)
		context.allocator = mem.tracking_allocator(&track)
	}

	server_static_init(hot.sip)

	posix.signal(.SIGINT, on_sigint)
	on_sigint :: proc "c" (sig: posix.Signal) {
		if sync.atomic_load(hot.sip.interrupted) {
			posix.exit(1)
		}

		sync.atomic_store(hot.sip.interrupted, true)
	}

	hr: hot.Reloader
	hr.watch_dirs = {"server", "sim"}
	hr.extra_args = {
		"-define:TRACK_ALLOCATIONS=true",
		"-define:SQLITE_SHARED=true",
	}
	hr.dyn_defs = {{"LATENCY", sim.LATENCY}, {"LOCAL", sim.LOCAL}}
	hr.lib = {
		memory_size = server_memory_size,
		static_init = server_static_init,
		init        = auto_cast server_init,
		deinit      = auto_cast server_deinit,
	}
	hr.reload = hot.reload

	hr.init_allocator = arna.allocator(&init_arna)

	context.logger = log.create_console_logger()

	err := nbio.acquire_thread_event_loop()
	log.assertf(err == nil, "failed to acquire the event loop: %v", err)
	hr.l = nbio.current_thread_event_loop()

	for !sync.atomic_load(hot.sip.interrupted) {
		_ = hot.reload(&hr, {module_name = "server"})

		runerr := nbio.run()
		log.assertf(runerr == nil, "failed to run the event loop: %v", runerr)
	}

	if sim.TRACK_ALLOCATIONS {
		hot.deinit(&hr)
		arna.destroy(&init_arna)
		nbio.release_thread_event_loop()
		log.destroy_console_logger(context.logger)
		context.logger = {}
		server_static_deinit()
		when sim.TRACK_ALLOCATIONS do sim.tracking_allocator_destroy(&track)
		hot.unload_libraries(&hr)
		arna.bulk_destroy(&temp_arna, &global_arna, &init_arna)
	}
}
