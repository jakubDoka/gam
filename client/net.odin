package client

import "../sim"
import "../util/b58"
import "../util/bit_arr"
import "../util/nm"
import "../util/rtt"
import "../util/sqlite"
import "base:runtime"
import "core:log"
import "core:mem"
import "core:nbio"
import "core:net"
import "core:os"
import "core:reflect"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:sync/chan"
import "core:thread"
import "core:time"

/// <ip>#<identity>
parse_conn_string :: proc(
	conn_string: string,
) -> (
	endpoint: nbio.Endpoint,
	identity_prefix: string,
	ok: bool,
) {
	SEP := "#"

	iter := conn_string
	endp := strings.split_iterator(&iter, SEP) or_return
	endpoint = nbio.parse_endpoint(string(endp)) or_return
	identity_prefix = iter
	ok = true

	return
}

client_handle_packet :: proc(
	client: ^Client,
	packet: sim.Server_Packet,
) -> (
	ignored: bool,
) {
	client.last_server_packet = time.now()

	packet := packet
	switch &p in packet {
	case sim.Server_Ping:
		ok := chan.send(
			client.rtt_worker_reqs,
			Rtt_Worker_Request {
				server = client.server_endpoint,
				config = p,
				timeout = sim.PING_INTERVAL,
				execute = rtt_worker_execute,
			},
		)
		assert(ok)
	case sim.Server_State:
		client.tps = p.tps

		present := bit_arr.init(len(client.ents.slots), context.temp_allocator)
		new := bit_arr.init(len(client.ents.slots), context.temp_allocator)

		for i in 0 ..< len(client.ents.slots) {
			assert(!bit_arr.contains(present, i))
		}

		net_id_to_ent := make(
			map[sim.Ent_Net_ID]^sim.Ent,
			client.ents.len,
			context.temp_allocator,
		)

		index_iter := sim.ents_iter(&client.ents)
		for e in sim.ents_iter_next(&index_iter) {
			net_id_to_ent[e.net_id] = e
		}

		d: sim.Decoder = {p.ents.raw}
		for len(d.remining) > 0 {
			synced := sim.ent_synced_decode(&client.ents, &d) or_return

			ne := net_id_to_ent[synced.net_id]
			if ne == nil {
				assert(synced.net_id.seq != 0)
				synced.net_id.seq -= 1
				ne = sim.ents_add(&client.ents, &synced.net_id)
				if ne == sim.NIL_ENT do continue
				ne.synced = synced
				bit_arr.set(new, int(ne.id.index))
			}

			bit_arr.set(present, int(ne.id.index))

			normalize_timer :: proc(
				client: ^Client,
				sync: ^f32,
				current: f32,
			) {
				sync^ -= client.rtt
				if sync^ < 0 && current > 0 {
					sync^ = current
				}
			}

			normalize_timer(client, &synced.reload, ne.reload)
			synced.parry_progress -= client.rtt

			if synced.net_id == p.you &&
			   f32(f64(time.since(client.last_inpulse)) / f64(time.Second)) <
				   client.rtt * 3 {
				synced.vel = ne.vel
			}

			x := client_ent_extra_get(client, ne.id)

			synced.counter = max(synced.counter, ne.counter)

			x.energy_smoothing =
				ne.synced.energy_consumed +
				x.energy_smoothing -
				synced.energy_consumed
			x.rot_smoothing = sim.normalize_angle(
				ne.synced.rot + x.rot_smoothing - synced.rot,
			)
			x.pos_smoothing = ne.synced.pos + x.pos_smoothing - synced.pos
			ne.synced = synced
		}

		for &e in sim.ents_iter(&client.ents) {
			if !bit_arr.contains(present, int(e.id.index)) &&
			   e.age > client.rtt * 2 + (1.0 / sim.TPS) {
				sim.ents_queue_remove(&client.ents, e.id)
				continue
			}

			e.parent = (net_id_to_ent[e.parent_net_id] or_else sim.NIL_ENT).id
		}

		client.ent = (net_id_to_ent[p.you] or_else sim.NIL_ENT).id
		client.applied_input.next_net_id = p.your_next_net_id

		for keys, i in p.players[:min(len(p.players), len(client.players))] {
			p := &client.players[i]
			p.input = keys
			p.ent = (net_id_to_ent[p.net_ent] or_else sim.NIL_ENT).id
		}

		buf := make([]sim.Vec, len(client.ents.slots), context.temp_allocator)
		marks := make(
			[dynamic]^sim.Ent,
			0,
			len(client.ents.slots),
			context.temp_allocator,
		)

		for &e, i in client.ents.slots {
			buf[i] = e.pos
			client.ent_extra[i].pos_smoothing += e.pos

			if !bit_arr.contains(present, i) {
				if sim.ent_is_alive(&e) {
					append(&marks, &e)
					e.id.gen += 1
				}
			}
		}

		sim.ents_move(&client.ents, client.rtt)

		for m in marks {
			m.id.gen -= 1
		}

		for e, i in client.ents.slots {
			client.ent_extra[i].pos_smoothing -= e.pos
		}
	case sim.Server_Map:
		delete(client.map_buf)
		client.map_buf = slice.clone(p.bytes)
		mapa, _ := sim.map_load(client.map_buf)
		client.ents.mapa = mapa

		client_fetch_missig_assets(
			client,
			slice.enumerated_array(&client.ents.sprites),
		)
	case sim.Server_Cold_State:
		clear(&client.players)

		client.ui.has_dirty_config = p.dirty_stats

		log.debug("received the cold state, our id:", client.hctx.ch.id)

		for &pl in p.players {
			append(&client.players, Player{pl, {}, {}})
			log.debug("player:", pl.id, ":", nm.str(&pl.name))
		}

		client.player_idx = -1
		for r, i in client.players {
			if r.pk == client.hctx.ch.id {
				client.player_idx = i
			}
		}
	case sim.Server_Stats:
		clear(&client.ents.stats)

		d := sim.Decoder{p.stats.raw}
		for len(d.remining) != 0 {
			i := len(client.ents.stats)
			append(&client.ents.stats, sim.Ent_Stats{})
			slot := &client.ents.stats[i]
			sim.ent_stats_decode(slot, sim.Ent_Stats_ID(i), &d) or_return
		}

		assets := make([dynamic]sim.Asset_ID, context.temp_allocator)

		for &s in client.ents.stats {
			context.user_ptr = &assets
			sim.recurse(s, visit, ignore_unknown = true)

			visit :: proc(
				val: any,
				tag: reflect.Struct_Tag,
			) -> (
				go_deeper: bool,
				ok: bool = true,
			) {
				client := (^[dynamic]sim.Asset_ID)(context.user_ptr)
				sw: switch &v in val {
				case sim.Asset_ID:
					sim.add_asset(client, v)
				case:
					go_deeper = true
				}

				return
			}
		}

		client_fetch_missig_assets(client, assets[:])
	case sim.Server_Cmd:
		switch p.type {
		case .Laser:
			l := retained_add(&client.lasers)
			if l == nil do break

			ls := sim.ents_stats_get(&client.ents, p.stats)

			l.pos = p.pos
			l.dir = p.dir
			l.team = p.team
			l.stats = p.stats
			l.lifetime = ls.lifetime
		}
	case sim.Broadcast_Packet:
		switch &p in p {
		case sim.Chat_Msg:
			chat_ring_push(
				&client.chat.messages,
				{
					name = p.name,
					color = ui_player_color(p.id[:]),
					time = time.now(),
					content = p.content,
				},
			)
		case sim.Empty:
		}
	case sim.Server_Event:
		switch p.type {
		case .File_Uploaded:
			for &ass, i in client.content_editor.dropped_assets {
				if ass.base.hash == p.hash {
					ass.uploaded = true
					break
				}
			}
		}
	}

	return
}

client_fetch_missig_assets :: proc(client: ^Client, set: []sim.Asset_ID) {
	has_missing := false
	for &s in set {
		if s == 0 do continue

		name := asset_path(client, s)

		if _, err := os.stat(name, context.temp_allocator); err != nil {
			append(&client.assets_to_fetch, s)
			has_missing = true
		}
	}

	if has_missing {
		fetch_assets(client)
	}
}

Req :: struct {
	using hctx: sim.Handshake,
	path:       string,
	idx:        int,
}

#assert(offset_of(Req, hctx) == 0)

req_connect :: proc(client: ^Client) -> (^Req, ^sim.Client_Request_Header) {
	req := new(Req)
	req.l = client.l
	req.host.asoc_data = client
	req.get_pk = get_pk

	sim.hctx_connect_client(req, client.hctx.server_endpoint, client.l)

	return req, (^sim.Client_Request_Header)(&req.ch.payload)

	get_pk :: proc(req: ^Req) -> sim.Private_Key {
		client := (^Client)(req.host.asoc_data)
		prof := get_selected_user(client)
		return prof.pk
	}
}

upload_assets :: proc(client: ^Client) {
	MAX_INFLIGHT_ASSETS :: 5

	ctx := &client.content_editor

	for client.inflight_assets < MAX_INFLIGHT_ASSETS {
		if ctx.upload_cursor >= len(ctx.dropped_assets) do break
		next := ctx.dropped_assets[ctx.upload_cursor]
		ctx.upload_cursor += 1

		req, req_slot := req_connect(client)
		req_slot.kind = .Upload_Content
		req_slot.conn_id = client.conn_id
		req.send.asset = next.base
		req.on_boot = on_boot
		req.asset_path = asset_path
		req.path = next.path
		req.idx = ctx.upload_cursor - 1

		on_boot :: proc(req: ^Req) -> bool {
			return sim.send_asset(req)
		}

		asset_path :: proc(hctx: ^Req) -> string {
			defer hctx.path = ""
			return strings.clone(hctx.path)
		}

		client.inflight_assets += 1
	}

	on_kill :: proc(req: ^Req) {
		client := (^Client)(req.host.asoc_data)
		client.inflight_assets -= 1

		if req.last_error == "" {
			client.content_editor.dropped_assets[req.idx].uploaded = true
		}

		upload_assets(client)

		delete(req.path)
		req^ = {}
		free(req)
	}
}

fetch_assets :: proc(client: ^Client) {
	MAX_INFLIGHT_ASSETS :: 5

	for client.inflight_assets < MAX_INFLIGHT_ASSETS {
		if client.inflight_asset_cursor >= len(client.assets_to_fetch) do break
		next := client.assets_to_fetch[client.inflight_asset_cursor]
		client.inflight_asset_cursor += 1

		req, req_slot := req_connect(client)
		req_slot.kind = .Download_Content
		req_slot.conn_id = client.conn_id
		req_slot.download_content.id = next
		req.path = strings.clone(asset_path(client, next))
		req.asset_path = asset_path_
		req.cleanup = on_kill
		sim.fetch_asset(req)

		asset_path_ :: proc(hctx: ^Req) -> string {
			defer hctx.path = ""
			return hctx.path
		}

		client.inflight_assets += 1
	}

	if client.inflight_assets == 0 {
		client.inflight_asset_cursor = 0
		clear(&client.assets_to_fetch)
		refresh_sheet(client)
	}

	on_kill :: proc(req: ^Req) {
		client := (^Client)(req.host.asoc_data)
		client.inflight_assets -= 1

		if req.last_error == "" {
			_, res := sqlite.exec(
				client.save_asset,
				req.sh.id,
				sim.hash_prefix(&req.fetch.asset_meta.hash),
				nm.str(&req.fetch.asset_meta.name),
				req.fetch.asset_meta.type,
			)
			sqlite.assert_ok(client.save_asset, res)
		} else {
			panic("TDOD: show an error")
		}

		fetch_assets(client)

		if len(req.error) != 0 {
			log.error(req.error)
		}

		req^ = {}
		free(req)
	}
}

client_ent_by_net_id :: proc(client: ^Client, id: sim.Ent_Net_ID) -> ^sim.Ent {
	// TODO: build a net id index instead, this is a strain on the server
	iter := sim.ents_iter(&client.ents)
	for e in sim.ents_iter_next(&iter) {
		if e.net_id == id {
			return e
		}
	}
	return sim.NIL_ENT
}

asset_path :: proc(client: ^Client, id: sim.Asset_ID) -> string {
	id := id
	name := b58.encode(mem.ptr_to_bytes(&id))
	asset_path_no_ext, _ := os.join_path(
		{client.data_dir, ASSET_CACHE, name},
		context.temp_allocator,
	)
	asset_path, _ := os.join_filename(
		asset_path_no_ext,
		sim.EXT_BY_TYPE[.Sprite][1:],
		context.temp_allocator,
	)

	return asset_path
}

client_connect :: proc(client: ^Client, endp: nbio.Endpoint) {
	if client.connection_stage != .Disconnected do return
	client.connection_stage = .Connecting

	client.hctx.get_pk = get_pk
	client.hctx.on_boot = on_boot

	{
		udp_sock, create_err := nbio.create_udp_socket(.IP4)
		sim.hctx_fail_guard(&client.hctx, "can't open udp socket", create_err)
		if create_err != nil do return

		client.udp.sock = udp_sock

		bind_err := nbio.bind(udp_sock, {nbio.IP4_Any, 0})
		sim.hctx_fail_ctx(&client.hctx, "can't bind udp socket", bind_err)
		if bind_err != nil do return

		client.hctx.error = ""
	}

	header := (^sim.Client_Request_Header)(&client.hctx.handshake.ch.payload)
	header.kind = .Play
	client.tcp.host.asoc_data = client

	sim.hctx_connect_client(&client.hctx, endp, client.l)

	on_failure :: proc(client: ^Client, reason: string) {
		#assert(offset_of(Client, hctx) == 0)
		client_clear_state(client, reason)
	}

	get_pk :: proc(client: ^Client) -> sim.Private_Key {
		selected_user := ui_get_selected_user(&client.ui)
		return selected_user.pk
	}

	on_boot :: proc(client: ^Client) -> bool {
		client.conn_id =
			(^sim.Server_Init_Data)(raw_data(&client.sh.payload)).conn_id

		sim.tcp_connection_boot(
			&client.tcp,
			sim.CLIENT_RECV_BUF_SIZE,
			sim.SERVER_RECV_BUF_SIZE,
			l = client.l,
		)
		client.tcp.host = {
			asoc_data = client,
			on_packet = client_on_tcp_packet,
		}
		client.cleanup = client_on_tcp_kill

		sim.udp_connection_boot(&client.udp, l = client.l)
		client.udp.host = {
			asoc_data = client,
			on_packet = client_on_udp_packet,
			on_kill   = client_on_udp_kill,
			decrypt   = client_decrypt_packet,
		}

		client.connection_stage = .Connected
		client.last_server_packet = time.now()

		return true
	}
}

client_on_tcp_kill :: proc(client: ^Client) {
	client_clear_state(client, "tcp connection terminated", .Tcp)
}

client_on_udp_kill :: proc(
	conn: ^sim.UDP_Connection,
	l: ^nbio.Event_Loop,
	natural: bool,
) {
	client := (^Client)(conn.host.asoc_data)
	client_clear_state(client, "udp connection terminated", .Udp)
}

client_on_udp_packet :: proc(
	conn: ^sim.UDP_Connection,
	_: ^nbio.Event_Loop,
	bytes: []u8,
) -> bool {
	client := (^Client)(conn.host.asoc_data)
	packet := sim.unmarshall_as(sim.Server_Packet, bytes) or_return
	client_handle_packet(client, packet)
	return true
}

client_on_tcp_packet :: proc(
	conn: ^sim.TCP_Connection,
	_: ^nbio.Event_Loop,
	bytes: []u8,
) -> bool {
	client := (^Client)(conn.host.asoc_data)
	packet := sim.unmarshall_as(sim.Server_Packet, bytes) or_return
	client_handle_packet(client, packet)
	return true
}

client_decrypt_packet :: proc(
	conn: ^sim.UDP_Connection,
	_: nbio.Endpoint,
	packet: []u8,
) -> (
	[]u8,
	sim.Decrypt_Error,
) {
	client := (^Client)(conn.host.asoc_data)
	return sim.decrypt_packet(&client.hctx.tcp.secret, packet)
}

Rtt_Worker_Request :: struct {
	server:  nbio.Endpoint,
	config:  sim.Server_Ping,
	timeout: time.Duration,
	// NOTE: hot reloading
	execute: proc(_: ^Rtt_Worker_Request, _: ^Rtt_Worker_Ctx),
}

Rtt_Worker :: struct {
	rt:   ^f32,
	reqs: chan.Chan(Rtt_Worker_Request, .Recv),
}

Rtt_Worker_Ctx :: struct {
	using base:  Rtt_Worker,
	socket:      net.UDP_Socket,
	es:          rtt.Estimator,
	last_server: nbio.Endpoint,
}

rtt_worker_execute :: proc(ws: ^Rtt_Worker_Request, worker: ^Rtt_Worker_Ctx) {
	reopen_socket := true
	defer if reopen_socket {
		net.close(worker.socket)
		socket, operr := net.make_bound_udp_socket(net.IP4_Any, 0)
		assert(operr == nil)
		worker.socket = socket
	}

	socket := worker.socket

	if ws.server != worker.last_server {
		worker.es = {}
		worker.last_server = ws.server
	}

	net.set_option(socket, .Receive_Timeout, ws.timeout)

	now := time.now()
	nonce: u8 = 0

	Packet :: struct {
		header:     sim.Crypt_Header,
		using ping: sim.Ping,
	}

	pkt: Packet

	pkt.id = ws.config.id
	pkt.tag = sim.compute_next_ping_tag(&ws.config.sk, nonce)
	nonce += 1

	wrtn, werr := net.send(socket, mem.ptr_to_bytes(&pkt), ws.server)
	if werr != nil {
		log.warn("failed to initiate ping, state:", ws, werr)
		return
	}

	assert(wrtn == size_of(pkt))

	rcvd, remote, rerr := net.recv(socket, mem.ptr_to_bytes(&pkt))
	if rerr != nil {
		log.warn("failed to receive inital ping response, state:", ws, rerr)
		return
	}

	if remote != ws.server {
		log.warn("recieved packet from somebody else, state:", ws, remote)
		return
	}

	if pkt.id != ws.config.id {
		log.warn("received ping with a wrong id, state:", ws, pkt)
		return
	}

	expected_tag := sim.compute_next_ping_tag(&ws.config.sk, nonce)
	if pkt.tag != expected_tag {
		log.warn("server did not send the expected tag, state:", ws, pkt)
		return
	}

	nonce += 1

	rtt.update(&worker.es, time.since(now) + sim.LATENCY * time.Millisecond)
	sync.atomic_store(worker.rt, rtt.smoothed(&worker.es))

	pkt.tag = sim.compute_next_ping_tag(&ws.config.sk, nonce)
	wrtn, werr = net.send(socket, mem.ptr_to_bytes(&pkt), ws.server)
	if werr != nil {
		log.warn("failed to send the final ping response, state:", ws, werr)
		return
	}

	assert(wrtn == size_of(pkt))

	reopen_socket = false
}

rtt_worker_run :: proc(ch: Rtt_Worker) -> ^thread.Thread {
	ctx := runtime.default_context()
	ctx.logger = context.logger

	return thread.create_and_start_with_poly_data(
		ch,
		worker_run,
		init_context = ctx,
	)

	worker_run :: proc(worker: Rtt_Worker) {
		socket, cserr := net.make_bound_udp_socket(net.IP4_Any, 0)
		assert(cserr == nil)
		defer net.close(socket)

		worker := Rtt_Worker_Ctx {
			base   = worker,
			socket = socket,
		}

		for {
			ws, ok := chan.recv(worker.reqs)
			if !ok do break
			ws->execute(&worker)
		}
	}
}
