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

CONNECTION_TIMEOUT :: 3 * time.Second

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

Clear_Source :: enum {
	Manual,
	Udp,
	Tcp,
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

Connection_State :: enum {
	Disconnected,
	Connecting,
	Connected,
	Disconnecting,
}

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
	endpoint = net.parse_endpoint(string(endp)) or_return
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
	client.last_server_packet = nbio.now(client.l)

	packet := packet
	switch &p in packet {
	case sim.Server_Ping:
		if client.rtt_worker != nil {
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
		}
	case sim.Server_State:
		client.tps = p.tps

		{
			packet: sim.Server_Packet = sim.Server_Map {
				client.ents.map_name,
				client.map_buf,
			}
			bytes := sim.serialize_to_bytes(packet, context.temp_allocator)

			hash: sim.Hash
			sim.hash(bytes, &hash)
			if hash != p.map_hash do return
		}

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
				fmt.assertf(synced.net_id.seq != 0, "%v", synced)
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
			   f32(
				   f64(nbio.since(client.l, client.last_inpulse)) /
				   f64(time.Second),
			   ) <
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

		assert(len(d.remining) == 0)

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
			assert(sim.ent_is_alive(m))
		}

		for e, i in client.ents.slots {
			client.ent_extra[i].pos_smoothing -= e.pos
		}

	case sim.Server_Map:
		client.ents.map_name = p.name
		delete(client.map_buf)
		client.map_buf = slice.clone(p.bytes)
		mapa, ok := sim.map_load(client.map_buf)
		if !ok do break
		client.ents.mapa = mapa

		assert(slice.equal(p.bytes, client.map_buf))

		sim.ents_load_stats(&client.ents, client.ents.mapa.asoc_stats.raw)

		client_fetch_missig_assets(
			client,
			slice.enumerated_array(&client.ents.sprites),
		)
	case sim.Server_Cold_State:
		clear(&client.players)

		for &pl in p.players {
			append(&client.players, Player{pl, {}, {}})
		}

		client.player_idx = -1
		for r, i in client.players {
			if r.pk == client.hctx.ch.id {
				client.player_idx = i
			}
		}
	case sim.Server_Stats:
		sim.ents_load_stats(&client.ents, p.stats.raw)

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
				assets := (^[dynamic]sim.Asset_ID)(context.user_ptr)
				sw: switch &v in val {
				case sim.Asset_ID:
					sim.add_asset(assets, v)
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
				&client.messages,
				{
					name = p.name,
					seed = p.id,
					time = nbio.now(client.l),
					content = p.content,
				},
			)
		case sim.Empty:
		}
	case sim.Server_Event:
		switch p.type {
		case .File_Uploaded:
			for &ass, i in client.upload.assets {
				if ass.base.hash == p.hash {
					ass.uploaded = true
					break
				}
			}
		}
	case sim.Asset:
		save_asset(client, client.sh.id, &p)
		client_fetch_missig_assets(client, {sim.hash_prefix(&p.hash)})
	case sim.Server_Asset_Deleted:
		delete_asset(client, client.sh.id, p.id, p.name)
	}

	return
}

client_fetch_missig_assets :: proc(client: ^Client, set: []sim.Asset_ID) {
	Ctx :: struct {
		using client: ^Client,
		to_stat:      int,
	}

	ctx := new_clone(Ctx{client = client})
	defer if ctx.to_stat == 0 do free(ctx)

	for s in set {
		if s == 0 do continue

		slot: Saved_Asset
		res, st := sqlite.query(client.get_asset, slot, s)
		sqlite.reset(st)

		ctx.to_stat += 1

		name := asset_path(client, s)

		// TODO(low): this does not matter that much but we could use arena
		nbio.open_poly3(
			strings.clone(name),
			ctx,
			s,
			res == .DONE,
			on_open,
			l = client.l,
		)

		on_open :: proc(
			op: ^nbio.Operation,
			ctx: ^Ctx,
			asset: sim.Asset_ID,
			missing_in_db: bool,
		) {
			delete(op.open.path)
			if op.open.err != nil || missing_in_db {
				append(&ctx.client.assets_to_fetch, asset)
			} else {
				nbio.close(op.open.handle, l = ctx.client.l)
			}

			ctx.to_stat -= 1
			if ctx.to_stat == 0 {
				fetch_assets(ctx.client)
				free(ctx)
			}
		}
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
	req.timeout = time.Second * 3
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

prepare_upload :: proc(client: ^Client, files: []cstring) {
	ctx := &client.upload
	ctx.error = ""

	gpa := context.allocator
	context.allocator = arna.allocator(&ctx.arena)
	ctx.arena_rc -= 1
	if ctx.arena_rc < 0 {
		free_all(context.allocator)
	}
	ctx.arena_rc += 1
	ctx.assets = {}

	resize(&ctx.assets, len(files))

	for file, i in files {
		file := strings.clone(string(file))
		entry := &ctx.assets[i]

		filename := nbio.base(file)

		mtype: Maybe(sim.Asset_Type)
		for ext, i in sim.EXT_BY_TYPE {
			if strings.ends_with(filename, ext) {
				mtype = i
			}
		}

		entry.issue = "Invalid file extension."
		type := mtype.? or_continue

		filename = filename[:len(filename) - len(sim.EXT_BY_TYPE[type])]

		entry.base.type = type
		entry.issue = "Name is too long."
		entry.base.name = nm.from_str(filename) or_continue

		entry.path = file
		entry.issue = ""

		Ctx :: struct {
			using client: ^Client,
			file_idx:     int,
			gen:          int,
		}

		ctx.arena_rc += 1
		ctx := new_clone(Ctx{client, i, ctx.gen})

		// TODO(low): the file can be big and that can mess up the
		// allocator, we should do a streamed hashing
		nbio.read_entire_file(
			entry.path,
			ctx,
			on_read,
			l = client.l,
			allocator = gpa,
		)

		on_read :: proc(
			user_data: rawptr,
			data: []byte,
			err: nbio.Read_Entire_File_Error,
		) {
			defer delete(data)

			ctx := (^Ctx)(user_data)
			ed_ctx: ^Upload_State = &ctx.client.upload
			ed_ctx.arena_rc -= 1
			// NOTE: the arena is always held once this exists but the
			// only place that can drop it is when the files get
			// reuploaded

			if ctx.gen != ed_ctx.gen {
				return
			}

			entry := &ed_ctx.assets[ctx.file_idx]

			if err.operation != .None {
				entry.issue = "Can't load the file for some reason."
				log.error("Failed to fully load the upload file", err)
				return
			}

			sim.hash(data, &entry.base.hash)
			entry.base.size = len(data)
		}
	}
}

upload_assets :: proc(client: ^Client, init := false) {
	MAX_INFLIGHT_ASSETS :: 5

	ctx := &client.upload

	if init do ctx.cursor = 0

	for client.inflight_assets < MAX_INFLIGHT_ASSETS {
		if ctx.cursor >= len(ctx.assets) do break
		next := ctx.assets[ctx.cursor]
		ctx.cursor += 1

		req, req_slot := req_connect(client)
		req_slot.kind = .Upload_Content
		req_slot.conn_id = client.conn_id
		req.send.asset = next.base
		req.on_boot = on_boot
		req.asset_path = asset_path
		req.cleanup = on_kill
		req.path = next.path
		req.idx = ctx.cursor - 1

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
			client.upload.assets[req.idx].uploaded = true
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
		log.debug("fetching asset:", req.path)
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
		client->on_sheet_refresh()
	}

	on_kill :: proc(req: ^Req) {
		client := (^Client)(req.host.asoc_data)
		client.inflight_assets -= 1

		if req.last_error == "" {
			fmt.assertf(
				req.fetch.asset_meta.size == req.fetch.written,
				"TODO %v %v",
				req.fetch.asset_meta.size,
				req.fetch.written,
			)

			save_asset(client, req.sh.id, &req.fetch.asset_meta)
		} else {
			// TODO: show an error
		}

		fetch_assets(client)
		delete(req.path)

		if len(req.error) != 0 {
			log.error(req.error)
		}

		req^ = {}
		free(req)
	}
}

save_asset :: proc(client: ^Client, sh_id: sim.Identity, asset: ^sim.Asset) {
	_, res := sqlite.exec(
		client.save_asset,
		sh_id,
		sim.hash_prefix(&asset.hash),
		nm.str(&asset.name),
		asset.type,
	)
	sqlite.assert_ok(client.save_asset, res)
}

client_ent_by_net_id :: proc(client: ^Client, id: sim.Ent_Net_ID) -> ^sim.Ent {
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
	asset_path_no_ext, _ := nbio.join_path(
		{client.data_dir, ASSET_CACHE, name},
		context.temp_allocator,
	)
	asset_path, _ := nbio.join_filename(
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
	client.hctx.cleanup = client_on_tcp_kill
	client.hctx.error = ""
	client.hctx.last_error = ""

	{
		udp_sock, create_err := nbio.create_udp_socket(.IP4, client.l)
		sim.hctx_fail_guard(&client.hctx, "can't open udp socket", create_err)
		if create_err != nil do return

		client.udp.sock = udp_sock

		bind_err := nbio.bind(client.l, udp_sock, {nbio.IP4_Any, 0})
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
		selected_user := get_selected_user(client)
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
		client.host.asoc_data = client
		client.host.on_packet = client_on_tcp_packet

		sim.udp_connection_boot(&client.udp, l = client.l)
		client.udp.host = {
			asoc_data = client,
			on_packet = client_on_udp_packet,
			on_kill   = client_on_udp_kill,
			decrypt   = client_decrypt_packet,
		}

		client.connection_stage = .Connected
		client.last_server_packet = nbio.now(client.l)

		return true
	}
}

client_on_tcp_kill :: proc(client: ^Client) {
	client_clear_state(client, "tcp connection terminated", .Tcp)
}

client_on_udp_kill :: proc(conn: ^sim.UDP_Connection, l: ^nbio.Event_Loop) {
	client := (^Client)(conn.host.asoc_data)
	client_clear_state(client, "udp connection terminated", .Udp)
}

client_clear_state :: proc(
	client: ^Client,
	reason: string,
	source: Clear_Source = .Manual,
) {
	if client == nil do return

	if client.connection_stage == .Disconnected do return
	client.connection_stage = .Disconnected
	client.last_cold_state_hash = {}
	sim.ents_clear(&client.ents)

	if source != .Tcp do sim.tcp_connection_kill(&client.hctx.tcp, client.l)
	if source != .Udp do sim.udp_connection_kill(&client.udp, client.l)

	log.errorf("killing connection (%s): %v", reason, source)
	client.ip_error = reason
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

	tm :: time

	now := tm.now()
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

	rtt.update(&worker.es, tm.since(now) + sim.LATENCY * time.Millisecond)
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

fetch_all_assets :: proc(client: ^Client) {
	req, req_slot := req_connect(client)
	req_slot.kind = .List_Assets
	req_slot.conn_id = client.conn_id
	req.on_boot = on_boot
	req.cleanup = on_kill
	req.host.on_packet = on_packet

	on_boot :: proc(req: ^Req) -> bool {
		sim.tcp_connection_boot(req, sim.ASSET_BUF_SIZE, 0, req.l)
		return true
	}

	on_packet :: proc(req: ^Req, l: ^nbio.Event_Loop, bytes: []u8) -> bool {
		client := (^Client)(req.host.asoc_data)
		assets := mem.slice_data_cast([]sim.Asset_ID, bytes)
		client_fetch_missig_assets(client, assets)
		return true
	}

	on_kill :: proc(req: ^Req) {
		free(req)
	}
}

client_on_ping :: proc(client: ^Client) {
	if client.connection_stage != .Connected do return

	if nbio.since(client.l, client.last_server_packet) > CONNECTION_TIMEOUT {
		client_clear_state(client, "connection timed out")
		return
	}

	assert(client.udp.sock != 0)
	assert(client.hctx.tcp.sock != 0)

	{
		selected_user := get_selected_user(client)

		packet := sim.Client_Cold_State {
			pause_game_progression = client.edit_mode_on,
			username               = selected_user.name,
		}

		buf := sim.serialize_to_bytes(packet, context.temp_allocator)

		new_hash: sim.Hash
		sim.hash(buf, &new_hash)

		if new_hash != client.last_cold_state_hash {
			client.last_cold_state_hash = new_hash
			tcp_send(client, packet)
		}
	}
}

client_on_tick :: proc(client: ^Client) {
	if client.connection_stage != .Connected do return
	udp_send(client, client.current_input.inner)
}

tcp_send :: proc(client: ^Client, packet: sim.Client_Packet) {
	ok := sim.tcp_connection_send(&client.hctx.tcp, packet, client.l)
	assert(ok)
}

udp_send :: proc(client: ^Client, packet: sim.Client_Packet) {
	assert(client.hctx.server_endpoint != {})

	ok := sim.udp_connection_send(
		&client.udp,
		client.hctx.server_endpoint,
		&client.hctx.tcp.secret,
		packet,
		client.l,
	)
	assert(ok)
}
