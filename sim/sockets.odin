package sim

import "../simt/nbio"
import "../util/hot"
import "base:runtime"
import "core:fmt"
import "core:log"
import "core:mem"
import "core:slice"
import "core:time"

GAME_PORT :: 6012
FILE_PORT :: 6013

ASSET_BUF_SIZE :: size_of(Crypt_Header) + 128 * size_of(Asset_ID)
HANDSHAKE_STAGE_TIMEOUT :: 500 * time.Millisecond
INACTIVE_SECRET :: Secret_Key{}
PING_INTERVAL :: 400 * time.Millisecond
BUFFER_CHUNK_SIZE :: (1 << 16) - size_of(int) * 4
LATENCY :: #config(LATENCY, 0)

DONWLOAD_BUF_SIZE :: 4096 * 4

Fetch_State :: struct {
	written:    int,
	asset_meta: Asset,
}

Send_State :: struct {
	asset:     Asset,
	file_size: int,
	red:       int,
}

send_asset :: proc(conn: ^Handshake) -> bool {
	conn.tcp.send_buf = make([]u8, DONWLOAD_BUF_SIZE)
	conn.tcp.timeout = time.Second * 3

	path := conn->asset_path()
	nbio.open_poly(path, conn, on_open, l = conn.l)

	on_open :: proc(op: ^nbio.Operation, conn: ^Handshake) {
		hctx_fail_guard(
			conn,
			"failed to open source file",
			op.open.path,
			op.open.err,
		)
		defer delete(op.open.path)

		if op.open.err != nil do return

		nbio.stat_poly(op.open.handle, conn, on_stat, l = op.l)
		conn.file = op.open.handle

		conn.error = ""
	}

	on_stat :: proc(op: ^nbio.Operation, conn: ^Handshake) {
		hctx_fail_guard(conn, "failed to stat the source file", op.stat.err)
		if op.stat.err != nil do return

		conn.send.file_size = int(op.stat.size)

		do_progress(conn)
		conn.error = ""
	}

	do_progress :: proc(conn: ^Handshake) {
		state := &conn.send

		if state.asset != {} {
			buf := tcp_connection_send_buffer(conn)
			copy(buf, mem.ptr_to_bytes(&state.asset))
			tcp_connection_send_filled(
				conn,
				size_of(state.asset),
				first_on_sent,
				l = conn.l,
			)
			state.asset = {}

			return
		}

		if state.red < state.file_size {
			buf := tcp_connection_send_buffer(conn)
			to_read := min(state.file_size - state.red, len(buf))
			nbio.read_poly(
				conn.file,
				state.red,
				buf[:to_read],
				conn,
				on_read,
				all = true,
				l = conn.l,
			)

			return
		}

		fmt.assertf(
			state.red == state.file_size,
			"%v == %v",
			state.red,
			state.file_size,
		)

		tcp_connection_kill(conn, conn.l)
	}

	first_on_sent :: proc(op: ^nbio.Operation, conn: ^Handshake) {
		conn.tcp.sender = nil

		hctx_fail_guard(conn, "failed to send initial packet", op.send.err)
		if op.send.err != nil do return

		do_progress(conn)
		conn.error = ""
	}

	on_read :: proc(op: ^nbio.Operation, conn: ^Handshake) {
		hctx_fail_guard(
			conn,
			"failed to read chunk",
			op.read.err,
			conn.send.red,
		)
		if op.read.err != nil do return

		tcp_connection_send_filled(conn, op.read.read, on_sent, l = op.l)
		conn.error = ""
	}

	on_sent :: proc(op: ^nbio.Operation, conn: ^Handshake) {
		conn.tcp.sender = nil

		hctx_fail_guard(conn, "failed to read chunk", op.send.err)
		if op.send.err != nil do return

		conn.send.red += op.send.sent - size_of(Crypt_Header)

		do_progress(conn)
		conn.error = ""
	}

	return true
}

fetch_asset :: proc(req: ^Handshake) {
	req.tcp.host.on_packet = first_on_packet
	req.on_boot = on_boot

	on_boot :: proc(req: ^Handshake) -> bool {
		req.timeout = time.Second * 5
		req.one_shot_recv = true
		tcp_connection_boot(req, DONWLOAD_BUF_SIZE, 0, l = req.l)

		return true
	}

	first_on_packet :: proc(
		req: ^Handshake,
		l: ^nbio.Event_Loop,
		bytes: []u8,
	) -> bool {
		MAX_ASSET_SIZE :: 1024 * 1024 * 8

		req.fetch.asset_meta = unmarshall_as(Asset, bytes) or_return
		if req.fetch.asset_meta.size > MAX_ASSET_SIZE {
			return hctx_fail(
				req,
				"asset size too large",
				req.fetch.asset_meta.size,
			)
		}

		path := req->asset_path()
		nbio.open_poly(path, req, on_dest_open, {.Write, .Create}, l = req.l)

		return true
	}

	on_dest_open :: proc(op: ^nbio.Operation, req: ^Handshake) {
		hctx_fail_guard(
			req,
			"failed to open destination file for assset download",
			op.open.path,
			op.open.err,
		)
		defer delete(op.open.path)

		if op.open.err != nil {
			return
		}

		req.file = op.open.handle
		req.fetch.written = 0

		req.tcp.host.on_packet = on_packet
		req.one_shot_recv = false
		tcp_connection_poll_packets(req, req.l)

		req.error = ""
	}

	on_packet :: proc(
		hctx: ^Handshake,
		l: ^nbio.Event_Loop,
		bytes: []u8,
	) -> bool {
		nbio.write_poly(
			hctx.file,
			hctx.fetch.written,
			slice.clone(bytes),
			hctx,
			on_write,
			all = true,
			l = l,
		)
		hctx_ref(hctx)
		hctx.fetch.written += len(bytes)

		if hctx.fetch.written > hctx.fetch.asset_meta.size {
			return hctx_fail(
				hctx,
				"written asset size exceeded the advertized size",
			)
		}

		return true

		on_write :: proc(op: ^nbio.Operation, hctx: ^Handshake) {
			delete(op.write.buf)
			defer hctx_drop_ref(hctx)

			hctx_fail_guard(hctx, "failed to write to disk", op.write.err)
			if op.write.err != nil do return
			hctx.error = ""
		}
	}
}

Handshake :: struct {
	using tcp:       TCP_Connection,
	server_endpoint: nbio.Endpoint,
	using handshake: struct {
		ch:  Client_Hello,
		sh:  Server_Hello,
		ceh: Client_End_Hello,
		xpk: Private_Key,
	},
	get_pk:          proc(hctx: ^Handshake) -> Private_Key,
	on_boot:         proc(hctx: ^Handshake) -> bool,
	// NOTE: the string will be deallocated by the caller
	asset_path:      proc(hctx: ^Handshake) -> string,
	cleanup:         proc(_: ^Handshake),
	l:               ^nbio.Event_Loop,
	last_error:      string,
	error:           string,
	ctx:             [dynamic]any,
	file:            nbio.Handle,
	rc:              int,
	using stt:       struct #raw_union {
		fetch: Fetch_State,
		send:  Send_State,
	},
}

hctx_drop_ref :: proc(hctx: ^Handshake) {
	hctx.rc -= 1
	if hctx.rc >= 0 do return

	if hctx.file != 0 do nbio.close(hctx.file, l = hctx.l)
	hctx->cleanup()
}

hctx_ref :: proc(hctx: ^Handshake) {
	hctx.rc += 1
}

@(deferred_in = hctx_fail_guard_end)
hctx_fail_guard :: proc(
	hctx: ^Handshake,
	error: string,
	ctx: ..any,
	loc := #caller_location,
) {
	assert(hctx.error == "")
	hctx.error = error
	hctx.ctx = slice.to_dynamic(ctx, context.temp_allocator)
}

hctx_fail_ctx :: proc(hctx: ^Handshake, error: string, ctx: ..any) {
	hctx.error = error
	append(&hctx.ctx, ..ctx)
}

hctx_fail_guard_end :: #force_inline proc(
	hctx: ^Handshake,
	_: string,
	_: ..any,
	loc := #caller_location,
) {
	if hctx.error != "" {
		hctx.last_error = hctx.error
		log.error(hctx.error, hctx.ctx, location = loc)
		tcp_connection_kill(hctx, hctx.l)
	}
}

@(require_results)
hctx_fail :: proc(
	hctx: ^Handshake,
	error: string,
	ctx: ..any,
	loc := #caller_location,
) -> bool {
	hctx_fail_ctx(hctx, error, ..ctx)
	log.error(hctx.error, hctx.ctx, location = loc)
	return false
}

hctx_on_kill :: proc(hctx: ^Handshake, l: ^nbio.Event_Loop) {
	hctx_drop_ref(hctx)
}

hctx_connect_client :: proc(
	hctx: ^Handshake,
	endp: nbio.Endpoint,
	l: ^nbio.Event_Loop,
) {
	hctx.l = l
	hctx.host.on_kill = hctx_on_kill
	hctx.handshake = {
		ch = {payload = hctx.handshake.ch.payload},
	}

	nbio.dial_poly(endp, hctx, on_dial, l = l)

	on_dial :: proc(op: ^nbio.Operation, hctx: ^Handshake) {
		hctx_fail_guard(
			hctx,
			"failed to dial the server",
			op.dial.err,
			op.dial.endpoint,
		)
		if op.dial.err != nil do return

		hctx.tcp.sock = op.dial.socket
		hctx.server_endpoint = op.dial.endpoint

		log.debug("dialed server")

		selected_user := hctx->get_pk()
		client_handshake_init(&selected_user, &hctx.xpk, &hctx.handshake.ch)

		nbio.send_poly(
			hctx.tcp.sock,
			{mem.ptr_to_bytes(&hctx.handshake.ch)},
			hctx,
			on_hello_sent,
			all = true,
			timeout = HANDSHAKE_STAGE_TIMEOUT,
			l = op.l,
		)

		hctx.error = ""
	}

	on_hello_sent :: proc(op: ^nbio.Operation, hctx: ^Handshake) {
		hctx_fail_guard(hctx, "failed to send cleint hello", op.send.err)
		if op.send.err != nil do return

		hctx_fail_ctx(
			hctx,
			"client hello was only partially sent",
			op.send.sent,
		)
		if op.send.sent != size_of(Client_Hello) do return

		log.debug("client hello sent")

		nbio.recv_poly(
			hctx.tcp.sock,
			{mem.ptr_to_bytes(&hctx.handshake.sh)},
			hctx,
			on_server_hello,
			all = true,
			timeout = HANDSHAKE_STAGE_TIMEOUT,
			l = op.l,
		)

		hctx.error = ""
	}

	on_server_hello :: proc(op: ^nbio.Operation, hctx: ^Handshake) {
		hctx_fail_guard(hctx, "failed to receive server hello", op.recv.err)
		if op.recv.err != nil do return

		hctx_fail_ctx(
			hctx,
			"server hello has incorrect length",
			op.recv.received,
			size_of(Server_Hello),
		)
		if op.recv.received != size_of(Server_Hello) do return

		selected_user := hctx->get_pk()
		ok := client_handshake_end(
			&selected_user,
			&hctx.xpk,
			&hctx.ch,
			&hctx.sh,
			&hctx.ceh,
			&hctx.tcp.secret,
		)
		hctx_fail_ctx(hctx, "failed to end handshake", hctx.handshake)
		if !ok do return

		log.debug("server hello is valid")

		nbio.send_poly(
			hctx.tcp.sock,
			{mem.ptr_to_bytes(&hctx.handshake.ceh)},
			hctx,
			on_handshake_finished,
			all = true,
			timeout = HANDSHAKE_STAGE_TIMEOUT,
			l = op.l,
		)

		hctx.error = ""
	}

	on_handshake_finished :: proc(op: ^nbio.Operation, hctx: ^Handshake) {
		hctx_fail_guard(hctx, "handshake did not terminate", op.send.err)
		if op.send.err != nil do return

		log.debug("handshake complete, booting")

		if !hctx->on_boot() do return

		hctx.error = ""
	}
}

hctx_connect_server :: proc(hctx: ^Handshake, l: ^nbio.Event_Loop) {
	hctx.host.on_kill = hctx_on_kill

	nbio.recv_poly(
		hctx.sock,
		{mem.ptr_to_bytes(&hctx.ch)},
		hctx,
		on_conn_recv_hello,
		all = true,
		timeout = HANDSHAKE_STAGE_TIMEOUT,
		l = l,
	)

	on_conn_recv_hello :: proc(op: ^nbio.Operation, hctx: ^Handshake) {
		nbio.set_lable(hctx.l, hctx.sock, "recv hello")

		hctx_fail_guard(hctx, "handhake did no arrive", op.recv.err)
		if op.recv.err != nil do return

		log.debug("received handshake init from:", op.recv.source)

		hctx_fail_ctx(hctx, "received invalid client hello", op.recv.received)
		if op.recv.received != size_of(Client_Hello) do return

		log.debug("sending server hello")

		pk := hctx->get_pk()

		server_handshake_init(&pk, &hctx.xpk, &hctx.ch, &hctx.sh)
		nbio.send_poly(
			hctx.sock,
			{mem.ptr_to_bytes(&hctx.sh)},
			hctx,
			on_conn_send_hello,
			all = true,
			timeout = HANDSHAKE_STAGE_TIMEOUT,
			l = op.l,
		)

		hctx.error = ""
	}

	on_conn_send_hello :: proc(op: ^nbio.Operation, hctx: ^Handshake) {
		nbio.set_lable(hctx.l, hctx.sock, "send hello")

		hctx_fail_guard(hctx, "failed to send the server hello", op.send.err)
		if op.send.err != nil do return

		log.debug("server hello sent")

		nbio.recv_poly(
			hctx.sock,
			{mem.ptr_to_bytes(&hctx.ceh)},
			hctx,
			on_conn_recv_end_hello,
			all = true,
			timeout = HANDSHAKE_STAGE_TIMEOUT,
			l = op.l,
		)

		hctx.error = ""
	}

	on_conn_recv_end_hello :: proc(op: ^nbio.Operation, hctx: ^Handshake) {
		nbio.set_lable(hctx.l, hctx.sock, "recv end hello")
		hctx_fail_guard(
			hctx,
			"failed to receive client termination",
			op.recv.err,
		)
		if op.recv.err != nil do return

		log.debug("received client end hello from:", op.recv.source)

		hctx_fail_ctx(
			hctx,
			"received incomplete client termination",
			op.recv.received,
		)
		if op.recv.received != size_of(hctx.ceh) do return

		pk := hctx->get_pk()

		ok := server_handshake_end(
			&pk,
			&hctx.xpk,
			&hctx.ch,
			&hctx.sh,
			&hctx.ceh,
			&hctx.secret,
		)
		hctx_fail_ctx(hctx, "authentication failed")
		if !ok do return

		if !hctx->on_boot() do return

		hctx.error = ""
	}
}

UDP_Connection :: struct {
	sock:     nbio.UDP_Socket,
	send_buf: Packet_Buffer,
	recv_buf: []u8,
	host:     Host(UDP_Connection),
	receiver: ^nbio.Operation,
}

udp_connection_boot :: proc(
	conn: ^UDP_Connection,
	is_server := false,
	l: ^nbio.Event_Loop,
) {
	conn.receiver = nbio.recv_poly2(
		conn.sock,
		{conn.recv_buf},
		conn,
		is_server,
		on_recv,
		l = l,
	)

	on_recv :: proc(
		op: ^nbio.Operation,
		conn: ^UDP_Connection,
		is_server: bool,
	) {
		conn.receiver = nil

		kill := true
		defer if kill && !is_server {
			udp_connection_kill(conn, l = op.l)
		} else {
			conn.receiver = nbio.recv_poly2(
				conn.sock,
				{conn.recv_buf},
				conn,
				is_server,
				on_recv,
				l = op.l,
			)
		}

		if op.recv.err != nil {
			log.error("cant receive anymore:", op.recv.err)
			return
		}

		if conn.host.on_ping != nil {
			if ping, is := crypt_header_to_ping(conn.recv_buf); is {
				if new_tag, more := conn.host.on_ping(conn, ping); more {
					ping.tag = new_tag
					slc := mem.ptr_to_bytes(&ping)
					udp_connection_send(conn, op.recv.source, nil, slc, op.l)
				}

				kill = false
				return
			}
		}

		bytes, err := conn.host.decrypt(conn, op.recv.source, conn.recv_buf)
		if err != .Ok {
			log.error("decryption error:", err, op.recv.source)
			return
		}

		if !conn.host.on_packet(conn, op.l, bytes) {
			log.error("failed to handle packet")
			return
		}

		kill = false
	}
}

udp_connection_kill :: proc(conn: ^UDP_Connection, l: ^nbio.Event_Loop) {
	hot.sip.io_remove(conn.receiver)
	if conn.sock != 0 do nbio.close(conn.sock, l = l)
	if conn.host.on_kill != nil do conn.host.on_kill(conn, l)
	conn.sock = 0
	conn.receiver = nil
}

udp_connection_send :: proc(
	conn: ^UDP_Connection,
	to: nbio.Endpoint,
	secret: ^Secret_Key,
	packet: any,
	l: ^nbio.Event_Loop,
) -> bool {
	bytes, rc := packet_buffer_alloc(&conn.send_buf, secret, packet) or_return

	when LATENCY != 0 {
		Ctx :: struct {
			bytes: []u8,
			rc:    ^Buffer_Chunk,
			to:    nbio.Endpoint,
			conn:  ^UDP_Connection,
		}

		ctx := new(Ctx)
		ctx^ = {
			bytes = bytes,
			rc    = rc,
			to    = to,
			conn  = conn,
		}

		nbio.timeout_poly(LATENCY * time.Millisecond, ctx, on_delay, l = l)

		on_delay :: proc(op: ^nbio.Operation, ctx: ^Ctx) {
			nbio.send_poly(
				ctx.conn.sock,
				{ctx.bytes},
				ctx.rc,
				on_udp_sent,
				ctx.to,
				l = op.l,
			)
			free(ctx)
		}
	} else {
		nbio.send_poly(conn.sock, {bytes}, rc, on_udp_sent, to, l = l)
	}

	on_udp_sent :: proc(op: ^nbio.Operation, rc: ^Buffer_Chunk) {
		buffer_chunk_drop(rc)
	}

	return true
}

Packet_Buffer :: struct {
	free_chunks: ^Buffer_Chunk,
	slots:       []Buffer_Chunk,
}

packet_buffer_alloc :: proc(
	buf: ^Packet_Buffer,
	sk: ^Secret_Key,
	packet: any,
) -> (
	res: []u8,
	within: ^Buffer_Chunk,
	ok: bool,
) {
	chunk := buf.free_chunks

	final_bytes: []u8

	for chunk != nil {
		if chunk.rc == 0 {
			chunk.used = 0
		}

		me: Encoder
		ok := marshall(packet, &me)
		assert(ok)

		if len(chunk.data) - (chunk.used + size_of(Crypt_Header)) <
		   encoded_len(&me) {

			chunk.used = BUFFER_CHUNK_SIZE
			chunk = chunk.next_free
			continue
		}

		buf, e, oka := begin_crypt_packet(chunk.data[chunk.used:])
		assert(oka)

		okaa := marshall(packet, &e)
		assert(okaa)

		len := end_crypt_packet(sk, buf, e)
		chunk.used += len
		final_bytes = buf[:len]
		assert(chunk.used <= BUFFER_CHUNK_SIZE)

		break
	}

	buf.free_chunks = chunk

	if chunk == nil do return

	chunk.rc += 1

	return final_bytes, chunk, true
}

packet_buffer_reserve :: proc(
	buf: ^Packet_Buffer,
	count: uint,
	loc := #caller_location,
) {
	buf.slots = make([]Buffer_Chunk, count, loc = loc)

	for &slot in buf.slots {
		slot.buffer = buf
		slot.next_free = buf.free_chunks
		buf.free_chunks = &slot
	}
}

packet_buffer_destroy :: proc(buf: ^Packet_Buffer) {
	delete(buf.slots)
}

Buffer_Chunk :: struct {
	buffer:    ^Packet_Buffer,
	next_free: ^Buffer_Chunk,
	rc:        int,
	used:      int,
	data:      [BUFFER_CHUNK_SIZE]u8,
}

#assert(size_of(Buffer_Chunk) == 1 << 16)

buffer_chunk_drop :: proc(buf: ^Buffer_Chunk) {
	buf.rc -= 1

	if buf.rc == 0 && buf.used == BUFFER_CHUNK_SIZE {
		buf.used = 0
		buf.next_free = buf.buffer.free_chunks
		buf.buffer.free_chunks = buf
	}
}

Host :: struct($T: typeid) {
	asoc_data: rawptr,
	on_packet: proc(_: ^T, _: ^nbio.Event_Loop, _: []u8) -> bool,
	on_kill:   proc(_: ^T, _: ^nbio.Event_Loop),
	decrypt:   proc(_: ^T, _: nbio.Endpoint, _: []u8) -> ([]u8, Decrypt_Error),
	on_ping:   proc(_: ^T, id: Ping) -> (Ping_Tag, bool),
}

TCP_Connection :: struct {
	secret:          Secret_Key,
	sock:            nbio.TCP_Socket,
	reader:          ^nbio.Operation,
	recv_buf:        []u8,
	red:             int,
	handled:         int,
	handling_packet: bool,
	one_shot_recv:   bool,
	timeout:         time.Duration,
	sender:          ^nbio.Operation,
	send_buf:        []u8,
	buffered:        int,
	host:            Host(TCP_Connection),
}

tcp_connection_recv :: proc(op: ^nbio.Operation, conn: ^TCP_Connection) {
	conn.reader = nil

	assert(conn.sock != 0)

	kill := true
	defer if kill do tcp_connection_kill(conn, op.l)

	if op.recv.err != nil {
		log.error("encountered connection error:", op.recv.err)
		return
	}

	if op.recv.received == 0 {
		return
	}

	conn.red += op.recv.received

	kill = !tcp_connection_poll_packets(conn, op.l)
}

tcp_connection_poll_packets :: proc(
	conn: ^TCP_Connection,
	l: ^nbio.Event_Loop,
) -> bool {
	should_stop := false

	b: for {
		packet_bytes, err := decrypt_packet(
			&conn.secret,
			conn.recv_buf[conn.handled:conn.red],
		)

		switch err {
		case .Auth:
			log.warn("packet is not authenticated, dropping connection")
			return false
		case .Incomplete:
			if len(conn.recv_buf) == conn.red {
				if conn.handled == 0 {
					log.warn(
						"packet does not fit in the buffer,",
						"dropping connection",
					)
					return false
				}
				copy(conn.recv_buf, conn.recv_buf[conn.handled:])
				conn.red -= conn.handled
				conn.handled = 0
			}
			break b
		case .Ok:
			conn.handling_packet = true
			res := conn.host.on_packet(conn, l, packet_bytes)
			should_stop = conn.one_shot_recv
			conn.handling_packet = false
			if !res do return false
			conn.handled += len(packet_bytes) + size_of(Crypt_Header)
			assert(conn.handled <= conn.red)
			if should_stop do break b
		}
	}

	if !should_stop {
		tcp_connection_boot_recv(conn, l)
	}

	return true
}

tcp_connection_send :: proc(
	conn: ^TCP_Connection,
	packet: any,
	l: ^nbio.Event_Loop,
) -> bool {
	assert(context.allocator != context.temp_allocator)

	when LATENCY != 0 {
		buf := serialize_to_bytes(packet)

		nbio.timeout_poly2(
			LATENCY * time.Millisecond,
			conn,
			buf,
			proc(op: ^nbio.Operation, conn: ^TCP_Connection, buf: []u8) {
				buf := buf
				tcp_connection_send_no_delay(conn, buf, op.l)
				delete(buf)
			},
			l = l,
		)

		return true
	} else {
		return tcp_connection_send_no_delay(conn, packet, l)
	}
}

tcp_connection_send_no_delay :: proc(
	conn: ^TCP_Connection,
	packet: any,
	l: ^nbio.Event_Loop,
) -> bool {
	buf, e := begin_crypt_packet(conn.send_buf[conn.buffered:]) or_return
	marshall(packet, &e) or_return
	len := end_crypt_packet(&conn.secret, buf, e)
	conn.buffered += len

	tcp_connection_ensure_sending(conn, l)

	return true
}

tcp_connection_send_buffer :: proc(conn: ^TCP_Connection) -> []u8 {
	return conn.send_buf[size_of(Crypt_Header):]
}

tcp_connection_send_filled :: proc(
	conn: ^TCP_Connection,
	size: int,
	on_sent: proc(op: ^nbio.Operation, sock: ^TCP_Connection),
	l: ^nbio.Event_Loop,
) {
	len := size + size_of(Crypt_Header)

	end_crypt_packet(&conn.secret, conn.send_buf[:len], {})

	conn.sender = nbio.send_poly(
		conn.sock,
		{conn.send_buf[:len]},
		conn,
		on_sent,
		all = true,
		timeout = conn.timeout,
		l = l,
	)
}

begin_crypt_packet :: proc(buf: []u8) -> (f: []u8, e: Encoder, ok: bool) {
	if len(buf) < size_of(Crypt_Header) do return
	return buf, Encoder{buf[size_of(Crypt_Header):]}, true
}

end_crypt_packet :: proc(sec: ^Secret_Key, buf: []u8, e: Encoder) -> int {
	assert(len(buf) >= size_of(Crypt_Header))
	header := (^Crypt_Header)(raw_data(buf))
	len := len(buf) - size_of(Crypt_Header) - len(e.remining)
	assert(mem.is_aligned(rawptr(uintptr(len)), 8))
	if sec == nil {
		header^ = {}
	} else {
		header.len = u32(len)
		encrypt(sec, &header.tag, buf[size_of(Crypt_Header):][:header.len])
	}
	return size_of(Crypt_Header) + len
}

tcp_connection_boot :: proc(
	conn: ^TCP_Connection,
	recv_buf_size: int,
	send_buf_size: int,
	l: ^nbio.Event_Loop,
	loc := #caller_location,
) {
	recv_buf_size := max(recv_buf_size, 1) // empty buffer would immediatelly panic
	conn.recv_buf = make([]u8, recv_buf_size, loc = loc)
	conn.send_buf = make([]u8, send_buf_size, loc = loc)
	tcp_connection_boot_recv(conn, l)
}

tcp_connection_boot_recv :: proc(conn: ^TCP_Connection, l: ^nbio.Event_Loop) {
	fmt.assertf(len(conn.recv_buf) != conn.red, "%v", conn)
	conn.reader = nbio.recv_poly(
		conn.sock,
		{conn.recv_buf[conn.red:]},
		conn,
		tcp_connection_recv,
		timeout = conn.timeout,
		l = l,
	)
}

tcp_connection_kill :: proc(conn: ^TCP_Connection, l: ^nbio.Event_Loop) {
	assert(!conn.handling_packet)
	hot.sip.io_remove(conn.reader)
	hot.sip.io_remove(conn.sender)
	if conn.sock != 0 do nbio.close(conn.sock, l = l)
	delete(conn.recv_buf)
	delete(conn.send_buf)
	conn^ = {
		host = conn.host,
	}
	if conn.host.on_kill != nil do conn.host.on_kill(conn, l)
}

tcp_connection_ensure_sending :: proc(
	conn: ^TCP_Connection,
	l: ^nbio.Event_Loop,
) {
	if conn.buffered == 0 || conn.sender != nil {
		return
	}

	assert(conn.sock != 0)

	conn.sender = nbio.send_poly(
		conn.sock,
		{conn.send_buf[:conn.buffered]},
		conn,
		tcp_connection_on_send,
		l = l,
	)
}

tcp_connection_on_send :: proc(op: ^nbio.Operation, conn: ^TCP_Connection) {
	conn.sender = nil

	if op.send.err != nil {
		log.error("error sending:", op.send.err)
		tcp_connection_kill(conn, op.l)
		return
	}

	assert(op.send.sent != 0)

	copy(conn.send_buf, conn.send_buf[op.send.sent:conn.buffered])
	conn.buffered -= op.send.sent

	tcp_connection_ensure_sending(conn, op.l)
}

interval_poly :: proc(
	period: time.Duration,
	v: $T,
	cb: proc(_: T),
	op_slot: ^^nbio.Operation = nil,
	l: ^nbio.Event_Loop,
) {
	op := nbio.timeout_poly3(period, v, cb, op_slot, on_tick, l = l)
	if op_slot != nil do op_slot^ = op

	on_tick :: proc(
		op: ^nbio.Operation,
		v: T,
		cb: proc(_: T),
		op_slot: ^^nbio.Operation,
	) {
		cb(v)
		if op.type == .None do return
		opa := nbio.timeout_poly3(
			op.timeout.duration,
			v,
			cb,
			op_slot,
			on_tick,
			l = op.l,
		)
		if op_slot != nil do op_slot^ = opa
	}
}

index: int
index2: int

interval_rewire_slot :: proc(op: ^nbio.Operation) -> any {
	return {&op.user_data[2], typeid_of(proc())}
}

op_rewire_slot :: proc(op: ^nbio.Operation) -> any {
	return {&op.user_data[0], typeid_of(proc())}
}
