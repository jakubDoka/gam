package sim

import "../util/hot"
import "core:log"
import "core:nbio"
import "core:reflect"
import "core:time"

INACTIVE_SECRET :: Secret_Key{}
PING_INTERVAL :: 400 * time.Millisecond
BUFFER_CHUNK_SIZE :: (1 << 16) - size_of(int) * 4
LATENCY :: #config(LATENCY, 0)

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
	l: ^nbio.Event_Loop = nil,
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
			udp_connection_kill(conn)
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
					slc := reflect.as_bytes(ping)
					udp_connection_send(
						conn,
						op.recv.source,
						nil,
						{&slc, arbitrary_packet_encode_dyn},
						op.l,
					)
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

udp_connection_kill :: proc(conn: ^UDP_Connection, l: ^nbio.Event_Loop = nil) {
	hot.sip.io_remove(conn.receiver)
	if conn.sock != 0 do nbio.close(conn.sock, l = l)
	if conn.host.on_kill != nil do conn.host.on_kill(conn, l)
	conn.sock = 0
	conn.receiver = nil
}

@(require_results)
udp_connection_send_client :: proc(
	conn: ^UDP_Connection,
	to: nbio.Endpoint,
	secret: ^Secret_Key,
	packet: Client_Packet,
	l: ^nbio.Event_Loop,
) -> bool {
	packet := packet
	return udp_connection_send(
		conn,
		to,
		secret,
		{&packet, client_packet_encode_dyn},
		l = l,
	)
}

@(require_results)
udp_connection_send_server :: proc(
	conn: ^UDP_Connection,
	to: nbio.Endpoint,
	secret: ^Secret_Key,
	packet: Server_Packet,
	l: ^nbio.Event_Loop,
) -> bool {
	packet := packet
	return udp_connection_send(
		conn,
		to,
		secret,
		{&packet, server_packet_encode_dyn},
		l,
	)
}

udp_connection_send :: proc(
	conn: ^UDP_Connection,
	to: nbio.Endpoint,
	secret: ^Secret_Key,
	packet: Any_Packet,
	l: ^nbio.Event_Loop = nil,
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
	packet: Any_Packet,
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

		if chunk.used + size_of(Crypt_Header) < len(chunk.data) {
			arr := chunk.data[chunk.used + size_of(Crypt_Header):]
			e := Encoder{arr}
			eok := packet.encode(packet.data, &e)
			bytes := arr[:len(arr) - len(e.remining)]
			if eok {
				final_bytes = chunk.data[chunk.used:][:size_of(Crypt_Header) +
				len(bytes)]
				header := (^Crypt_Header)(&chunk.data[chunk.used])
				if sk != nil {
					header.len = u16(len(bytes))
					encrypt(sk, &header.tag, bytes)
				} else {
					header^ = {}
				}
				chunk.used += size_of(Crypt_Header) + len(bytes)
				assert(chunk.used <= BUFFER_CHUNK_SIZE)
				break
			} else {
				assert(chunk.used != 0)
			}
		}

		chunk.used = BUFFER_CHUNK_SIZE
		chunk = chunk.next_free
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
		log.error("encoungered connection error:", op.recv.err)
		return
	}

	if op.recv.received == 0 {
		log.error("unexpected eof")
		return
	}

	conn.red += op.recv.received

	b: for {
		packet_bytes, err := decrypt_packet(
			&conn.secret,
			conn.recv_buf[conn.handled:conn.red],
		)

		switch err {
		case .Auth:
			log.warn("packet is not authenticated, dropping connection")
			return
		case .Incomplete:
			if len(conn.recv_buf) == conn.red {
				if conn.handled == 0 {
					log.warn(
						"packet does not fit in the buffer,",
						"dropping connection",
					)
					return
				}
				copy(conn.recv_buf, conn.recv_buf[conn.handled:])
				conn.red -= conn.handled
				conn.handled = 0
			}
			break b
		case .Ok:
			conn.handling_packet = true
			res := conn.host.on_packet(conn, op.l, packet_bytes)
			conn.handling_packet = false
			if !res do return
			conn.handled += len(packet_bytes) + size_of(Crypt_Header)
			assert(conn.handled <= conn.red)
		}
	}

	kill = false
	conn.reader = nbio.recv_poly(
		conn.sock,
		{conn.recv_buf[conn.red:]},
		conn,
		tcp_connection_recv,
		timeout = conn.timeout,
		l = op.l,
	)
}

tcp_connection_send_client :: proc(
	conn: ^TCP_Connection,
	packet: Client_Packet,
	l: ^nbio.Event_Loop,
) -> bool {
	packet := packet
	return tcp_connection_send(conn, {&packet, client_packet_encode_dyn}, l)
}

tcp_connection_send_server :: proc(
	conn: ^TCP_Connection,
	packet: Server_Packet,
	l: ^nbio.Event_Loop,
) -> bool {
	packet := packet
	return tcp_connection_send(conn, {&packet, server_packet_encode_dyn}, l)
}

tcp_connection_send_arbitrary :: proc(
	conn: ^TCP_Connection,
	packet: []u8,
	l: ^nbio.Event_Loop,
) -> bool {
	packet := packet
	return tcp_connection_send(conn, {&packet, arbitrary_packet_encode_dyn}, l)
}

tcp_connection_send :: proc(
	conn: ^TCP_Connection,
	packet: Any_Packet,
	l: ^nbio.Event_Loop,
) -> bool {
	if LATENCY != 0 {
		e: Encoder

		ok := packet.encode(packet.data, &e)
		assert(ok)

		assert(context.allocator != context.temp_allocator)

		buf := make([]u8, encoded_len(&e))

		e = {buf}
		ok = packet.encode(packet.data, &e)
		assert(ok)

		nbio.timeout_poly2(
			LATENCY * time.Millisecond,
			conn,
			buf,
			proc(op: ^nbio.Operation, conn: ^TCP_Connection, buf: []u8) {
				buf := buf
				tcp_connection_send_no_delay(conn, {&buf, encode_dyn}, op.l)
				delete(buf)

				encode_dyn :: proc(data: rawptr, e: ^Encoder) -> bool {
					return encode_slice(e, (^[]u8)(data)^)
				}
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
	packet: Any_Packet,
	l: ^nbio.Event_Loop,
) -> bool {
	(conn.buffered + size_of(Crypt_Header) <= len(conn.send_buf)) or_return

	available_buffer := conn.send_buf[conn.buffered + size_of(Crypt_Header):]

	e := Encoder{available_buffer}
	packet.encode(packet.data, &e) or_return
	bytes := available_buffer[:len(available_buffer) - len(e.remining)]

	assert(len(bytes) > 0)

	header := (^Crypt_Header)(raw_data(conn.send_buf[conn.buffered:]))
	header.len = u16(len(bytes))
	encrypt(&conn.secret, &header.tag, bytes)

	conn.buffered += size_of(Crypt_Header) + len(bytes)

	tcp_connection_ensure_sending(conn, l)

	return true
}

tcp_connection_boot :: proc(
	conn: ^TCP_Connection,
	recv_buf_size: int,
	send_buf_size: int,
	l: ^nbio.Event_Loop = nil,
	loc := #caller_location,
) {
	recv_buf_size := max(recv_buf_size, 1) // empty buffer would immediatelly panic
	conn.recv_buf = make([]u8, recv_buf_size, loc = loc)
	conn.send_buf = make([]u8, send_buf_size, loc = loc)
	conn.reader = nbio.recv_poly(
		conn.sock,
		{conn.recv_buf},
		conn,
		tcp_connection_recv,
		timeout = conn.timeout,
		l = l,
	)
}

tcp_connection_kill :: proc(conn: ^TCP_Connection, l: ^nbio.Event_Loop = nil) {
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

rewire_interval :: proc(op: ^nbio.Operation, cb: $T) {
	op.user_data[2] = rawptr(cb)
}

interval_poly :: proc(
	period: time.Duration,
	v: $T,
	cb: proc(_: T),
	op_slot: ^^nbio.Operation = nil,
	l: ^nbio.Event_Loop = nil,
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

rewire_op :: proc(op: ^nbio.Operation, cb: $T) {
	op.user_data[0] = rawptr(cb)
}
