package pure_client

import "../../sim"
import "../../util/nm"

import "core:mem"
import "core:reflect"
import "core:slice"
import "core:testing"
import "core:time"

Chat_Msg_Meta :: struct {
	name: nm.Name,
	seed: sim.Identity,
	time: time.Time,
}

Chat_Msg_Header :: struct {
	using meta: Chat_Msg_Meta,
	len:        u16,
}

Chat_Ring :: struct {
	buf:  []u8,
	head: int,
	tail: int,
}

chat_ring_init :: proc(r: ^Chat_Ring, buf: []u8) {
	assert(mem.is_power_of_two(uintptr(len(buf))))
	r.buf = buf
	chat_ring_clear(r)
}

chat_ring_clear :: proc(r: ^Chat_Ring) {
	r.head = 0
	r.tail = 0
}

chat_ring_wrap_int :: proc(r: ^Chat_Ring, value: int) -> int {
	return value & (len(r.buf) - 1)
}

chat_ring_push :: proc(r: ^Chat_Ring, msg: Chat_Msg) -> bool {
	wtail := chat_ring_wrap_int(r, r.tail)

	need := size_of(Chat_Msg_Header) + len(msg.content)
	if need > len(r.buf) do return false

	if wtail + need > len(r.buf) {
		slice.zero(r.buf[wtail:])
		r.tail += len(r.buf) - wtail
		r.head = max(r.head, r.tail)
		wtail = 0
	}

	it := chat_ring_iter(r)
	for len(r.buf) - (r.tail - it.cursor) < need {
		_, ok := chat_ring_iter_next(&it)
		assert(ok)
	}
	r.head = it.cursor

	hdr := Chat_Msg_Header {
		meta = msg,
		len  = u16(len(msg.content)),
	}
	copy(r.buf[wtail:], reflect.as_bytes(hdr))
	copy(r.buf[wtail + size_of(Chat_Msg_Header):], msg.content)
	r.tail += need

	return true
}

Chat_Ring_Iter :: struct {
	r:      ^Chat_Ring,
	cursor: int,
}

chat_ring_iter :: proc(r: ^Chat_Ring) -> Chat_Ring_Iter {
	return {r, r.head}
}

chat_ring_iter_next :: proc(it: ^Chat_Ring_Iter) -> (msg: Chat_Msg, ok: bool) {
	whead := chat_ring_wrap_int(it.r, it.cursor)

	if it.cursor == it.r.tail do return

	if it.r.buf[whead] == 0 {
		it.cursor += len(it.r.buf) - whead
		whead = 0
		if it.cursor == it.r.tail do return
	}

	hdr: Chat_Msg_Header
	copy(reflect.as_bytes(hdr), it.r.buf[whead:])

	msg.meta = hdr.meta
	msg.content = string(it.r.buf[whead + size_of(Chat_Msg_Header):][:hdr.len])

	it.cursor += size_of(hdr) + int(hdr.len)

	ok = true
	return
}

Chat_Msg :: struct {
	using meta: Chat_Msg_Meta,
	content:    string,
}

collect :: proc(
	r: ^Chat_Ring,
	allocator := context.temp_allocator,
) -> []Chat_Msg {
	messages := make([dynamic]Chat_Msg, allocator)
	it := chat_ring_iter(r)
	for m in chat_ring_iter_next(&it) do append(&messages, m)
	return messages[:]
}

@(test)
test_chat_ring :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator

	HDR :: size_of(Chat_Msg_Header)

	{
		buf := make([]u8, 1024)
		r: Chat_Ring
		chat_ring_init(&r, buf)

		testing.expect(t, push_str(&r, "alice", "hello"))
		testing.expect(t, push_str(&r, "bob", "world"))
		testing.expect(t, push_str(&r, "carol", ""))

		msgs := collect(&r)
		testing.expect_value(t, len(msgs), 3)
		testing.expect_value(t, nm.str(&msgs[0].name), "alice")
		testing.expect_value(t, msgs[0].content, "hello")
		testing.expect_value(t, nm.str(&msgs[1].name), "bob")
		testing.expect_value(t, msgs[1].content, "world")
		testing.expect_value(t, nm.str(&msgs[2].name), "carol")
		testing.expect_value(t, msgs[2].content, "")
	}

	{
		buf := make([]u8, 256)
		r: Chat_Ring
		chat_ring_init(&r, buf)

		sizes := [?]int{3, 7, 1, 12, 5, 20, 4, 9, 31, 2, 17, 6, 8, 11, 14}
		for i in 0 ..< 500 {
			sz := sizes[i % len(sizes)]
			payload := make([]u8, sz)
			for j in 0 ..< sz do payload[j] = u8('A' + (i % 26))
			name, _ := nm.from_str("n")
			testing.expect(
				t,
				chat_ring_push(&r, {name = name, content = string(payload)}),
			)

			total: int
			it := chat_ring_iter(&r)
			for {
				m, ok := chat_ring_iter_next(&it)
				if !ok do break
				total += 1
				testing.expect(
					t,
					len(m.content) <= 64,
					"payload length looks corrupt",
				)
			}
		}
	}

	// message larger than buffer is rejected
	{
		buf := make([]u8, 64)
		r: Chat_Ring
		chat_ring_init(&r, buf)

		big := make([]u8, 64)
		testing.expect(t, !push_str(&r, "x", string(big)))
		testing.expect_value(t, len(collect(&r)), 0)
	}

	// iteration on empty ring yields nothing
	{
		buf := make([]u8, 64)
		r: Chat_Ring
		chat_ring_init(&r, buf)

		it := chat_ring_iter(&r)
		_, ok := chat_ring_iter_next(&it)
		testing.expect(t, !ok)
		testing.expect_value(t, len(collect(&r)), 0)
	}

	// clear empties a populated ring
	{
		buf := make([]u8, 128)
		r: Chat_Ring
		chat_ring_init(&r, buf)

		testing.expect(t, push_str(&r, "a", "hi"))
		testing.expect(t, push_str(&r, "b", "yo"))
		chat_ring_clear(&r)
		testing.expect_value(t, len(collect(&r)), 0)
		testing.expect(t, push_str(&r, "c", "after"))
		msgs := collect(&r)
		testing.expect_value(t, len(msgs), 1)
		testing.expect_value(t, msgs[0].content, "after")
	}

	// eviction preserves the most recent messages in order
	{
		buf := make([]u8, 128)
		r: Chat_Ring
		chat_ring_init(&r, buf)

		// tag each message with a single byte = i; survivors must be a
		// strictly increasing suffix of [0..50).
		for i in 0 ..< 50 {
			payload := []u8{u8(i)}
			testing.expect(t, push_str(&r, "n", string(payload)))
		}

		msgs := collect(&r)
		testing.expect(t, len(msgs) > 0)
		last_seen := -1
		for m in msgs {
			testing.expect_value(t, len(m.content), 1)
			n := int(m.content[0])
			testing.expect(t, n > last_seen, "messages out of order")
			last_seen = n
		}
		testing.expect_value(t, last_seen, 49)
	}

	// wrap-around: second push triggers the zero-pad branch and evicts the first
	{
		buf := make([]u8, 64)
		r: Chat_Ring
		chat_ring_init(&r, buf)

		payload := "0123456789"
		testing.expect(t, push_str(&r, "a", payload))
		testing.expect(t, push_str(&r, "b", payload))
		msgs := collect(&r)
		testing.expect_value(t, len(msgs), 1)
		testing.expect_value(t, nm.str(&msgs[0].name), "b")
		testing.expect_value(t, msgs[0].content, payload)
	}

	push_str :: proc(r: ^Chat_Ring, sender_str: string, msg: string) -> bool {
		return chat_ring_push(
			r,
			{name = nm.from_str(sender_str), content = msg},
		)
	}
}
