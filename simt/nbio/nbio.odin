package simt_nbio

import ".."
import "core:nbio"
import "core:net"
import "core:time"

SIMULATE :: simt.SIMULATE

when SIMULATE {
	Event_Loop :: struct {}
} else {
	Event_Loop :: nbio.Event_Loop
}

when SIMULATE {
	TCP_Socket :: distinct i64
} else {
	TCP_Socket :: nbio.TCP_Socket
}

when SIMULATE {
	UDP_Socket :: distinct i64
} else {
	UDP_Socket :: nbio.UDP_Socket
}

when SIMULATE {
	Any_Socket :: union {
		TCP_Socket,
		UDP_Socket,
	}
} else {
	Any_Socket :: nbio.Any_Socket
}

when SIMULATE {
	Handle :: distinct i64
} else {
	Handle :: nbio.Handle
}

when SIMULATE {
	Closable :: union {
		TCP_Socket,
		UDP_Socket,
		Handle,
	}
} else {
	Closable :: nbio.Closable
}

when SIMULATE {
	CWD :: Handle(0)
} else {
	CWD :: nbio.CWD
}

IP4_Address :: net.IP4_Address
IP6_Address :: net.IP6_Address
Address :: net.Address
Endpoint :: net.Endpoint

IP4_Any :: net.IP4_Any
IP4_Loopback :: net.IP4_Loopback

General_Error :: nbio.General_Error
FS_Error :: nbio.FS_Error
Network_Error :: nbio.Network_Error
Bind_Error :: net.Bind_Error
Accept_Error :: nbio.Accept_Error
Send_Error :: nbio.Send_Error
Recv_Error :: nbio.Recv_Error
Create_Socket_Error :: nbio.Create_Socket_Error
Address_Family :: nbio.Address_Family

File_Flags :: nbio.File_Flags
Permissions :: nbio.Permissions
Permissions_Default_File :: nbio.Permissions_Default_File

NO_TIMEOUT :: nbio.NO_TIMEOUT

when SIMULATE {
	Operation :: struct {
		l:         ^Event_Loop,
		user_data: [nbio.MAX_USER_ARGUMENTS + 1]rawptr,
		kind:      enum {
			accept,
			dial,
			open,
			read,
			recv,
			send,
			stat,
			timeout,
			write,
		},
		accept:    struct {
			socket:          TCP_Socket,
			client:          TCP_Socket,
			client_endpoint: Endpoint,
			err:             Accept_Error,
		},
		dial:      struct {
			endpoint: Endpoint,
			socket:   TCP_Socket,
			err:      Network_Error,
		},
		open:      struct {
			path:   string,
			handle: Handle,
			err:    FS_Error,
		},
		read:      struct {
			read: int,
			err:  FS_Error,
		},
		recv:      struct {
			source:   Endpoint,
			received: int,
			err:      Recv_Error,
		},
		send:      struct {
			sent: int,
			err:  Send_Error,
		},
		stat:      struct {
			size: i64,
			err:  FS_Error,
		},
		timeout:   struct {
			duration: time.Duration,
		},
		write:     struct {
			buf: []u8,
			err: FS_Error,
		},
	}
} else {
	Operation :: nbio.Operation
}

acquire_thread_event_loop :: proc() -> General_Error {
	when !SIMULATE {
		return nbio.acquire_thread_event_loop()
	}
	panic("TODO: acquire_thread_event_loop")
}

release_thread_event_loop :: proc() {
	when !SIMULATE {
		nbio.release_thread_event_loop()
		return
	}
	panic("TODO: release_thread_event_loop")
}

current_thread_event_loop :: proc(loc := #caller_location) -> ^Event_Loop {
	when !SIMULATE {
		return nbio.current_thread_event_loop(loc)
	}
	panic("TODO: current_thread_event_loop")
}

tick :: proc(timeout: time.Duration = NO_TIMEOUT) -> General_Error {
	when !SIMULATE {
		return nbio.tick(timeout)
	}
	panic("TODO: tick")
}

run :: proc() -> General_Error {
	when !SIMULATE {
		return nbio.run()
	}
	panic("TODO: run")
}

remove :: proc(target: ^Operation) {
	when !SIMULATE {
		nbio.remove(target)
		return
	}
	panic("TODO: remove")
}

create_udp_socket :: proc(
	family: Address_Family,
	l: ^Event_Loop,
	loc := #caller_location,
) -> (
	UDP_Socket,
	Create_Socket_Error,
) {
	when !SIMULATE {
		return nbio.create_udp_socket(family, l, loc)
	}
	panic("TODO: create_udp_socket")
}

listen_tcp :: proc(
	endpoint: Endpoint,
	backlog := 1000,
	l: ^Event_Loop,
	loc := #caller_location,
) -> (
	socket: TCP_Socket,
	err: Network_Error,
) {
	when !SIMULATE {
		return nbio.listen_tcp(endpoint, backlog, l, loc)
	}
	panic("TODO: listen_tcp")
}

bind :: proc(socket: Any_Socket, ep: Endpoint) -> Bind_Error {
	when !SIMULATE {
		return nbio.bind(socket, ep)
	}
	panic("TODO: bind")
}

parse_endpoint :: proc(endpoint_str: string) -> (ep: Endpoint, ok: bool) {
	when !SIMULATE {
		return nbio.parse_endpoint(endpoint_str)
	}
	panic("TODO: parse_endpoint")
}

close :: proc(subject: Closable, l: ^Event_Loop) -> ^Operation {
	when !SIMULATE {
		return nbio.close(subject, l = l)
	}
	panic("TODO: close")
}

accept_poly :: #force_inline proc(
	socket: TCP_Socket,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	timeout: time.Duration = NO_TIMEOUT,
	l: ^Event_Loop,
) -> ^Operation {
	when !SIMULATE {
		return nbio.accept_poly(socket, p, cb, timeout, l)
	}
	panic("TODO: accept_poly")
}

dial_poly :: #force_inline proc(
	endpoint: Endpoint,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	timeout: time.Duration = NO_TIMEOUT,
	l: ^Event_Loop,
) -> ^Operation {
	when !SIMULATE {
		return nbio.dial_poly(endpoint, p, cb, timeout, l)
	}
	panic("TODO: dial_poly")
}

recv_poly :: #force_inline proc(
	socket: Any_Socket,
	bufs: [][]byte,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	all := false,
	timeout: time.Duration = NO_TIMEOUT,
	l: ^Event_Loop,
) -> ^Operation {
	when !SIMULATE {
		return nbio.recv_poly(socket, bufs, p, cb, all, timeout, l)
	}
	panic("TODO: recv_poly")
}

recv_poly2 :: #force_inline proc(
	socket: Any_Socket,
	bufs: [][]byte,
	p: $T,
	p2: $T2,
	cb: $C/proc(op: ^Operation, p: T, p2: T2),
	all := false,
	timeout: time.Duration = NO_TIMEOUT,
	l: ^Event_Loop,
) -> ^Operation {
	when !SIMULATE {
		return nbio.recv_poly2(socket, bufs, p, p2, cb, all, timeout, l)
	}
	panic("TODO: recv_poly2")
}

send_poly :: #force_inline proc(
	socket: Any_Socket,
	bufs: [][]byte,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	endpoint: Endpoint = {},
	all := true,
	timeout: time.Duration = NO_TIMEOUT,
	l: ^Event_Loop,
) -> ^Operation {
	when !SIMULATE {
		return nbio.send_poly(socket, bufs, p, cb, endpoint, all, timeout, l)
	}
	panic("TODO: send_poly")
}

read_poly :: #force_inline proc(
	handle: Handle,
	offset: int,
	buf: []byte,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	all := false,
	timeout: time.Duration = NO_TIMEOUT,
	l: ^Event_Loop,
) -> ^Operation {
	when !SIMULATE {
		return nbio.read_poly(handle, offset, buf, p, cb, all, timeout, l)
	}
	panic("TODO: read_poly")
}

write_poly :: #force_inline proc(
	handle: Handle,
	offset: int,
	buf: []byte,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	all := true,
	timeout: time.Duration = NO_TIMEOUT,
	l: ^Event_Loop,
) -> ^Operation {
	when !SIMULATE {
		return nbio.write_poly(handle, offset, buf, p, cb, all, timeout, l)
	}
	panic("TODO: write_poly")
}

open_poly :: #force_inline proc(
	path: string,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	mode: File_Flags = {.Read},
	perm: Permissions = Permissions_Default_File,
	dir: Handle = CWD,
	l: ^Event_Loop,
) -> ^Operation {
	when !SIMULATE {
		return nbio.open_poly(path, p, cb, mode, perm, dir, l)
	}
	panic("TODO: open_poly")
}

stat_poly :: #force_inline proc(
	handle: Handle,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	l: ^Event_Loop,
) -> ^Operation {
	when !SIMULATE {
		return nbio.stat_poly(handle, p, cb, l)
	}

	panic("TODO: stat_poly")
}

when SIMULATE {
	_prep_timeout :: proc(
		dur: time.Duration,
		cb: proc(_: ^Operation),
		l: ^Event_Loop,
	) -> ^Operation {
		panic("TODO: timeout")
	}
}

timeout_poly :: #force_inline proc(
	dur: time.Duration,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	l: ^Event_Loop,
) -> ^Operation {
	when !SIMULATE {
		return nbio.timeout_poly(dur, p, cb, l)
	}

	defer _put_user_data(op, cb, p)
	return _prep_timeout(dur, _poly_cb(C, T), l)
}

timeout_poly2 :: #force_inline proc(
	dur: time.Duration,
	p: $T,
	p2: $T2,
	cb: $C/proc(op: ^Operation, p: T, p2: T2),
	l: ^Event_Loop,
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.timeout_poly2(dur, p, p2, cb, l)
	}

	defer _put_user_data2(op, cb, p, p2)
	return _prep_timeout(dur, _poly_cb2(C, T, T2), l)
}

timeout_poly3 :: #force_inline proc(
	dur: time.Duration,
	p: $T,
	p2: $T2,
	p3: $T3,
	cb: $C/proc(op: ^Operation, p: T, p2: T2, p3: T3),
	l: ^Event_Loop,
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.timeout_poly3(dur, p, p2, p3, cb, l)
	}

	defer _put_user_data3(op, cb, p, p2, p3)
	return _prep_timeout(dur, _poly_cb3(C, T, T2, T3), l)
}

_poly_cb :: #force_inline proc($C: typeid, $T: typeid) -> proc(_: ^Operation) {
	return auto_cast nbio._poly_cb(C, T)
}

_poly_cb2 :: #force_inline proc(
	$C: typeid,
	$T: typeid,
	$T2: typeid,
) -> proc(_: ^Operation) {
	return auto_cast nbio._poly_cb2(C, T, T2)
}

_poly_cb3 :: #force_inline proc(
	$C: typeid,
	$T: typeid,
	$T2: typeid,
	$T3: typeid,
) -> proc(_: ^Operation) {
	return auto_cast nbio._poly_cb3(C, T, T2, T3)
}

_put_user_data :: #force_inline proc(op: ^Operation, cb: $C, p: $T) {
	nbio._put_user_data(auto_cast op, cb, p)
	ptr := uintptr(&op.user_data)
	intrinsics.unaligned_store((^C)(rawptr(ptr)), cb)
	intrinsics.unaligned_store((^T)(rawptr(ptr + size_of(cb))), p)
}

_put_user_data2 :: #force_inline proc(op: ^Operation, cb: $C, p: $T, p2: $T2) {
	ptr := uintptr(&op.user_data)
	intrinsics.unaligned_store((^C)(rawptr(ptr)), cb)
	intrinsics.unaligned_store((^T)(rawptr(ptr + size_of(cb))), p)
	intrinsics.unaligned_store(
		(^T2)(rawptr(ptr + size_of(cb) + size_of(p))),
		p2,
	)
}

_put_user_data3 :: #force_inline proc(
	op: ^Operation,
	cb: $C,
	p: $T,
	p2: $T2,
	p3: $T3,
) {
	ptr := uintptr(&op.user_data)
	intrinsics.unaligned_store((^C)(rawptr(ptr)), cb)
	intrinsics.unaligned_store((^T)(rawptr(ptr + size_of(cb))), p)
	intrinsics.unaligned_store(
		(^T2)(rawptr(ptr + size_of(cb) + size_of(p))),
		p2,
	)
	intrinsics.unaligned_store(
		(^T3)(rawptr(ptr + size_of(cb) + size_of(p) + size_of(p2))),
		p3,
	)
}
