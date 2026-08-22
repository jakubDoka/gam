package simt_nbio

import ".."
import "core:container/xar"
import "core:crypto"
import "core:log"

import "../../util/arna"
import "../../util/bit_arr"
import "base:intrinsics"
import "base:runtime"
import "core:container/priority_queue"
import "core:fmt"
import "core:io"
import "core:math/rand"
import "core:nbio"
import "core:net"
import "core:os"
import "core:slice"
import "core:strings"
import "core:time"

SIMULATE :: simt.SIMULATE

Machine_Config :: struct {
	ip: Address,
}

when SIMULATE {
	Event_Loop :: struct {
		using config: Machine_Config,
		port_alloc:   int,
		files:        map[string]^File,
		using shared: ^Shared,
	}

	shareholder: ^Shared

	Shared :: struct {
		rc:             int,
		listeners:      map[Endpoint]^Listener,
		bindings:       map[Endpoint]UDP_Socket,
		free_ops:       ^Operation,
		free_listeners: ^Listener,
		allocator_arna: arna.Allocator,
		allocator:      runtime.Allocator,
		tasks:          priority_queue.Priority_Queue(Task),
		time:           time.Duration,
		fds:            xar.Array(File_Descriptor, 5),
		free_fds:       ^File_Descriptor,
	}

	Listener :: struct {
		queued:    TCP_Socket,
		accept_op: ^Operation,
		next_free: ^Listener,
		l:         ^Event_Loop,
	}

	File :: struct {
		perm:    Permissions,
		content: [dynamic]u8,
	}

	File_Descriptor_Kind :: enum int {
		Invalid,
		UDP_Socket,
		TCP_Socket,
		File,
	}

	File_Descriptor :: struct {
		idx:            i64,
		label:          string,
		next_free_fd:   ^File_Descriptor,
		kind:           File_Descriptor_Kind,
		mode:           File_Flags,
		using file:     ^File,
		using listener: ^Listener,
		next:           TCP_Socket,
		recv_ops:       bit_arr.DL_List,
		send_ops:       bit_arr.DL_List,
		peer:           TCP_Socket,
		endpoint:       Endpoint,
	}

	Task_Kind :: enum {
		Execute,
		Cancel,
	}

	Task :: struct {
		fire_at: time.Duration,
		gen:     int,
		op:      ^Operation,
		kind:    Task_Kind,
	}
} else {
	Event_Loop :: nbio.Event_Loop

	Shared :: struct {}
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
Read_Entire_File_Callback :: nbio.Read_Entire_File_Callback
Read_Entire_File_Error :: nbio.Read_Entire_File_Error

File_Flags :: nbio.File_Flags
Permissions :: nbio.Permissions
File_Type :: nbio.File_Type
Permissions_Default_File :: nbio.Permissions_Default_File

NO_TIMEOUT :: nbio.NO_TIMEOUT

// NOTE: just so we dont have refs to `os` crate in the usage code
join_path :: os.join_path
join_filename :: os.join_filename
base :: os.base
dir :: os.dir

Error :: os.Error
when SIMULATE {
	File_Info :: struct {
		name:     string,
		fullpath: string,
		type:     File_Type,
	}
} else {
	File_Info :: os.File_Info
}
when !SIMULATE {
	File :: os.File
}
Walker :: os.Walker

set_lable :: proc(l: ^Event_Loop, fd: Closable, value: string) {
	when SIMULATE {
		fd := _access_fd(l, fd) or_else panic("")
		fd.label = value
	}
}

rand_bytes :: proc(fill: []u8) {
	when !SIMULATE {
		crypto.rand_bytes(fill)
	} else {
		ok := runtime.random_generator_read_bytes(
			context.random_generator,
			fill,
		)
		assert(ok)
	}
}

now :: proc(l: ^Event_Loop) -> time.Time {
	when !SIMULATE {
		return time.now()
	} else {
		return {i64(l.time)}
	}
}

since :: proc(l: ^Event_Loop, a: time.Time) -> time.Duration {
	when !SIMULATE {
		return time.since(a)
	} else {
		return l.time - time.Duration(a._nsec)
	}
}

open :: proc(
	l: ^Event_Loop,
	name: string,
	mode := os.File_Flags{.Read},
	perm := os.Permissions_Default,
) -> (
	^File,
	Error,
) {
	when !SIMULATE {
		return os.open(name, mode, perm)
	} else {
		file := _open_file(
			l,
			name,
			transmute(nbio.File_Flags)mode,
			transmute(nbio.Permissions)perm,
		)
		if file == nil do return nil, .Not_Exist
		return file, nil
	}
}

to_stream :: proc(f: ^File) -> io.Stream {
	when !SIMULATE {
		return os.to_stream(f)
	} else {
		return strings.to_stream((^strings.Builder)(&f.content))
	}
}

write_entire_file :: proc(
	l: ^Event_Loop,
	name: string,
	data: []byte,
	perm := os.Permissions_Read_All + {.Write_User},
	truncate := true,
) -> Error {
	when !SIMULATE {
		return os.write_entire_file(name, data, perm, truncate)
	} else {
		assert(truncate)
		file := _open_file(
			l,
			name,
			{.Create, .Trunc},
			transmute(nbio.Permissions)perm,
		)
		append(&file.content, ..data)
		return nil
	}
}

read_entire_file_sync :: proc(
	l: ^Event_Loop,
	name: string,
	allocator := context.allocator,
	loc := #caller_location,
) -> (
	[]byte,
	Error,
) {
	when !SIMULATE {
		return os.read_entire_file(name, allocator, loc)
	} else {
		file := _open_file(l, name, {.Read}, {})
		if file == nil do return {}, .Not_Exist
		return slice.clone(file.content[:], allocator)
	}
}

read_all_directory_by_path :: proc(
	l: ^Event_Loop,
	path: string,
	allocator := context.allocator,
) -> (
	[]File_Info,
	Error,
) {
	when !SIMULATE {
		return os.read_all_directory_by_path(path, allocator)
	} else {
		count := 0
		for fpath in l.files {
			if dir(fpath) == path do count += 1
		}

		buf := make([]File_Info, count, allocator)
		i := 0
		for fpath in l.files {
			if dir(fpath) == path {
				buf[i] = {
					fullpath = fpath,
					name     = base(fpath),
					type     = .Regular,
				}
				i += 1
			}
		}

		return buf, nil
	}
}

stat :: proc(
	l: ^Event_Loop,
	path: string,
	allocator := context.allocator,
) -> (
	File_Info,
	Error,
) {
	when !SIMULATE {
		return os.stat(path, allocator)
	} else {
		if path in l.files {
			return {fullpath = path, name = base(path), type = .Regular}, nil
		}
		return {}, .Not_Exist
	}
}

make_directory_all :: proc(path: string) -> Error {
	when !SIMULATE {
		return os.make_directory_all(path)
	} else {
		// NOTE: we dont have a concept of directories
		return nil
	}
}

when SIMULATE {
	Operation_Type :: enum {
		None,
		accept,
		dial,
		open,
		read,
		recv,
		send,
		stat,
		timeout,
		write,
		close,
	}

	Operation :: struct {
		l:            ^Event_Loop,
		next_free:    ^Operation,
		rs_queue:     bit_arr.DL_Node,
		gen:          int,
		cb:           proc(_: ^Operation),
		user_data:    [nbio.MAX_USER_ARGUMENTS + 1]rawptr,
		type:         Operation_Type,
		using config: struct #raw_union {
			accept:  struct {
				socket:          TCP_Socket,
				client:          TCP_Socket,
				client_endpoint: Endpoint,
				err:             Accept_Error,
			},
			dial:    struct {
				endpoint: Endpoint,
				socket:   TCP_Socket,
				err:      Network_Error,
			},
			open:    struct {
				path:   string,
				handle: Handle,
				mode:   File_Flags,
				perm:   Permissions,
				dir:    Handle,
				err:    FS_Error,
			},
			read:    struct {
				handle: Handle,
				offset: int,
				all:    bool,
				buf:    []u8,
				read:   int,
				err:    FS_Error,
			},
			write:   struct {
				handle:  Handle,
				offset:  int,
				all:     bool,
				buf:     []u8,
				written: int,
				err:     FS_Error,
			},
			recv:    struct {
				socket:        Any_Socket,
				source:        Endpoint,
				all:           bool,
				received:      int,
				err:           Recv_Error,
				_backing_bufs: [1][]u8,
			},
			send:    struct {
				socket:        Any_Socket,
				endpoint:      Endpoint,
				all:           bool,
				sent:          int,
				err:           Send_Error,
				_backing_bufs: [1][]u8,
			},
			stat:    struct {
				handle: Handle,
				type:   File_Type,
				size:   i64,
				err:    FS_Error,
			},
			timeout: struct {
				duration: time.Duration,
			},
			close:   struct {
				subject: Closable,
				err:     FS_Error,
			},
		},
	}
} else {
	Operation :: nbio.Operation
}

create_event_loop :: proc(
	config: Machine_Config = {},
) -> (
	^Event_Loop,
	General_Error,
) {
	when !SIMULATE {
		err := nbio.acquire_thread_event_loop()
		return nbio.current_thread_event_loop(), err
	} else {
		if shareholder == nil {
			arena: arna.Allocator
			err := arna.init(&arena, 1024 * 1024 * 16)
			assert(err == nil)

			l := new(Shared, arna.allocator(&arena))
			l.allocator_arna = arena
			l.allocator = arna.allocator(&l.allocator_arna)

			priority_queue.init(
				&l.tasks,
				less,
				priority_queue.default_swap_proc(Task),
				allocator = l.allocator,
			)
			less :: proc(a, b: Task) -> bool {
				return a.fire_at < b.fire_at
			}

			l.fds.allocator = l.allocator
			l.listeners.allocator = l.allocator
			l.bindings.allocator = l.allocator

			xar.append(&l.fds, File_Descriptor{})

			shareholder = l
		}

		shareholder.rc += 1

		l := new(Event_Loop, shareholder.allocator)
		l.shared = shareholder
		l.files.allocator = shareholder.allocator
		l.config = config

		return l, nil
	}
}

destroy_event_loop :: proc(l: ^Event_Loop) {
	when !SIMULATE {
		nbio.release_thread_event_loop()
	} else {
		assert(priority_queue.len(l.tasks) == 0)

		l.rc -= 1
		if l.rc == 0 {
			cnt := 0
			for ; l.free_fds != nil; cnt += 1 {
				l.free_fds = l.free_fds.next_free_fd
			}

			for it := xar.iterator(&l.fds); fd in xar.iterate_by_ptr(&it) {
				if fd.kind != .Invalid {
					log.errorf("%#v", fd)
				}
			}

			arna.destroy(&l.allocator_arna)

			shareholder = nil
		}
	}
}

tick :: proc(
	l: ^Event_Loop,
	timeout: time.Duration = NO_TIMEOUT,
) -> General_Error {
	when !SIMULATE {
		assert(l == nbio.current_thread_event_loop())
		return nbio.tick(timeout)
	} else {
		// NOTE: we always eat at most 1 event, this makes sense because we
		// skip trough time so at any point we never have more events to do
		// of course timeout of 0 will mostly be a noop

		wait_time := time.Duration(1 << 32) if timeout < 0 else timeout
		until := l.time + wait_time
		for {
			v, ok := priority_queue.peek_safe(l.tasks)
			if !ok do return nil

			if v.fire_at > until do break

			priority_queue.pop(&l.tasks)

			if v.op == nil || v.op.gen != v.gen {
				continue
			}

			switch v.kind {
			case .Execute:
				_execute_op(v.op)
			case .Cancel:
				_timeout_op(v.op)
			}

			l.time = v.fire_at
			return nil
		}

		l.time = until
		return nil
	}
}

run :: proc(l: ^Event_Loop) -> General_Error {
	when !SIMULATE {
		assert(l == nbio.current_thread_event_loop())
		return nbio.run()
	} else {
		for priority_queue.len(l.tasks) > 0 {
			if res := tick(l); res != nil {
				return res
			}
		}

		return nil
	}
}

remove :: proc(target: ^Operation) {
	when !SIMULATE {
		nbio.remove(target)
	} else {
		_remove_op(target)
	}
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
	} else {
		fd, idx := _new_fd(l, .UDP_Socket)
		return UDP_Socket(idx), nil
	}
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
	} else {
		if endpoint in l.listeners {
			return 0, net.Listen_Error.Address_In_Use
		}

		fd, idx := _new_fd(l, .TCP_Socket)

		fd.listener = l.free_listeners
		if fd.listener == nil {
			fd.listener = new(Listener)
		} else {
			l.free_listeners = fd.listener.next_free
			fd.listener^ = {}
		}

		fd.listener.l = l

		fd.endpoint = endpoint
		l.listeners[endpoint] = fd.listener

		return TCP_Socket(idx), nil
	}
}

bind :: proc(l: ^Event_Loop, socket: Any_Socket, ep: Endpoint) -> Bind_Error {
	when !SIMULATE {
		return nbio.bind(socket, ep)
	} else {

		ep := ep
		if ep.port == 0 {
			l.port_alloc += 1
			ep.port = l.port_alloc
		}
		ep.address = l.ip

		socket := socket.(UDP_Socket)

		fd, ok := _access_fd(l, socket)
		if !ok {
			return .Invalid_Argument
		}
		fd.endpoint = ep

		if ep in l.bindings {
			return .Address_In_Use
		}
		l.bindings[ep] = socket
		return nil
	}
}

close :: proc(subject: Closable, l: ^Event_Loop) -> (op: ^Operation) {
	when !SIMULATE {
		return nbio.close(subject, l = l)
	} else {
		op = _new_op(l, .close, proc(_: ^Operation) {}, NO_TIMEOUT)
		op.close.subject = subject
		_add_task(l, _rand_dur(l, 0, time.Millisecond * 5), op, .Execute)
		return
	}
}

when SIMULATE {
	_prep_accept :: proc(
		socket: TCP_Socket,
		timeout: time.Duration,
		cb: proc(_: ^Operation),
		l: ^Event_Loop,
	) -> (
		op: ^Operation,
	) {
		op = _new_op(l, .accept, cb, timeout)
		op.accept.socket = socket

		defer if op.accept.err != nil {
			_add_task(l, 0, op, .Execute)
		}

		fd_ref, ok := _access_fd(l, socket)
		if !ok {
			op.accept.err = .Invalid_Argument
			return
		}

		if fd_ref.listener == nil {
			op.accept.err = .Not_Listening
			return
		}

		if fd_ref.listener.accept_op != nil {
			op.accept.err = .Insufficient_Resources
			return
		}

		fd_ref.listener.accept_op = op
		_run_accept(l, fd_ref.listener)

		return
	}

	_prep_dial :: proc(
		endpoint: Endpoint,
		timeout: time.Duration,
		cb: proc(_: ^Operation),
		l: ^Event_Loop,
	) -> (
		op: ^Operation,
	) {
		op = _new_op(l, .dial, cb, timeout)
		op.dial.endpoint = endpoint
		_add_task(l, _rand_dur(l, 0, time.Millisecond * 50), op, .Execute)
		return
	}

	_prep_recv :: proc(
		socket: Any_Socket,
		bufs: [][]byte,
		all: bool,
		timeout: time.Duration,
		cb: proc(_: ^Operation),
		l: ^Event_Loop,
	) -> (
		op: ^Operation,
	) {
		op = _new_op(l, .recv, cb, timeout)
		assert(len(bufs) == 1)
		op.recv.socket = socket
		assert(len(bufs) == 1)
		assert(len(bufs[0]) != 0)
		op.recv._backing_bufs = bufs[0]
		op.recv.all = all

		_add_task(l, 0, op, .Execute)
		return
	}

	_prep_send :: proc(
		socket: Any_Socket,
		bufs: [][]byte,
		endpoint: Endpoint,
		all: bool,
		timeout: time.Duration,
		cb: proc(_: ^Operation),
		l: ^Event_Loop,
	) -> (
		op: ^Operation,
	) {
		op = _new_op(l, .send, cb, timeout)
		op.send.socket = socket
		op.send.endpoint = endpoint
		assert(len(bufs) == 1)
		assert(len(bufs[0]) != 0)
		op.send._backing_bufs = bufs[0]
		op.send.all = all

		dur := _rand_dur(l, time.Millisecond * 40, time.Millisecond * 60)
		_add_task(l, dur, op, .Execute)
		return
	}

	_prep_read :: proc(
		handle: Handle,
		offset: int,
		buf: []byte,
		all: bool,
		timeout: time.Duration,
		cb: proc(_: ^Operation),
		l: ^Event_Loop,
	) -> (
		op: ^Operation,
	) {
		op = _new_op(l, .read, cb, timeout)
		op.read.handle = handle
		op.read.offset = offset
		op.read.buf = buf
		op.read.all = all

		_add_task(l, _rand_dur(l, 0, time.Millisecond * 50), op, .Execute)
		return
	}

	_prep_write :: proc(
		handle: Handle,
		offset: int,
		buf: []byte,
		all: bool,
		timeout: time.Duration,
		cb: proc(_: ^Operation),
		l: ^Event_Loop,
	) -> (
		op: ^Operation,
	) {
		op = _new_op(l, .write, cb, timeout)
		op.write.handle = handle
		op.write.offset = offset
		op.write.buf = buf
		op.write.all = all

		_add_task(l, _rand_dur(l, 0, time.Millisecond * 50), op, .Execute)
		return
	}

	_prep_open :: proc(
		path: string,
		mode: File_Flags,
		perm: Permissions,
		dir: Handle,
		cb: proc(_: ^Operation),
		l: ^Event_Loop,
	) -> (
		op: ^Operation,
	) {
		op = _new_op(l, .open, cb)
		op.open.path = path
		op.open.mode = mode
		op.open.perm = perm
		op.open.dir = dir

		_add_task(l, _rand_dur(l, 0, time.Millisecond * 30), op, .Execute)
		return
	}

	_prep_stat :: proc(
		handle: Handle,
		cb: proc(_: ^Operation),
		l: ^Event_Loop,
	) -> (
		op: ^Operation,
	) {
		op = _new_op(l, .stat, cb)
		op.stat.handle = handle

		_add_task(l, _rand_dur(l, 0, time.Millisecond * 20), op, .Execute)
		return
	}

	_prep_timeout :: proc(
		dur: time.Duration,
		cb: proc(_: ^Operation),
		l: ^Event_Loop,
	) -> (
		op: ^Operation,
	) {
		op = _new_op(l, .timeout, cb)
		op.timeout.duration = dur
		_add_task(l, dur, op, .Execute)
		return
	}

	_run_accept :: proc(l: ^Event_Loop, listener: ^Listener) {
		for listener.accept_op != nil && listener.queued != 0 {
			fd := xar.get_ptr(&l.fds, listener.queued)
			listener.accept_op.accept.client = listener.queued
			listener.accept_op.accept.client_endpoint =
				xar.get_ptr(&l.fds, fd.peer).endpoint
			listener.queued = fd.next
			op := listener.accept_op
			listener.accept_op = nil
			_add_task(l, 0, op, .Execute)
		}
	}

	_execute_op :: proc(op: ^Operation) {
		l := op.l
		switch op.type {
		case .None:
			panic("unreachable")
		case .accept:
		case .dial:
			listener, ok := l.listeners[op.dial.endpoint]
			if !ok {
				op.dial.err = net.Dial_Error.Host_Unreachable
				break
			}

			local_fd, local_idx := _new_fd(l, .TCP_Socket)
			peer_fd, peer_idx := _new_fd(l, .TCP_Socket)
			listener.l.port_alloc += 1
			peer_fd.endpoint = {listener.l.ip, listener.l.port_alloc}
			l.port_alloc += 1
			local_fd.endpoint = {l.ip, l.port_alloc}

			local_fd.peer = TCP_Socket(peer_idx)
			peer_fd.peer = TCP_Socket(local_idx)

			op.dial.socket = TCP_Socket(local_idx)

			peer_fd.next = listener.queued
			listener.queued = TCP_Socket(peer_idx)

			_run_accept(l, listener)
		// NOTE: the structure of both of these is identical
		case .send, .recv:
			fd_ref, ok := _access_fd(l, op.send.socket)
			if !ok {
				op.recv.err = net.TCP_Recv_Error.Invalid_Argument
				break
			}

			is_udp := fd_ref.kind == .UDP_Socket

			peer: i64
			switch s in op.send.socket {
			case UDP_Socket:
				peera := l.bindings[op.send.endpoint]
				peer = i64(peera)
			case TCP_Socket:
				peer = i64(fd_ref.peer)
			}

			if peer == 0 && (op.type != .recv || !is_udp) {
				if op.type == .send || op.recv.all {
					op.send.err = .Connection_Closed
				}

				break
			}

			if op.type == .send {
				fd_ref = xar.get_ptr(&l.fds, peer)
				bit_arr.dl_push(&fd_ref.send_ops, &op.rs_queue)
			} else {
				bit_arr.dl_push(&fd_ref.recv_ops, &op.rs_queue)
			}

			for fd_ref.send_ops != {} && fd_ref.recv_ops != {} {
				send, recv: ^Operation =
					container_of(fd_ref.send_ops.last, Operation, "rs_queue"),
					container_of(fd_ref.recv_ops.last, Operation, "rs_queue")
				fsbuf, frbuf: []u8 =
					send.send._backing_bufs[0], recv.recv._backing_bufs[0]
				sbuf, rbuf: []u8 =
					fsbuf[send.send.sent:], frbuf[recv.recv.received:]

				source_end: Endpoint

				fd := _access_fd(l, send.send.socket) or_else panic("")

				source_end = fd.endpoint

				fmt.assertf(len(sbuf) != 0, "%v", send.send.sent)
				fmt.assertf(len(rbuf) != 0, "%v", recv.recv.received)

				to_copy := min(len(rbuf), len(sbuf))
				copy(rbuf[:to_copy], sbuf[:to_copy])

				if fd_ref.kind == .UDP_Socket {
					// NOTE: not true in general but relevant for our code
					assert(to_copy == len(sbuf))
				}

				send.send.sent += to_copy
				recv.recv.received += to_copy
				recv.recv.source = source_end

				if !send.send.all || send.send.sent == len(fsbuf) {
					_exec_cb(send)
				}

				if !recv.recv.all || recv.recv.received == len(fsbuf) {
					_exec_cb(recv)
				}
			}

			return
		case .open:
			file := _open_file(l, op.open.path, op.open.mode, op.open.perm)
			if file == nil {
				op.open.err = .Not_Found
				break
			}

			fd, id := _new_fd(l, .File)
			fd.mode = op.open.mode
			fd.file = file
			op.open.handle = Handle(id)
		case .close:
			fd_ref, ok := _access_fd(l, op.close.subject)
			if !ok {
				op.close.err = .Invalid_Argument
				break
			}

			if fd_ref.kind == .UDP_Socket {
				delete_key(&l.bindings, fd_ref.endpoint)
			}

			if fd_ref.listener != nil {
				delete_key(&l.listeners, fd_ref.endpoint)
				fd_ref.listener.next_free = l.free_listeners
				l.free_listeners = fd_ref.listener
			}

			if fd_ref.peer != 0 {
				assert(fd_ref.kind == .TCP_Socket)
				ofd := _access_fd(l, fd_ref.peer) or_else panic("")
				fmt.assertf(
					ofd.peer == TCP_Socket(fd_ref.idx),
					"%v %v",
					ofd.peer,
					fd_ref.idx,
				)
				ofd.peer = 0
				_remove_fd_ops(ofd)
			}

			_remove_fd_ops(fd_ref)

			fd_ref^ = {
				idx = fd_ref.idx,
			}
			fd_ref.next_free_fd = l.free_fds
			l.free_fds = fd_ref
		case .stat:
			fd_ref, ok := _access_fd(l, op.stat.handle)
			if !ok {
				op.stat.err = .Invalid_Argument
				break
			}

			op.stat.type = .Regular
			op.stat.size = i64(len(fd_ref.file.content))
		case .read:
			fd_ref, ok := _access_fd(l, op.read.handle)
			if !ok {
				op.read.err = .Invalid_Argument
				break
			}

			if op.read.offset < 0 {
				op.read.err = .Invalid_Argument
				break
			}

			op.read.read = min(
				max(len(fd_ref.file.content) - op.read.offset, 0),
				len(op.read.buf),
			)

			if op.read.all {
				if op.read.read != len(op.read.buf) {
					op.read.err = .EOF
					break
				}
			}

			if op.read.read != 0 {
				copy(
					op.read.buf,
					fd_ref.file.content[op.read.offset:][:op.read.read],
				)
			}
		case .write:
			fd_ref, ok := _access_fd(l, op.write.handle)
			if !ok {
				op.write.err = .Invalid_Argument
				break
			}

			if op.write.offset < 0 {
				op.write.err = .Invalid_Argument
				break
			}

			op.write.written = len(op.write.buf)

			if op.write.all {
				if op.write.written != len(op.write.buf) {
					op.write.err = .EOF
					break
				}
			}

			if op.write.written != 0 {
				resize(
					&fd_ref.file.content,
					op.write.offset + op.write.written,
				)
				copy(
					fd_ref.file.content[op.write.offset:][:op.write.written],
					op.write.buf,
				)
			}
		case .timeout:
		case:
			panic("wutafuka, corrupted operation")
		}

		_exec_cb(op)
	}

	_open_file :: proc(
		l: ^Event_Loop,
		name: string,
		mode: File_Flags,
		perm: nbio.Permissions,
	) -> ^File {
		context.allocator = l.allocator

		file := l.files[name]

		if .Create in mode && file == nil {
			file = new(File)
			file.content.allocator = l.allocator
			file.perm = perm
			l.files[strings.clone(name)] = file
		}

		if .Trunc in mode && file != nil {
			clear(&file.content)
		}

		return file
	}

	_new_fd :: proc(
		l: ^Event_Loop,
		kind: File_Descriptor_Kind,
	) -> (
		fd: ^File_Descriptor,
		idx: i64,
	) {
		defer {
			assert(idx != 0)
			fd.kind = kind
		}

		if l.free_fds != nil {
			f := l.free_fds
			l.free_fds = f.next_free_fd
			return f, f.idx
		}

		idx = i64(xar.len(l.fds))
		xar.append(&l.fds, File_Descriptor{idx = idx})
		return xar.get_ptr(&l.fds, idx), idx
	}

	_access_fd :: proc(l: ^Event_Loop, cls: union {
			UDP_Socket,
			TCP_Socket,
			Handle,
			Closable,
			Any_Socket,
		}) -> (^File_Descriptor, bool) {
		fd: i64
		kind: File_Descriptor_Kind
		switch t in cls {
		case UDP_Socket:
			fd = i64(t)
			kind = .UDP_Socket
		case TCP_Socket:
			fd = i64(t)
			kind = .TCP_Socket
		case Handle:
			fd = i64(t)
			kind = .File
		case Closable:
			switch t in t {
			case UDP_Socket:
				fd = i64(t)
				kind = .UDP_Socket
			case TCP_Socket:
				fd = i64(t)
				kind = .TCP_Socket
			case Handle:
				fd = i64(t)
				kind = .File
			}
		case Any_Socket:
			switch t in t {
			case UDP_Socket:
				fd = i64(t)
				kind = .UDP_Socket
			case TCP_Socket:
				fd = i64(t)
				kind = .TCP_Socket
			}
		}

		return _access_fd_(l, fd, kind)
	}

	_access_fd_ :: proc(
		l: ^Event_Loop,
		fd: i64,
		kind: File_Descriptor_Kind,
	) -> (
		ref: ^File_Descriptor,
		ok: bool,
	) {
		if int(fd) > xar.len(l.fds) || fd < 0 {
			return
		}

		fd_ref := xar.get_ptr(&l.fds, fd)
		if fd_ref.kind != kind {
			return
		}

		return fd_ref, true
	}

	_rand_dur :: proc(
		l: ^Event_Loop,
		min: time.Duration,
		max: time.Duration,
	) -> time.Duration {
		return time.Duration(rand.int_range(int(min), int(max)))
	}

	_add_task :: proc(
		l: ^Event_Loop,
		after: time.Duration,
		op: ^Operation,
		kind: Task_Kind,
	) {
		fmt.assertf(op.type != .None, "%v", rawptr(op))

		gen: int
		if op != nil do gen = op.gen

		priority_queue.push(
			&l.tasks,
			Task{fire_at = l.time + after, gen = gen, op = op, kind = kind},
		)
	}

	_new_op :: proc(
		l: ^Event_Loop,
		kind: Operation_Type,
		cb: proc(_: ^Operation) = nil,
		timeout: time.Duration = NO_TIMEOUT,
	) -> (
		op: ^Operation,
	) {
		if l.free_ops != nil {
			op, l.free_ops = l.free_ops, l.free_ops.next_free
			op^ = {
				gen = op.gen,
			}
		} else {
			op = new(Operation, l.allocator)
		}

		op.type, op.cb, op.l = kind, cb, l
		op.gen += 1

		if timeout > 0 do _add_task(l, timeout, op, .Cancel)

		return
	}

	_remove_op :: proc(op: ^Operation) {
		if op == nil do return

		fmt.assertf(op.type != .None, "%v", rawptr(op))

		l := op.l
		op.next_free = l.free_ops
		l.free_ops = op
		bit_arr.dl_remove(&op.rs_queue)

		op.type = .None
		op.gen += 1
	}

	_timeout_op :: proc(op: ^Operation) {
		l := op.l
		switch op.type {
		case .None:
			panic("unreachable")
		case .accept:
			op.accept.err = .Timeout
		case .dial:
			op.dial.err = net.Dial_Error.Timeout
		case .recv:
			op.recv.err = net.UDP_Recv_Error.Timeout
		case .send:
			op.send.err = net.UDP_Send_Error.Timeout
		case .open:
			op.open.err = .Timeout
		case .close:
			op.close.err = .Timeout
		case .stat:
			op.stat.err = .Timeout
		case .read:
			op.read.err = .Timeout
		case .write:
			op.write.err = .Timeout
		case .timeout:
			panic("cant timeout timeout")
		case:
			panic("wutafuka, corrupted operation")
		}

		_exec_cb(op)
	}

	_exec_cb :: proc(op: ^Operation) {
		op->cb()
		if op.type != .None {
			_remove_op(op)
		}
	}

	_remove_fd_ops :: proc(fd_ref: ^File_Descriptor) {
		to_invalidate := [?]bit_arr.DL_Iter {
			bit_arr.dl_iter(&fd_ref.send_ops),
			bit_arr.dl_iter(&fd_ref.recv_ops),
		}

		invalidation_errors := [?]Recv_Error{.Connection_Closed, nil}

		for &ti, i in to_invalidate {
			for tim in bit_arr.dl_iter_next(
				&ti,
				Operation,
				offset_of(Operation, rs_queue),
			) {
				if tim.recv.received != 0 {
					tim.recv.err = .Connection_Closed
				} else {
					tim.recv.err = invalidation_errors[i]
				}
				_exec_cb(tim)
			}
		}
	}
}

accept_poly :: #force_inline proc(
	socket: TCP_Socket,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	timeout: time.Duration = NO_TIMEOUT,
	l: ^Event_Loop,
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.accept_poly(socket, p, cb, timeout, l)
	} else {

		defer _put_user_data(op, cb, p)
		return _prep_accept(socket, timeout, _poly_cb(C, T), l)
	}
}

dial_poly :: #force_inline proc(
	endpoint: Endpoint,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	timeout: time.Duration = NO_TIMEOUT,
	l: ^Event_Loop,
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.dial_poly(endpoint, p, cb, timeout, l)
	} else {

		defer _put_user_data(op, cb, p)
		return _prep_dial(endpoint, timeout, _poly_cb(C, T), l)
	}
}

recv_poly :: #force_inline proc(
	socket: Any_Socket,
	bufs: [][]byte,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	all := false,
	timeout: time.Duration = NO_TIMEOUT,
	l: ^Event_Loop,
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.recv_poly(socket, bufs, p, cb, all, timeout, l)
	} else {
		defer _put_user_data(op, cb, p)
		return _prep_recv(socket, bufs, all, timeout, _poly_cb(C, T), l)
	}
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
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.recv_poly2(socket, bufs, p, p2, cb, all, timeout, l)
	} else {

		defer _put_user_data2(op, cb, p, p2)
		return _prep_recv(socket, bufs, all, timeout, _poly_cb2(C, T, T2), l)
	}
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
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.send_poly(socket, bufs, p, cb, endpoint, all, timeout, l)
	} else {

		defer _put_user_data(op, cb, p)
		return _prep_send(
			socket,
			bufs,
			endpoint,
			all,
			timeout,
			_poly_cb(C, T),
			l,
		)
	}
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
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.read_poly(handle, offset, buf, p, cb, all, timeout, l)
	} else {

		defer _put_user_data(op, cb, p)
		return _prep_read(handle, offset, buf, all, timeout, _poly_cb(C, T), l)
	}
}

read_poly3 :: #force_inline proc(
	handle: Handle,
	offset: int,
	buf: []byte,
	p: $T,
	p2: $T2,
	p3: $T3,
	cb: $C/proc(op: ^Operation, p: T, p2: T2, p3: T3),
	all := false,
	timeout: time.Duration = NO_TIMEOUT,
	l: ^Event_Loop,
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.read_poly3(
			handle,
			offset,
			buf,
			p,
			p2,
			p3,
			cb,
			all,
			timeout,
			l,
		)
	} else {

		defer _put_user_data3(op, cb, p, p2, p3)
		return _prep_read(
			handle,
			offset,
			buf,
			all,
			timeout,
			_poly_cb3(C, T, T2, T3),
			l,
		)
	}
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
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.write_poly(handle, offset, buf, p, cb, all, timeout, l)
	} else {

		defer _put_user_data(op, cb, p)
		return _prep_write(
			handle,
			offset,
			buf,
			all,
			timeout,
			_poly_cb(C, T),
			l,
		)
	}
}

open_poly :: #force_inline proc(
	path: string,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	mode: File_Flags = {.Read},
	perm: Permissions = Permissions_Default_File,
	dir: Handle = CWD,
	l: ^Event_Loop,
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.open_poly(path, p, cb, mode, perm, dir, l)
	} else {

		defer _put_user_data(op, cb, p)
		return _prep_open(path, mode, perm, dir, _poly_cb(C, T), l)
	}
}

open_poly2 :: #force_inline proc(
	path: string,
	p: $T,
	p2: $T2,
	cb: $C/proc(op: ^Operation, p: T, p2: T2),
	mode: File_Flags = {.Read},
	perm: Permissions = Permissions_Default_File,
	dir: Handle = CWD,
	l: ^Event_Loop,
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.open_poly2(path, p, p2, cb, mode, perm, dir, l)
	} else {
		defer _put_user_data2(op, cb, p, p2)
		return _prep_open(path, mode, perm, dir, _poly_cb2(C, T, T2), l)
	}
}

open_poly3 :: #force_inline proc(
	path: string,
	p: $T,
	p2: $T2,
	p3: $T3,
	cb: $C/proc(op: ^Operation, p: T, p2: T2, p3: T3),
	mode: File_Flags = {.Read},
	perm: Permissions = Permissions_Default_File,
	dir: Handle = CWD,
	l: ^Event_Loop,
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.open_poly3(path, p, p2, p3, cb, mode, perm, dir, l)
	} else {
		defer _put_user_data3(op, cb, p, p2, p3)
		return _prep_open(path, mode, perm, dir, _poly_cb3(C, T, T2, T3), l)
	}
}

stat_poly :: #force_inline proc(
	handle: Handle,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	l: ^Event_Loop,
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.stat_poly(handle, p, cb, l)
	} else {

		defer _put_user_data(op, cb, p)
		return _prep_stat(handle, _poly_cb(C, T), l)
	}
}

stat_poly3 :: #force_inline proc(
	handle: Handle,
	p: $T,
	p2: $T2,
	p3: $T3,
	cb: $C/proc(op: ^Operation, p: T, p2: T2, p3: T3),
	l: ^Event_Loop,
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.stat_poly3(handle, p, p2, p3, cb, l)
	} else {
		defer _put_user_data3(op, cb, p, p2, p3)
		return _prep_stat(handle, _poly_cb3(C, T, T2, T3), l)
	}
}

timeout_poly :: #force_inline proc(
	dur: time.Duration,
	p: $T,
	cb: $C/proc(op: ^Operation, p: T),
	l: ^Event_Loop,
) -> (
	op: ^Operation,
) {
	when !SIMULATE {
		return nbio.timeout_poly(dur, p, cb, l)
	} else {
		defer _put_user_data(op, cb, p)
		return _prep_timeout(dur, _poly_cb(C, T), l)
	}
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
	} else {
		defer _put_user_data2(op, cb, p, p2)
		return _prep_timeout(dur, _poly_cb2(C, T, T2), l)
	}
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
	} else {
		defer _put_user_data3(op, cb, p, p2, p3)
		return _prep_timeout(dur, _poly_cb3(C, T, T2, T3), l)
	}
}

_poly_cb :: #force_inline proc($C: typeid, $T: typeid) -> proc(_: ^Operation) {
	return proc(op: ^Operation) {
			ptr := uintptr(&op.user_data)
			cb := intrinsics.unaligned_load((^C)(rawptr(ptr)))
			p := intrinsics.unaligned_load((^T)(rawptr(ptr + size_of(C))))
			cb(op, p)
		}
}

_poly_cb2 :: #force_inline proc(
	$C: typeid,
	$T: typeid,
	$T2: typeid,
) -> proc(_: ^Operation) {
	return proc(op: ^Operation) {
			ptr := uintptr(&op.user_data)
			cb := intrinsics.unaligned_load((^C)(rawptr(ptr)))
			p := intrinsics.unaligned_load((^T)(rawptr(ptr + size_of(C))))
			p2 := intrinsics.unaligned_load(
				(^T2)(rawptr(ptr + size_of(C) + size_of(T))),
			)
			cb(op, p, p2)
		}
}

_poly_cb3 :: #force_inline proc(
	$C: typeid,
	$T: typeid,
	$T2: typeid,
	$T3: typeid,
) -> proc(_: ^Operation) {
	return proc(op: ^Operation) {
			ptr := uintptr(&op.user_data)
			cb := intrinsics.unaligned_load((^C)(rawptr(ptr)))
			p := intrinsics.unaligned_load((^T)(rawptr(ptr + size_of(C))))
			p2 := intrinsics.unaligned_load(
				(^T2)(rawptr(ptr + size_of(C) + size_of(T))),
			)
			p3 := intrinsics.unaligned_load(
				(^T3)(rawptr(ptr + size_of(C) + size_of(T) + size_of(T2))),
			)
			cb(op, p, p2, p3)
		}
}

_put_user_data :: #force_inline proc(op: ^Operation, cb: $C, p: $T) {
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

read_entire_file :: proc {
	read_entire_file_async,
	read_entire_file_sync,
}

read_entire_file_async :: proc(
	path: string,
	user_data: rawptr,
	cb: Read_Entire_File_Callback,
	allocator := context.allocator,
	dir := CWD,
	l: ^Event_Loop,
	loc := #caller_location,
) {
	_read_entire_file(l, path, user_data, cb, allocator, dir)
}

_read_entire_file :: proc(
	l: ^Event_Loop,
	path: string,
	user_data: rawptr,
	cb: Read_Entire_File_Callback,
	allocator := context.allocator,
	dir := CWD,
) {
	open_poly3(path, user_data, cb, allocator, on_open, dir = dir, l = l)

	on_open :: proc(
		op: ^Operation,
		user_data: rawptr,
		cb: Read_Entire_File_Callback,
		allocator: runtime.Allocator,
	) {
		if op.open.err != nil {
			cb(user_data, nil, {.Open, op.open.err})
			return
		}

		stat_poly3(op.open.handle, user_data, cb, allocator, on_stat, l = op.l)
	}

	on_stat :: proc(
		op: ^Operation,
		user_data: rawptr,
		cb: Read_Entire_File_Callback,
		allocator: runtime.Allocator,
	) {
		err: Read_Entire_File_Error

		defer if err.operation != .None {
			close(op.stat.handle, l = op.l)
			cb(user_data, nil, err)
		}

		if op.stat.err != nil {
			err = {.Stat, op.stat.err}
			return
		}

		if op.stat.type != .Regular {
			err = {.Stat, .Unsupported}
			return
		}

		buf, aerr := make([]byte, op.stat.size, allocator)
		if aerr != nil {
			err = {.Read, .Allocation_Failed}
			return
		}

		read_poly3(
			op.stat.handle,
			0,
			buf,
			user_data,
			cb,
			allocator,
			on_read,
			all = true,
			l = op.l,
		)
	}

	on_read :: proc(
		op: ^Operation,
		user_data: rawptr,
		cb: Read_Entire_File_Callback,
		allocator: runtime.Allocator,
	) {
		close(op.read.handle, l = op.l)

		if op.read.err != nil {
			delete(op.read.buf, allocator)
			cb(user_data, nil, {.Read, op.read.err})
			return
		}

		assert(op.read.read == len(op.read.buf))
		cb(user_data, op.read.buf, {})
	}
}
