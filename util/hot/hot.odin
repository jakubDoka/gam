package hot_reload

import "../../simt/nbio"
import "base:runtime"
import "core:debug/trace"
import "core:dynlib"
import "core:fmt"
import "core:log"
import "core:os"
import "core:reflect"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:time"

HOT_RELOAD :: #config(HOT_RELOAD, false)

when ODIN_OS == .Windows {
	DYN_EXT :: ".dll"
} else when ODIN_OS == .Darwin {
	DYN_EXT :: ".dylib"
} else {
	DYN_EXT :: ".so"
}

_interrupted: bool
sip: Static_Init_Params = {
	nbio.remove,
	nbio.run,
	&_interrupted,
	&global_trace_ctx,
}

Static_Init_Params :: struct {
	io_remove:   proc(_: ^nbio.Operation),
	io_run:      proc(_: ^nbio.Event_Loop) -> nbio.General_Error,
	interrupted: ^bool,
	trace:       ^trace.Context,
}

Api :: struct {
	dlib:          dynlib.Library,
	memory_size:   proc() -> int,
	static_init:   proc(_: Static_Init_Params),
	static_deinit: proc(),
	init:          proc(_: ^Reloader, config: rawptr) -> rawptr,
	update:        proc(_: ^Reloader, state: rawptr),
	rewire:        proc(_: ^Reloader, state: rawptr),
	deinit:        proc(_: ^Reloader, state: rawptr),
}

Options :: struct {
	skip_full_reload: bool,
}

Define :: struct {
	name:  string,
	value: any,
}

Rewire_Table :: [dynamic; 32]rawptr

Reloader :: struct {
	inited:            bool,
	module_name:       string,
	watch_dirs:        []string,
	extra_args:        []string,
	dyn_defs:          []Define,
	state:             rawptr,
	init_allocator:    runtime.Allocator,
	using lib:         Api,
	rewire_table:      Rewire_Table,
	retired_libraries: [dynamic; 512]dynlib.Library,
	max_mtime:         time.Time,
	version:           int,
	force_reload:      bool,
	l:                 ^nbio.Event_Loop,
	config:            rawptr,
	reload:            proc(
		_: ^Reloader,
		_: Options,
		_ := #caller_location,
	) -> Status,
}

File :: struct {
	name:  string,
	mtime: time.Time,
}

Status :: enum {
	Ok,
	Refresh,
	Full_Reboot,
}

// NOTE: this might be a overengeneered crap, but I feel like once we get into
// more complicated long running tasks it will be usefull
Rewireing :: struct {
	hr:    ^Reloader,
	table: Rewire_Table,
}

load_fn :: proc(fn: any) -> rawptr {
	assert(reflect.is_procedure(type_info_of(fn.id)))
	return (^rawptr)(fn.data)^
}

store_fn :: proc(slot: any, vl: rawptr) {
	assert(reflect.is_procedure(type_info_of(slot.id)))
	(^rawptr)(slot.data)^ = vl
}

rewire_apply :: proc(r: Rewireing) {
	r.hr.rewire_table = r.table
}

rewire :: proc(r: ^Rewireing, vl: any) {
	current := load_fn(vl)
	if current == nil do return
	idx, ok := slice.linear_search(r.hr.rewire_table[:], current)
	if !ok {
		fmt.panicf("%v %v %v", vl, r.hr.rewire_table, r.table)
	}
	store_fn(vl, r.table[idx])
}

deinit :: proc(hr: ^Reloader) {
	if hr.state != nil do hr->deinit(hr.state)
	free_all(hr.init_allocator)
	hr.static_deinit()
}

unload_libraries :: proc(hr: ^Reloader) {
	if hr.dlib != nil do dynlib.unload_library(hr.dlib)
	for lib in hr.retired_libraries do dynlib.unload_library(lib)
	clear(&hr.retired_libraries)
}

update :: proc(hr: ^Reloader) {
	hr->update(hr.state)
}

should_reload :: proc(hr: ^Reloader) -> (should_reload: bool) {
	context.allocator = context.temp_allocator

	for wd in hr.watch_dirs {
		w := os.walker_create(wd)
		defer os.walker_destroy(&w)

		for entry in os.walker_walk(&w) {
			if entry.type != .Regular do continue
			if !strings.ends_with(entry.name, ".odin") do continue

			if time.time_to_unix_nano(hr.max_mtime) <
			   time.time_to_unix_nano(entry.modification_time) {
				hr.max_mtime = entry.modification_time
				should_reload = true
			}
		}
	}

	return
}

interrupted :: proc() -> bool {
	return sync.atomic_load(&_interrupted)
}

@(require_results)
reload :: proc(
	hr: ^Reloader,
	options: Options,
	loc := #caller_location,
) -> (
	res: Status = .Ok,
) {
	if !hr.inited {
		hr.inited = true

		posix.signal(.SIGINT, on_sigint)
		on_sigint :: proc "c" (sig: posix.Signal) {
			if sync.atomic_load(sip.interrupted) {
				posix.exit(1)
			}

			sync.atomic_store(sip.interrupted, true)
		}
	}

	if hr.reload != nil {
		prev := hr.reload
		defer hr.reload = prev
		hr.reload = nil
		return prev(hr, options, loc)
	}

	if !HOT_RELOAD {
		if hr.state == nil {
			hr.state = hr->init(hr.config)
		}
		return
	}

	force_reload := hr.force_reload
	hr.force_reload = false
	should_reload := force_reload || should_reload(hr)

	if !should_reload do return

	new_lib: Api

	{context.allocator = context.temp_allocator
		log.debug("hot reloading")

		module_name := hr.module_name

		name := fmt.tprintf("tmp/%v%v" + DYN_EXT, module_name, hr.version)
		hr.version += 1

		args: [dynamic]string
		append(
			&args,
			"odin",
			"build",
			module_name,
			"-debug",
			"-build-mode:dll",
			fmt.tprintf("-out:%v", name),
		)
		append(&args, ..hr.extra_args)

		for def in hr.dyn_defs {
			append(&args, fmt.tprintf("-define:%v=%v", def.name, def.value))
		}

		desc: os.Process_Desc
		desc.command = args[:]
		state, _, stderr, err := os.process_exec(desc, context.temp_allocator)
		assert(err == nil)
		if state.exit_code != 0 {
			log.error("failed to build:", string(stderr))
			return
		}

		_, ok := dynlib.initialize_symbols(
			&new_lib,
			name,
			fmt.tprintf("%v_", module_name),
			"dlib",
		)
		assert(ok, dynlib.last_error(), loc = loc)
	}

	if hr.static_deinit != nil do hr.static_deinit()
	if hr.dlib != nil do append(&hr.retired_libraries, hr.dlib)

	new_lib.static_init(sip)

	is_full_reload :=
		hr.state == nil ||
		hr.memory_size() != new_lib.memory_size() ||
		force_reload

	res = is_full_reload ? .Full_Reboot : .Refresh

	if options.skip_full_reload && is_full_reload {
		dynlib.unload_library(new_lib.dlib)
		return
	}

	if is_full_reload {
		if hr.state != nil do hr->deinit(hr.state)
		free_all(hr.init_allocator)
		unload_libraries(hr)
	}

	hr.lib = new_lib

	if is_full_reload {
		clear(&hr.rewire_table)
		hr.state = hr->init(hr.config)
	} else {
		if hr.rewire != nil do hr->rewire(hr.state)
	}

	return
}

once: sync.Once
global_trace_ctx: trace.Context

dump_trace :: proc() {
	ctx := sip.trace
	if !trace.in_resolve(ctx) {
		buf: [64]trace.Frame
		runtime.print_string("Debug Trace:\n")
		frames := trace.frames(ctx, 1, buf[:])
		for f in frames {
			fl := trace.resolve(ctx, f, context.temp_allocator)
			if fl.loc.file_path == "" && fl.loc.line == 0 {
				continue
			}
			fl.column = 1
			runtime.print_caller_location(fl.loc)
			runtime.print_byte('\n')
		}
	}
}

@(require_results)
init_trace :: proc(
) -> proc(prefix, message: string, loc: runtime.Source_Code_Location) -> ! {
	when !ODIN_DEBUG do return context.assertion_failure_proc
	sync.once_do(&once, proc() {
		trace.init(&global_trace_ctx)
	})
	return proc(prefix, message: string, loc := #caller_location) -> ! {
			runtime.print_caller_location(loc)
			runtime.print_string(" ")
			runtime.print_string(prefix)
			if len(message) > 0 {
				runtime.print_string(": ")
				runtime.print_string(message)
			}
			runtime.print_byte('\n')
			dump_trace()
			runtime.trap()
		}
}
