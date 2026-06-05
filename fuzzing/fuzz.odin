package fuzzing

import "../server"
import "../sim"
import "../util/arna"
import "../util/hot"
import "../util/sqlite"
import "base:runtime"
import "core:fmt"
import "core:log"
import "core:nbio"
import "core:os"
import "core:path/filepath"
import "core:strings"

NEEDLE :: "doodleberry"

@(thread_local)
global: arna.Allocator
@(thread_local)
temp: arna.Allocator
@(thread_local)
stmts: server.Server_Statements

@(export)
fuzz_init :: proc "c" () {
	global.reserved = 1024 * 1024 * 1024
	temp.reserved = 1024 * 1024 * 64

	err := arna.bulk_init(&global, &temp)
	assert_contextless(err == nil)

	context = runtime.default_context()
	server.init_db(&stmts)
}

@(export)
fuzz_one :: proc "c" (data: [^]u8, size: uint) {
	context = runtime.default_context()

	when ODIN_BUILD_MODE == .Executable {
		context.logger = log.create_console_logger()
	}

	arna.reset(&global, decommit = false)
	arna.reset(&temp, decommit = false)
	context.allocator = arna.allocator(&global)
	context.temp_allocator = arna.allocator(&temp)

	hr: hot.Reloader
	hr.init_allocator = arna.allocator(&global)

	sv := server.server_init(&hr)
	sv.statements = stmts

	sqlite.exec(
		sqlite.db_handle(sv.count_ip_sightings),
		`
		DELETE FROM user;
		DELETE FROM ip_sighting;
	`,
	)

	d := sim.Decoder{data[:size]}

	from: server.Connection
	from.tcp_endpoint = nbio.Endpoint{nbio.IP4_Loopback, 0}

	for packet in sim.client_packet_decode(&d) {
		server.server_handle_packet(sv, &from, packet)
		free_all(context.temp_allocator)
	}
}

when ODIN_BUILD_MODE == .Executable {
	run_one :: proc(path: string) {
		data, err := os.read_entire_file(path, context.allocator)
		if err != nil {
			fmt.eprintfln("failed to read %s: %v", path, err)
			os.exit(1)
		}
		fmt.eprintln("running:", path)
		fuzz_one(raw_data(data), uint(len(data)))
	}

	main :: proc() {
		fuzz_init()

		if len(os.args) >= 2 {
			run_one(os.args[1])
			return
		}

		crashes_dir := "fuzzing/findings/main/crashes"
		if !os.exists(crashes_dir) {
			crashes_dir = "findings/main/crashes"
		}

		fd, derr := os.open(crashes_dir)
		if derr != nil {
			fmt.eprintfln("failed to open %s: %v", crashes_dir, derr)
			os.exit(1)
		}
		defer os.close(fd)

		entries, rerr := os.read_dir(fd, -1, context.allocator)
		if rerr != nil {
			fmt.eprintfln("failed to read dir %s: %v", crashes_dir, rerr)
			os.exit(1)
		}

		count := 0
		for entry in entries {
			if entry.type == .Directory do continue
			if !strings.has_prefix(entry.name, "id:") do continue
			path, _ := filepath.join(
				{crashes_dir, entry.name},
				allocator = context.temp_allocator,
			)
			run_one(path)
			count += 1
		}

		fmt.eprintfln("ran %d crash(es)", count)
	}
}
