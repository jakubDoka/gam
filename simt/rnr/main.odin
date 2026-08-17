package main

import "../../client"
import "../../server"
import "../../sim"
import "../../util/arna"
import "../../util/hot"
import "core:log"

main :: proc() {
	CHUNK_SIZE :: 1024 * 1024 * 16
	TEMP_SIZE :: 1024 * 1024 * 64
	INIT_SIZE :: 1024 * 1024 * 16

	temp_arna: arna.Allocator
	temp_arna.reserved = TEMP_SIZE
	global_arna: arna.Allocator
	global_arna.reserved = CHUNK_SIZE * 8
	init_arna: arna.Allocator
	init_arna.reserved = INIT_SIZE

	arna_err := arna.bulk_init(&temp_arna, &global_arna, &init_arna)
	log.assertf(arna_err == nil, "failed to initialize arenas: %v", arna_err)

	context.assertion_failure_proc = hot.init_trace()
	context.temp_allocator = arna.allocator(&temp_arna)
	context.allocator = sim.global_allocator_create(
		arna.allocator(&global_arna),
		CHUNK_SIZE,
	)
	context.logger = log.create_console_logger(
		allocator = arna.allocator(&global_arna),
	)
}
