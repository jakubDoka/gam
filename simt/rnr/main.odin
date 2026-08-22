package main

import "../../client/pure"
import "../../server"
import "../../sim"
import "../../util/arna"
import "../../util/bit_arr"
import "../../util/hot"
import "../../util/sqlite"
import "../nbio"
import "base:runtime"
import "core:log"
import "core:math/rand"
import "core:sync"
import "core:time"

SEED :: #config(SEED, 0)

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
	context.logger.options &= ~{.Time, .Date, .Procedure}

	gen := rand.create_u64(SEED)
	context.random_generator = rand.default_random_generator(&gen)

	init := arna.allocator(&init_arna)

	lista := make([dynamic]^hot.Reloader, init)

	append(
		&lista,
		server_boot(
			{ip = nbio.IP4_Any},
			{endpoint = {nbio.IP4_Any, 6000}},
			init,
		),
	)

	for i in 0 ..< 5 {
		append(
			&lista,
			client_boot(
				{ip = nbio.IP4_Address{0, 0, 0, u8(i + 1)}},
				{predefined_rtt = 120},
				init,
			),
		)
	}

	nbio.run(lista[0].l)

	for i in lista {
		i.init_allocator = {}
		i->deinit(i.state)
		nbio.destroy_event_loop(i.l)
	}

	context.logger = {}
	server.server_static_deinit()
	sim.global_allocator_destroy(context.allocator)
	arna.bulk_destroy(&temp_arna, &global_arna, &init_arna)
}

server_boot :: proc(
	mconfig: nbio.Machine_Config,
	config: server.Config,
	allc := context.allocator,
) -> ^hot.Reloader {
	l, _ := nbio.create_event_loop(mconfig)

	to_load := [?]string {
		"config/stats.yaml",
		"config/sprites/core.png",
		"config/sprites/blah.png",
		"config/sprites/node.png",
		"config/sprites/turret.png",
		"config/sprites/turrnat.png",
		"config/sprites/drill.png",
		"config/sprites/spawner.png",
	}

	to_load_content := [?][]u8 {
		#load("../../config/stats.yaml"),
		#load("../../config/sprites/core.png"),
		#load("../../config/sprites/blah.png"),
		#load("../../config/sprites/node.png"),
		#load("../../config/sprites/turret.png"),
		#load("../../config/sprites/turrnat.png"),
		#load("../../config/sprites/drill.png"),
		#load("../../config/sprites/spawner.png"),
	}

	for tl, i in to_load {
		nbio.write_entire_file(l, tl, to_load_content[i])
	}

	config := config
	config.db, _ = sqlite.open(cstring(":memory:"))

	hr := new(hot.Reloader, allc)
	hr.config = new_clone(config, allc)
	hr.init_allocator = allc
	hr.lib = hot.decl_api(server.API)
	hr.reload = hot.reload_impl
	hr.l = l
	hr->reload({})
	return hr
}

client_boot :: proc(
	mconfig: nbio.Machine_Config,
	config: pure.Config,
	allc := context.allocator,
) -> ^hot.Reloader {
	l, _ := nbio.create_event_loop(mconfig)

	config := config
	config.db, _ = sqlite.open(cstring(":memory:"))

	hr := new(hot.Reloader, allc)
	hr.config = new_clone(config, allc)
	hr.init_allocator = allc
	hr.lib = hot.decl_api(
		hot.Api(^Client){init = client_init, deinit = client_deinit},
	)
	hr.reload = hot.reload_impl
	hr.l = l
	hr->reload({})
	return hr

	Client :: struct {
		using base: pure.Client,
		on_tick:    ^nbio.Operation,
		n:          int,
	}

	client_init :: proc(
		hr: ^hot.Reloader,
		config: ^pure.Config,
	) -> (
		client: ^Client,
	) {
		context.allocator = hr.init_allocator
		client = new(Client)
		client.on_sheet_refresh = proc(_: ^Client) {}
		pure.client_init(client, hr, config)

		sim.interval_poly(
			time.Second / 60,
			client,
			client_on_tick,
			&client.on_tick,
			client.l,
		)

		pure.create_profile(client, "foob")
		pure.select_profile(client, "foob")

		return
	}

	client_on_tick :: proc(client: ^Client) {
		client.n += 1

		client.current_input.seq += 1

		client.ents.delta = 1.0 / 60
		client.rtt = sync.atomic_load(&client.shared_rtt)

		sim.ents_update(&client.ents)

		if hot.interrupted() {
			hot.sip.io_remove(client.on_tick)
			pure.client_shutdown(client)
			return
		}

		if client.connection_stage == .Connected && rand.float32() < 0.01 {
			pure.fetch_all_assets(client)
		}

		if client.connection_stage == .Connected && rand.float32() < 0.05 {
			spawn: if client.ent == {} {
				counts, alives := pure.compute_team_params(client)

				selected_team: sim.Ent_Team_ID
				for i in 0 ..< len(counts) {
					tid := sim.Ent_Team_ID(i)
					if sim.team_spawnable(tid, counts) && alives[tid] {
						selected_team = tid
						break
					}
				}

				spawn_parent := pure.find_spawn_parent(client, selected_team)

				if spawn_parent == sim.NIL_ENT {
					break spawn
				}

				pure.tcp_send(
					client,
					sim.Client_Cmd {
						type = .Spawn,
						parent = spawn_parent.net_id,
						id = 2,
					},
				)
			} else {
				pure.tcp_send(client, sim.Client_Cmd{type = .Abandon})
			}
		}

		ent := sim.ents_get(&client.ents, client.ent)
		if ent != sim.NIL_ENT && rand.float32() < 0.2 {
			best_build_score: f32
			best_build := sim.NIL_ENT

			for y in 0 ..< client.ents.height {
				for x in 0 ..< client.ents.width {
					build := sim.ents_building_get(&client.ents, {x, y})
					if build == sim.NIL_ENT do continue
					score := rand.float32()
					if score > best_build_score {
						best_build_score = score
						best_build = build
					}
				}
			}

			if best_build != sim.NIL_ENT {
				tile := sim.Map_Pos {
					int(rand.int63_max(i64(client.ents.width + 3))),
					int(rand.int63_max(i64(client.ents.height + 2))),
				}

				pure.tcp_send(
					client,
					sim.Client_Cmd {
						type = .Build,
						pos = pure.map_tile_center(tile),
						id = sim.Ent_Stats_ID(4),
						parent = best_build.net_id,
					},
				)
			}
		}

		if client.connection_stage == .Connected && rand.float32() < 0.01 {
			selected_profile := pure.get_selected_user(client)

			buf: [100]u8
			len := rand.int_range(0, len(buf))
			ok := runtime.random_generator_read_bytes(
				context.random_generator,
				buf[:len],
			)
			assert(ok)

			pure.tcp_send(
				client,
				sim.Broadcast_Packet(
					sim.Chat_Msg {
						name = selected_profile.name,
						id = client.handshake.ch.id,
						content = string(buf[:len]),
					},
				),
			)
		}

		if client.connection_stage == .Connected && rand.float32() < 0.01 {
			stats := rand.choice(client.ents.stats[:])
			if stats.bind_range != 0 {
				stats.bind_range += (rand.float32() - 0.5)
			}

			pure.tcp_send(
				client,
				sim.Client_Content_Action{type = .Edit, stats = stats},
			)
		}

		if client.connection_stage == .Connected && rand.float32() < 0.005 {
			edit_state: pure.Map_Edit_State

			{context.allocator = context.temp_allocator
				edit_state.changed_terrain = bit_arr.init(
					int(client.ents.width * client.ents.height),
				)
				edit_state.width = client.ents.width
				edit_state.height = client.ents.height
				append(&edit_state.teams, ..client.ents.teams)
			}

			mapa := pure.map_export(client, &edit_state)
			pure.tcp_send(client, sim.Client_Map_Edit{mapa})
		}

		if client.connection_stage == .Connected && rand.float32() < 0.005 {
			pure.tcp_send(client, sim.Client_Content_Action{type = .Save})
		}

		if client.connection_stage == .Disconnected && rand.float32() < 0.05 {
			pure.client_connect(client, {nbio.IP4_Any, 6000})
		}

		free_all(context.temp_allocator)
	}

	client_deinit :: proc(hr: ^hot.Reloader, client: ^Client) {
		if !client.did_shutdown {
			hot.sip.io_remove(client.on_tick)
		}
		pure.client_deinit(hr, client)
	}
}
