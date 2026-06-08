package client

import "../sim"
import "../util/arna"
import "../util/b58"
import "../util/nm"
import "../util/packer"
import "../util/sqlite"
import orui "../vendored/orui/src"
import rt "base:runtime"
import "core:crypto"
import "core:fmt"
import "core:math"
import la "core:math/linalg"
import "core:math/rand"
import "core:nbio"
import "core:reflect"
import "core:strings"
import "core:time"
import rl "vendor:raylib"

id :: orui.id
box :: orui.container

ID_WIDTH :: 32
PADDING :: 4
SELECTED_PROFILE_CID :: 0
ROW_HEIGHT :: 32
HEIGHT :: ROW_HEIGHT * 0.66

Profile :: struct {
	name: sim.Player_Name,
	pk:   sim.Private_Key,
}

Saved_Text_Input :: struct {
	id:      int,
	content: string,
}

Saved_Server :: struct {
	nick_name:   string,
	conn_string: string,
	pk:          sim.Identity,
}

Saved_Asset :: struct {
	pk:   sim.Identity,
	id:   sim.Asset_ID,
	name: nm.Name,
	type: sim.Asset_Type,
}

UI_Statements :: struct {
	save_input_content:     sqlite.Statement `
		INSERT INTO text_input VALUES (?, ?)
			ON CONFLICT (id) DO UPDATE SET content = ?2
	`,
	load_input_content:     sqlite.Statement `
		SELECT content FROM text_input WHERE id = ?
	`,
	delete_input_content:   sqlite.Statement `
		DELETE FROM text_input WHERE id = ?
	`,
	save_profile:           sqlite.Statement `
		INSERT INTO profile VALUES (?, ?)
	`,
	load_profiles:          sqlite.Statement `
		SELECT * FROM profile
	`,
	count_profiles:         sqlite.Statement `
		SELECT COUNT(*) FROM profile
	`,
	delete_profile:         sqlite.Statement `
		DELETE FROM profile WHERE name = ?
	`,
	edit_profile:           sqlite.Statement `
		UPDATE profile SET name = ? WHERE name = ?
	`,
	select_profile_by_name: sqlite.Statement `
		SELECT * FROM profile WHERE name = ?
	`,
	select_theme_color:     sqlite.Statement `
		SELECT hue, saturation, brightness, alpha FROM theme WHERE name = ?
	`,
	save_theme_color:       sqlite.Statement `
		INSERT INTO theme VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (name) DO UPDATE SET
				hue = ?2, saturation = ?3, brightness = ?4, alpha = ?5
	`,
	save_server:            sqlite.Statement `
		INSERT INTO server VALUES (?, ?, ?)
			ON CONFLICT (nick_name) DO UPDATE SET
				conn_string = ?2, pk = ?3
	`,
	load_server:            sqlite.Statement `
		SELECT * FROM server WHERE nick_name = ?
	`,
	load_servers:           sqlite.Statement `
		SELECT * FROM server
	`,
	delete_server:          sqlite.Statement `
		DELETE FROM server WHERE nick_name = ?
	`,
	save_asset:             sqlite.Statement `
		INSERT INTO asset VALUES (?, ?, ?, ?)
			ON CONFLICT (id, server) DO UPDATE SET name = ?3, type = ?4
	`,
	get_server_assets:      sqlite.Statement `
		SELECT id FROM asset WHERE server = ?
	`,
	get_asset:              sqlite.Statement `
		SELECT * FROM asset WHERE id = ?
	`,
	delete_asset:           sqlite.Statement `
		DELETE FROM Asset WHERE id = ?
	`,
}

Theme_Color :: struct #raw_union {
	using vec:    UI_Color_Picker_State,
	using values: struct {
		hue:        f32,
		saturation: f32,
		brightness: f32,
		alpha:      f32,
	},
}

// NOTE: the alignment here is to hot-reload the UI while adding more stuff to
// this struct
UI_Reactor :: struct {
	assets:                  [dynamic]sim.Asset_ID,
	last_handled_button:     Maybe(rl.MouseButton),
	ip_buf:                  strings.Builder,
	ip_error:                string,
	colors:                  UI_Colors,
	settings_expanded:       bool,
	servers:                 UI_Servers,
	profiles:                UI_Profiles,
	content_editing:         UI_Content_Editor,
	map_editing:             UI_Map_Editor,
	chat:                    UI_Chat,
	db:                      sqlite.Connection,
	using ui_statements:     UI_Statements,
	selected_team:           sim.Ent_Team_ID,
	selected_units:          [dynamic]sim.Ent_ID,
	sheet:                   packer.Sheet,
	orui_ctx:                orui.Context,
	has_dirty_config:        bool,
	control_selection_pivot: sim.Vec,
	events:                  [dynamic]UI_Event,
}

UI_Event_Kind :: enum {
	Edit_Stat,
}

UI_Event :: struct {
	kind: UI_Event_Kind,
	stat: sim.Ent_Stats_ID,
}

emit_event :: #force_no_inline proc(
	r: ^UI_Reactor,
	kind: UI_Event_Kind,
	event: UI_Event,
) {
	event := event
	event.kind = kind

	append(&r.events, event)
}

UI_Chat :: struct {
	open:     bool,
	prompt:   strings.Builder,
	messages: Chat_Ring,
	scroll:   int,
}

UI_Colors :: struct {
	expanded:    bool,
	selected:    UI_Color,
	picker_hsvs: [UI_Color]Theme_Color,
	picker_rgbs: [UI_Color]rl.Color,
}

UI_Servers :: struct {
	expanded:             bool,
	create_expanded:      bool,
	create_info_expanded: bool,
	create_conn_string:   strings.Builder,
	create_nick_name:     strings.Builder,
	create_fetcher:       UI_Server_Info_Listener,
	server_info_cache:    [dynamic]^UI_Server_Info_Listener,
}

UI_Server_Info_Listener :: struct {
	using inner:       Handshake,
	gc:                bool,
	error:             string,
	present:           bool,
	state:             Connection_State,
	expected_identity: sim.Identity,
	pk:                sim.Private_Key,
	server_info:       sim.Server_Info,
}

server_info_close :: proc(ctx: ^UI_Server_Info_Listener, gc := false) {
	if ctx.state == .Connected {
		ctx.gc = gc
		ctx->on_fail("")
	} else if ctx.state == .Disconnected {
		if gc do free(ctx)
	}
}

fetch_server_info :: proc(
	ctx: ^UI_Server_Info_Listener,
	endp: nbio.Endpoint,
	l: ^nbio.Event_Loop,
) -> ^UI_Server_Info_Listener {
	ctx^ = {}
	sim.private_key_generate(&ctx.pk)
	assert(ctx.state == .Disconnected)
	ctx.state = .Connecting
	ctx.host.asoc_data = l
	ctx.on_fail = on_fail
	ctx.get_pk = get_pk
	ctx.on_boot = on_boot
	ctx.host.on_kill = on_kill
	ctx.host.on_packet = on_packet

	header := (^sim.Client_Request_Header)(&ctx.ch.payload)
	header.kind = .Watch_Server_Info

	hctx_connect(ctx, endp, l)

	return ctx

	on_fail :: proc(ctx: ^UI_Server_Info_Listener, reason: string) {
		l := (^nbio.Event_Loop)(ctx.host.asoc_data)

		assert(ctx.state == .Connected || ctx.state == .Connecting)
		sim.tcp_connection_kill(&ctx.tcp, l)
		ctx.error = reason
	}

	get_pk :: proc(ctx: ^UI_Server_Info_Listener) -> sim.Private_Key {
		return ctx.pk
	}

	on_boot :: proc(ctx: ^UI_Server_Info_Listener, l: ^nbio.Event_Loop) {
		sim.tcp_connection_boot(&ctx.tcp, 512, 0, l = l)
		ctx.state = .Connected
	}

	on_packet :: proc(
		ctx: ^UI_Server_Info_Listener,
		l: ^nbio.Event_Loop,
		bytes: []u8,
	) -> bool {
		copy(reflect.as_bytes(ctx.server_info), bytes)
		assert(ctx.host.asoc_data != nil)
		return true
	}

	on_kill :: proc(ctx: ^UI_Server_Info_Listener, l: ^nbio.Event_Loop) {
		ctx.state = .Disconnected
		if ctx.gc do free(ctx)
	}
}

UI_Profiles :: struct {
	expanded:          bool,
	editing:           bool,
	editing_name:      strings.Builder,
	editing_error:     string,
	creation_expanded: bool,
	creation_name:     strings.Builder,
	creation_error:    string,
}

UI_Content_Editor :: struct {
	expanded:             bool,
	selected:             sim.Ent_Stats_ID,
	stat_edit_state:      sim.Ent_Stats,
	stat_editor:          Stat_Editor_State,
	edit_name:            strings.Builder,
	create_stat:          bool,
	create_stat_name:     strings.Builder,
	upload_error:         string,
	upload_arena:         arna.Allocator,
	dropped_assets:       #soa[dynamic]struct {
		base:  sim.Asset,
		path:  string,
		issue: string,
	},
	last_prepared_upload: time.Time,
}

Stat_Editor_State :: struct {
	depth:               int,
	root:                orui.Id,
	eidt_root:           orui.Id,
	string_field:        strings.Builder,
	color:               UI_Color_Picker_State,
	expanded_substructs: [dynamic; 16]orui.Id,
	current_field:       orui.Id,
	last_field:          orui.Id,
	has_error:           bool,
}

ui_destroy :: proc(client: ^UI_Reactor) {
	sim.recurse(client^, visit, ignore_unknown = true)

	visit :: proc(
		vl: any,
		tag: reflect.Struct_Tag,
	) -> (
		go_deeper: bool,
		ok: bool = true,
	) {
		switch &v in vl {
		case strings.Builder:
			delete(v.buf)
			v.buf = {}
		case:
			go_deeper = true
		}

		return
	}

	delete(client.selected_units)
	for e in client.servers.server_info_cache do free(e)
	delete(client.servers.server_info_cache)
	orui.destroy(&client.orui_ctx)
	ui_map_editor_destroy(&client.map_editing)
}

ui_icon_button :: proc(
	id: orui.Id,
	size: f32,
	icon: rl.GuiIconName,
	tooltip: string,
	config: Button_Config = {},
) -> bool {
	config := config
	config.width = orui.fixed(size)
	config.height = orui.fixed(size)
	config.icon = icon
	config.tooltip = tooltip

	return ui_button(id, config)
}

ui_connection_menu :: proc(client: ^Client) {
	{box(
			id("connetion-ui-padder"),
			{width = orui.grow(), height = orui.percent(0.45)},
		)

		{box(id("settings-padder"), {width = orui.grow()})}

		ui_icon_dropdown(
			id("game-settings"),
			&client.settings_expanded,
			ROW_HEIGHT,
			.ICON_GEAR_BIG,
			"settings",
			{layer = 100},
		)
	}

	if client.settings_expanded {
		box(
			id("settings-ui-centerer"),
			{
				width = orui.grow(),
				height = orui.grow(),
				position = {.Absolute, {}},
				align_cross = .Center,
				align_main = .Center,
				direction = .TopToBottom,
				layer = 50,
			},
		)

		{box(
				id("settings-colors"),
				{
					background_color = ui_color(.SECONDARY_FAINT),
					direction = .TopToBottom,
					gap = PADDING,
					padding = orui.padding(PADDING),
				},
			)

			ui_label(
				id("settings-color-label"),
				{
					label = "UI Colors",
					width = orui.grow(),
					height = orui.fixed(ROW_HEIGHT),
					align = .Start,
				},
			)

			for &color, vl in UI_COLORS {
				if vl not_in EDITABLE_COLORS do continue
				hsv := &client.ui.colors.picker_hsvs[vl]

				box(
					id("ui-colors-expanded", vl),
					{width = orui.grow(), gap = PADDING},
				)

				name, _ := reflect.enum_name_from_value(vl)
				ui_label(
					id("ui-colors-color", vl),
					{
						label = name,
						width = orui.grow(),
						height = orui.fixed(ROW_HEIGHT),
						background = ui_color_slot(.SLOT1, color),
						foreground = ui_color_slot(
							.SLOT2,
							la.max(
								rl.Color{255, 255, 255, 255} - color,
								rl.BLACK,
							),
						),
						align = .Start,
					},
				)

				if color_visibly_different(color, UI_COLORS_DEFAULT[vl]) {
					if ui_icon_button(
						id("ui-colors-color-reset", vl),
						ROW_HEIGHT,
						.ICON_RESTART,
						"Reset to default",
					) {
						hsv.hsv = ui_color_to_hsv(UI_COLORS_DEFAULT[vl])
						client.colors.selected = .NONE
					}
				}

				color_visibly_different :: proc(a, b: rl.Color) -> bool {
					a := [?]i32{i32(a.r), i32(a.g), i32(a.b), i32(a.a)}
					b := [?]i32{i32(b.r), i32(b.g), i32(b.b), i32(b.a)}

					diff := la.abs(a - b)
					return diff.a + diff.r + diff.g + diff.b > 4
				}

				defer {
					_, err := sqlite.exec(
						client.save_theme_color,
						name,
						hsv.hue,
						hsv.saturation,
						hsv.brightness,
						hsv.alpha,
					)
					sqlite.assert_ok(client.save_theme_color, err)
				}

				if client.colors.selected != vl {
					if ui_icon_button(
						id("ui-colors-edit", vl),
						ROW_HEIGHT,
						.ICON_PENCIL_BIG,
						"Edit color",
					) {
						client.colors.selected = vl
					}
					continue
				}

				box(
					id("ui-colors-picker-anchor", vl),
					{
						width = orui.fixed(ROW_HEIGHT),
						height = orui.fixed(ROW_HEIGHT),
						position = {.Relative, {}},
					},
				)

				box(
					id("ui-colors-picker-popup", vl),
					{
						position = {.Absolute, {}},
						bounds = {.Window, .Shift, PADDING},
						layer = 100,
					},
				)

				if ui_clicked_off() {
					client.colors.selected = .NONE
				}

				ui_color_picker(
					id("ui-colors-color-picker", vl),
					hsv,
					{
						width = orui.fixed(ROW_HEIGHT * 5),
						height = orui.fixed(ROW_HEIGHT * 5),
					},
				)
			}
		}
	}

	box(
		id("connetion-ui-center"),
		{width = orui.grow(), height = orui.grow(), align_main = .Center},
	)

	box(
		id("connection-ui"),
		{
			width = orui.fixed(500),
			direction = .TopToBottom,
			gap = PADDING,
			scroll = orui.scroll(.Vertical),
			clip = {.Intersect, {}},
		},
	)

	{box(id("ip-row"), {width = orui.grow(), gap = PADDING})
		defaut_ip := "127.0.0.1:1234" when sim.LOCAL else "95.217.156.80:1234"

		ip, confirmed := ui_text_input(
			id("ip-input"),
			&client.ip_buf,
			{
				width = orui.grow(),
				height = orui.fixed(ROW_HEIGHT),
				placeholder = "127.0...",
				default_text = defaut_ip,
			},
		)

		if ui_button(
			   id("connect"),
			   {
				   label = "connect",
				   width = orui.fixed(100),
				   height = orui.fixed(ROW_HEIGHT),
			   },
		   ) ||
		   confirmed {

			endp, ok := nbio.parse_endpoint(string(ip))
			if !ok {
				client.ip_error = "expected ip adress:port"
			} else {
				client.ip_error = ""
				client_connect(client, endp)
			}
		}
	}

	ui_error_label(
		id("ip-error"),
		client.ip_error,
		orui.grow(),
		orui.fixed(ROW_HEIGHT),
	)

	{
		ctx := &client.servers

		i := 0
		for e in ctx.server_info_cache {
			if e.present {
				ctx.server_info_cache[i] = e
				i += 1
			} else {
				server_info_close(e, gc = true)
			}
		}
		resize(&ctx.server_info_cache, i)

		for &entry in ctx.server_info_cache do entry.present = false
	}

	if ui_dropdown(
		id("server-expand"),
		&client.servers.expanded,
		{
			label = "servers",
			width = orui.grow(),
			height = orui.fixed(ROW_HEIGHT),
		},
	) {
		ctx := &client.servers

		i := 0
		server_query, sqs := sqlite.query(client.load_servers, Saved_Server)
		for row in sqlite.query_next(&server_query) {
			defer i += 1

			entry: ^UI_Server_Info_Listener
			entry_idx: int

			endp, identity, ok := parse_conn_string(row.conn_string)

			for oentry, i in ctx.server_info_cache {
				if oentry.expected_identity == row.pk {
					entry = oentry
					entry_idx = i
				}
			}

			if entry == nil {
				entry = new(UI_Server_Info_Listener)
				fetch_server_info(entry, endp, client.l)
				entry_idx = len(ctx.server_info_cache)
				entry.expected_identity = row.pk
				append(&ctx.server_info_cache, entry)
			}

			was_fetched := entry.sh.id != {}
			entry.present = true

			{box(
					id("server-name-row"),
					{
						width = orui.grow(),
						height = orui.fixed(ROW_HEIGHT),
						gap = PADDING,
					},
				)

				if ui_button(
					id("server-name", i),
					{
						label = row.nick_name,
						width = orui.grow(),
						height = orui.fixed(ROW_HEIGHT),
						focused_color = .PRIMARY,
						background = .SECONDARY,
						align = .Start,
						disabled = entry.sh.id != entry.expected_identity ||
						entry.state != .Connected,
					},
				) {
					client_connect(client, endp)
				}

				if ui_icon_button(
					id("server-delete", i),
					ROW_HEIGHT,
					.ICON_BIN,
					"Delete server",
				) {
					_, delete_err := sqlite.exec(
						client.delete_server,
						row.nick_name,
					)
					sqlite.assert_ok(client.delete_server, delete_err)
				}

				if ui_icon_button(
					id("server-refresh", i),
					ROW_HEIGHT,
					.ICON_RESTART,
					"Refresh server identity",
					{
						disabled = entry.state != .Connected &&
						entry.state != .Disconnected,
					},
				) {
					entry.expected_identity = {}
				}
			}

			if len(entry.error) == 0 && entry.state == .Disconnected {
				entry.error = "Server disconnected"
			}

			if len(entry.error) != 0 {
				ui_error_label(
					id("dial-server-error"),
					entry.error,
					orui.grow(),
					orui.fixed(ROW_HEIGHT),
				)
				continue
			}

			if entry.state == .Connecting || entry.state == .Disconnecting {
				ui_load_bar(
					{width = orui.grow(), height = orui.fixed(ROW_HEIGHT)},
				)
				continue
			}

			if entry.expected_identity != entry.sh.id &&
			   entry.expected_identity != {} {
				ui_error_label(
					id("server-invalid-identity"),
					"servers idenitty changed",
					orui.grow(),
					orui.fixed(ROW_HEIGHT),
				)
				continue
			}

			box(
				id("server-info-table"),
				{
					width = orui.grow(),
					gap = PADDING,
					background_color = ui_color(.SECONDARY_FAINT),
					padding = orui.padding(PADDING),
					layout = .Grid,
					cols = 2,
					rows = 2,
				},
			)

			for field in reflect.struct_fields_zipped(sim.Server_Info) {
				value := reflect.struct_field_value(entry.server_info, field)

				name, _ := strings.replace_all(
					field.name,
					"_",
					"-",
					context.temp_allocator,
				)

				ui_label(
					id("server-info-field-name"),
					{label = fmt.tprintf("%v:", name), background = .NONE},
				)

				ui_label(
					id("server-info-field-value"),
					{label = fmt.tprint(value), background = .NONE},
				)
			}
		}
		sqlite.reset(sqs)

		if ui_dropdown(
			id("create-server-expand"),
			&ctx.create_expanded,
			{
				label = "+",
				width = orui.grow(),
				height = orui.fixed(ROW_HEIGHT),
			},
		) {
			{box(
					id("create-server-row"),
					{
						width = orui.grow(),
						height = orui.fixed(ROW_HEIGHT),
						gap = PADDING,
					},
				)

				text, confirmed := ui_text_input(
					id("create-server-name-input"),
					&ctx.create_conn_string,
					{
						width = orui.grow(),
						height = orui.fixed(ROW_HEIGHT),
						placeholder = "127.0.0...",
					},
				)

				endp, _, ok := parse_conn_string(text)

				if endp != ctx.create_fetcher.server_endpoint {
					server_info_close(&ctx.create_fetcher)
				}

				is_active := ctx.create_fetcher.state != .Disconnected

				if ui_icon_button(
					   id("create-server-confirm"),
					   ROW_HEIGHT,
					   .ICON_LASER,
					   "Fetch server info",
					   {disabled = is_active},
				   ) ||
				   (confirmed && !is_active) {
					if !ok {
						ctx.create_fetcher.error = "expected ip adress:port#identity"
						return
					}

					fetch_server_info(&ctx.create_fetcher, endp, client.l)
				}
			}

			ui_error_label(
				id("create-server-error"),
				ctx.create_fetcher.error,
				orui.grow(),
				orui.fixed(ROW_HEIGHT),
			)

			if ctx.create_fetcher.state == .Connected {
				b58_id := b58.encode(ctx.create_fetcher.handshake.sh.id[:])

				_, identity, ok := parse_conn_string(
					string(ctx.create_conn_string.buf[:]),
				)

				matches :=
					strings.starts_with(b58_id, identity) &&
					len(identity) >= ID_WIDTH

				{box(
						id("create-server-row"),
						{
							width = orui.grow(),
							height = orui.fixed(ROW_HEIGHT),
							gap = PADDING,
						},
					)

					ui_label(
						id("server-id-hash"),
						{
							label = b58_id[:ID_WIDTH],
							width = orui.grow(),
							height = orui.fixed(ROW_HEIGHT),
							align = .Start,
							foreground = matches ? .SUCCESS : .PRIMARY,
						},
					)

					ui_icon_dropdown(
						id("server-idenity-info-button"),
						&ctx.create_info_expanded,
						ROW_HEIGHT,
						.ICON_INFO,
						"server identity info",
					)

					already_copied := string(rl.GetClipboardText()) == b58_id

					if ui_icon_button(
						id("server-idenity-copy"),
						ROW_HEIGHT,
						already_copied ? .ICON_OK_TICK : .ICON_FILE_COPY,
						"Copy identity",
						{disabled = already_copied},
					) {
						rl.SetClipboardText(strings.clone_to_cstring(b58_id))
					}
				}

				if ctx.create_info_expanded {

					ui_label(
						id("server-info-text"),
						{
							label = "This is the server identity. Server owner should generally share this with you and you should include it in the connection string. Otherwise there is no guarantee you are connecting to the right server.",
							width = orui.grow(),
							height = orui.fixed(ROW_HEIGHT * 4),
							align = .Start,
						},
					)

				}

				{box(
						id("create-server-row"),
						{
							width = orui.grow(),
							height = orui.fixed(ROW_HEIGHT),
							gap = PADDING,
						},
					)

					text, confirmed := ui_text_input(
						id("server-id-nick-name"),
						&ctx.create_nick_name,
						{
							width = orui.grow(),
							height = orui.fixed(ROW_HEIGHT),
							placeholder = "nick...",
						},
					)

					is_valid := len(text) > 0

					existing: Saved_Server
					res, stm := sqlite.query(
						client.load_server,
						existing,
						text,
					)
					sqlite.reset(stm)
					is_valid &= res == .DONE
					is_valid &= matches

					if ui_icon_button(
						   id("server-save-id"),
						   ROW_HEIGHT,
						   .ICON_FILE_SAVE_CLASSIC,
						   "Save server",
						   {disabled = !is_valid},
					   ) ||
					   (confirmed && is_valid) {

						new_server: Saved_Server
						new_server.nick_name = text
						new_server.conn_string = string(
							ctx.create_conn_string.buf[:],
						)
						new_server.pk = ctx.create_fetcher.sh.id

						_, res := sqlite.exec(
							client.save_server,
							new_server.nick_name,
							new_server.conn_string,
							new_server.pk,
						)
						sqlite.assert_ok(client.save_server, res)
					}
				}
			}
		}
	}

	if ui_dropdown(
		id("profile-expand"),
		&client.profiles.expanded,
		{
			label = "profiles",
			width = orui.grow(),
			height = orui.fixed(ROW_HEIGHT),
		},
	) {
		ctx := &client.profiles

		selected_profile := ui_get_selected_user(client).name

		i := 0
		was_selected := false
		profile_query, pqs := sqlite.query(client.load_profiles, Profile)
		for row in sqlite.query_next(&profile_query) {
			row := row
			selected := nm.str(&row.name) == nm.str(&selected_profile)
			was_selected |= selected

			if ui_button(
				id("profile-name", i),
				{
					label = nm.str(&row.name),
					width = orui.grow(),
					height = orui.fixed(ROW_HEIGHT),
					toggle = !selected,
				},
			) {
				selected_profile = row.name
				if selected do selected_profile = {}

				_, save_err := sqlite.exec(
					client.save_input_content,
					SELECTED_PROFILE_CID,
					nm.str(&selected_profile),
				)
				sqlite.assert_ok(client.save_input_content, save_err)
				ctx.editing = false
				selected = !was_selected
			}

			if selected {
				{box(
						id("profile-selected"),
						{
							width = orui.grow(),
							height = orui.fixed(ROW_HEIGHT),
							gap = PADDING,
						},
					)

					if ui_icon_button(
						id("profile-selected-delete"),
						ROW_HEIGHT,
						.ICON_BIN,
						"Delete profile",
					) {
						_, delete_err := sqlite.exec(
							client.delete_profile,
							nm.str(&row.name),
						)
						sqlite.assert_ok(client.delete_profile, delete_err)
					}

					changed := ui_icon_button(
						id("profile-selected-edit"),
						ROW_HEIGHT,
						ctx.editing ? .ICON_FILE_SAVE_CLASSIC : .ICON_PENCIL_BIG,
						ctx.editing ? "Save profile name" : "Rename profile",
					)

					if ctx.editing {
						text, confirmed := ui_text_input(
							id("profile-selected-edit-name"),
							&ctx.editing_name,
							{
								width = orui.grow(),
								height = orui.fixed(ROW_HEIGHT),
							},
						)

						changed |= confirmed

						if changed {
							cnt, save_err := sqlite.exec(
								client.edit_profile,
								text,
								nm.str(&row.name),
							)
							ctx.editing_error = ""
							if save_err == .CONSTRAINT {
								ctx.editing_error = "name already taken"
								changed = false
							} else {
								sqlite.assert_ok(client.edit_profile, save_err)
								assert(cnt == 1)
							}
						}
					} else {
						ui_label(
							id("profile-selected-identity"),
							{
								label = b58.encode(row.pk[:])[:ID_WIDTH],
								width = orui.grow(),
								height = orui.fixed(ROW_HEIGHT),
							},
						)

						if changed {
							clear(&ctx.editing_name.buf)
							append(
								&ctx.editing_name.buf,
								..nm.bytes(&row.name),
							)
						}
					}
					ctx.editing ~= changed
				}

				ui_error_label(
					id("profile-selected-edit-error"),
					ctx.editing_error,
					orui.grow(),
					orui.fixed(ROW_HEIGHT),
				)
			}

			i += 1
		}
		sqlite.reset(pqs)

		if ui_dropdown(
			id("create-profile-expand"),
			&ctx.creation_expanded,
			{
				label = "+",
				width = orui.grow(),
				height = orui.fixed(ROW_HEIGHT),
			},
		) {
			{box(
					id("profile-creation"),
					{
						width = orui.grow(),
						height = orui.fixed(ROW_HEIGHT),
						gap = PADDING,
					},
				)

				name, confirmed := ui_text_input(
					id("profile-creation-name"),
					&ctx.creation_name,
					{width = orui.grow(), height = orui.fixed(ROW_HEIGHT)},
				)

				if ui_icon_button(
					   id("create-profile"),
					   ROW_HEIGHT,
					   .ICON_FILE_SAVE_CLASSIC,
					   "Create profile",
				   ) ||
				   confirmed {

					pk: sim.Private_Key
					crypto.rand_bytes(pk[:])

					ctx.creation_error = ""
					if name == "" {
						ctx.creation_error = "name cannot be empty"
					} else {
						_, res := sqlite.exec(client.save_profile, name, pk)
						if res == .CONSTRAINT {
							ctx.creation_error = "name already taken"
						} else {
							sqlite.assert_ok(client.save_profile, res)
						}
					}
				}
			}

			ui_error_label(
				id("profile-creation-error"),
				ctx.creation_error,
				orui.grow(),
				orui.fixed(ROW_HEIGHT),
			)
		}
	}
}

ui_load_bar :: proc(config: Label_Config) {
	config := config

	elipsis := "..."
	config.label = fmt.tprint(
		"Loading",
		elipsis[:int(rl.GetTime() * 3) % 3 + 1],
		sep = "",
	)
	config.background = ui_color_slot(
		.SLOT1,
		rl.ColorLerp(
			ui_color(.SECONDARY),
			ui_color(.SECONDARY_FAINT),
			(math.sin(f32(rl.GetTime() * 5)) + 1) / 2,
		),
	)

	ui_label(id("server-info-loading"), config)
}

ui_clicked_off :: proc() -> bool {
	return(
		!rl.CheckCollisionPointRec(
			rl.GetMousePosition(),
			orui.bounding_rect(),
		) &&
		rl.IsMouseButtonPressed(.LEFT) \
	)
}

ui_game_hud :: proc(client: ^Client) {
	box(id("hud"), {width = orui.grow(), gap = PADDING})

	if ui_button(
		   id("disconnect"),
		   {label = "disconnect", height = orui.fixed(ROW_HEIGHT)},
	   ) ||
	   rl.IsKeyPressed(.ESCAPE) {
		client_clear_state(client, "manual disconnect")
	}

	ui_label(
		id("rtt"),
		{
			label = fmt.tprintf(
				"rtt: %vms",
				math.floor(client.rtt * 2 * 1000),
			),
			width = orui.fixed(120),
			height = orui.fixed(ROW_HEIGHT),
		},
	)

	ui_label(
		id("tps"),
		{
			label = fmt.tprintf("tps: %v", client.tps),
			width = orui.fixed(100),
			height = orui.fixed(ROW_HEIGHT),
		},
	)

	if client.asset_loader != nil {
		ui_label(
			id("asset-load-inicator"),
			{
				label = fmt.tprint(
					"loading:",
					len(client.asset_loader.metas) -
					client.asset_loader.files_recvd,
				),
				height = orui.fixed(ROW_HEIGHT),
			},
		)
	}

	{box(
			id("hud-spacer"),
			{width = orui.grow(), height = orui.fixed(ROW_HEIGHT)},
		)}

	selected_profile := ui_get_selected_user(client)

	if nm.ln(selected_profile.name) != 0 {
		player_idx := -1
		for r, i in client.players {
			if r.pk == client.hctx.ch.id {
				player_idx = i
			}
		}

		if player_idx == -1 {
			if len(client.players) != 0 {
				ui_error_label(
					orui.id("profile-selection-error"),
					"account issue",
					orui.fit(),
					orui.fixed(ROW_HEIGHT),
				)
			}
		} else {
			player := client.players[player_idx]

			if client.content_editing.expanded && client.has_dirty_config {
				if ui_icon_button(
					id("content-edinting-save"),
					ROW_HEIGHT,
					.ICON_FILE_SAVE_CLASSIC,
					"Save content changes",
				) {
					tcp_send(client, sim.Client_Content_Action{kind = .Save})
				}
			}

			if .Edit_Content in player.permissions {
				if ui_icon_button(
					id("download-all-assets"),
					ROW_HEIGHT,
					.ICON_FILE_SAVE,
					"Download all assets",
				) {
					fetch_all_assets(client)
				}

				ui_icon_dropdown(
					id("edit-content-opener"),
					&client.content_editing.expanded,
					ROW_HEIGHT,
					.ICON_GEAR_BIG,
					"content editor",
				)
			}

			if client.map_editing.expanded && ui_map_has_changes(client) {
				if ui_icon_button(
					id("map-editor-save"),
					ROW_HEIGHT,
					.ICON_FILE_SAVE_CLASSIC,
					"Save map changes",
				) {
					mapa := ui_map_export(client)
					tcp_send(client, sim.Client_Map_Edit{mapa = mapa})
				}
			}

			if .Edit_Content in player.permissions {
				ui_icon_dropdown(
					id("map-editor-opener"),
					&client.map_editing.expanded,
					ROW_HEIGHT,
					.ICON_GRID,
					"map editor",
				)
			}
		}

		ui_label(
			id("profile-selected-name"),
			{
				label = nm.str(&selected_profile.name),
				height = orui.fixed(ROW_HEIGHT),
			},
		)
	}
}

ui_chat :: proc(client: ^Client) {
	selected_profile := ui_get_selected_user(client)

	if selected_profile.name == {} do return

	ctx := &client.chat
	box(
		id("chat-popup"),
		{
			width = orui.grow(),
			height = orui.grow(),
			direction = .TopToBottom,
			position = {.Absolute, {}},
			clip = {.Intersect, {}},
			layer = -1,
		},
	)

	chat_messages := id("chat-messages")
	box(
		chat_messages,
		{
			width = orui.grow(),
			direction = .TopToBottom,
			placement = orui.placement(.BottomLeft, .BottomLeft),
			position = {.Absolute, {}},
		},
	)

	{box(
			id("chat-messages-press-down"),
			{width = orui.grow(), height = orui.grow()},
		)}

	max_visible :=
		int(rl.GetScreenHeight() / (PADDING + font_medium.baseSize)) -
		int(ctx.open)
	display_time :: time.Second * 15
	fade_time :: time.Millisecond * 500

	count := 0
	msgs := chat_ring_iter(&ctx.messages)
	for msg in chat_ring_iter_next(&msgs) do count += 1

	prev_scroll := ctx.scroll
	i := 0
	msgs = chat_ring_iter(&ctx.messages)
	for msg in chat_ring_iter_next(&msgs) {
		msg := msg
		i += 1
		ri := count - i

		if ri < prev_scroll do continue
		if ri - prev_scroll > max_visible do continue

		opacity :=
			1 -
			clamp(
				(f32(time.since(msg.time)) - f32(display_time - fade_time)) /
				f32(fade_time),
				0,
				1,
			)
		if ctx.open do opacity = 1
		if opacity == 0 do continue

		box(id("chat-messages-press-down", i), {width = orui.percent(0.6)})

		hovered := false

		ui_label(
			id("chat-message-sender", i),
			{
				label = fmt.tprintf("[%v]:", nm.str(&msg.name)),
				height = orui.grow(),
				background = ui_color_alpha_slot(
					.SLOT1,
					.SECONDARY_FAINT,
					opacity,
				),
				foreground = ui_color_slot(
					.SLOT2,
					rl.ColorAlpha(msg.color, opacity),
				),
				align = .Start,
				padding = orui.Edges{PADDING, 0, PADDING, PADDING * 2},
			},
		)
		hovered |= orui.hovered()

		ui_label(
			id("chat-message", i),
			{
				label = msg.content,
				background = ui_color_alpha_slot(
					.SLOT1,
					.SECONDARY_FAINT,
					opacity,
				),
				foreground = ui_color_alpha_slot(.SLOT2, .FOREGROUND, opacity),
				align = .Start,
			},
		)
		hovered |= orui.hovered()

		if hovered {
			scroll := rl.GetMouseWheelMove()
			ctx.scroll += int(scroll) * 4
			ctx.scroll = clamp(ctx.scroll, 0, count - max_visible / 2)
		}
	}

	if ctx.open {
		orui.set_scroll_offset(chat_messages, {0, 1000000000000000})

		text, confirm := ui_text_input(
			id("chat-prompt"),
			&ctx.prompt,
			{width = orui.grow(), layer = 100, dont_save_state = true},
		)

		if confirm {
			tcp_send(
				client,
				sim.Broadcast_Packet(
					sim.Chat_Msg {
						name = selected_profile.name,
						id = client.handshake.ch.id,
						content = string(ctx.prompt.buf[:]),
					},
				),
			)
			clear(&ctx.prompt.buf)
		}

		ctx.open = orui.focused()
	}

	ctx.open ~= is_key_pressed(client, .ENTER)
}

ui_player_color :: proc(seed: []u8) -> rl.Color {
	gen := rand.create_bytes(seed)
	context.random_generator = rand.default_random_generator(&gen)

	return rl.ColorFromHSV(rand.float32() * 360, 0.6, 1)
}

fetch_all_assets :: proc(client: ^Client) {
	present_assets := make([dynamic]sim.Asset_ID, context.temp_allocator)

	query, stmt := sqlite.query(
		client.get_server_assets,
		Saved_Asset,
		client.hctx.sh.id,
	)
	for asset in sqlite.query_next(&query) {
		append(&present_assets, asset.id)
	}
	sqlite.reset(stmt)

	tcp_send(
		client,
		sim.Client_Asset_Request{inverted = true, assets = present_assets[:]},
	)
}

ui_is_interacting :: proc(
	ui: ^UI_Reactor,
	button: Maybe(rl.MouseButton) = {},
	ignore_map_editor := false,
) -> bool {
	if orui.current_context.pointer_capture_id != 0 do return true

	button, ok := button.?
	if ok && button == ui.last_handled_button do return true

	if !ignore_map_editor && ui_map_eats_input(ui) do return true

	ctx := orui.current_context

	buf := orui.current_buffer(ctx)
	for hid in orui.hovered_ids() {
		idx, ok := orui.element_index_by_id(ctx, buf, hid)
		if !ok do continue

		for idx != 0 {
			elem := &ctx.elements[buf][idx]
			if elem.background_color.a > 0 do return true
			if elem.texture != nil do return true
			idx = elem.parent
		}
	}

	return false
}

ui_ship_selection :: proc(client: ^Client) {
	SHIP_BUTTON_SIZE :: 128
	MAX_SHIPS_PER_ROW :: 5
	TEAM_BUTTON_SIZE :: 40

	box(
		id("ship-selection-square"),
		{
			direction = .TopToBottom,
			background_color = UI_COLOR_SECONDARY,
			padding = orui.padding(PADDING * 2),
			placement = orui.placement(.Center, .Center),
			position = {.Relative, {}},
			layer = 1,
		},
	)

	team_prefix := min(1, len(client.ents.teams))

	{box(
			id("ship-selection-team"),
			{width = orui.grow(), align_main = .Center, gap = PADDING},
		)

		counts := make([]int, len(client.ents.teams), context.temp_allocator)
		for p in client.players {
			e := sim.ents_get(&client.ents, p.ent)
			if int(e.team) >= len(counts) do continue
			counts[e.team] += 1
		}

		alives := make([]bool, len(client.ents.teams), context.temp_allocator)
		iter := sim.ents_iter(&client.ents)
		for e in sim.ents_iter_next(&iter) {
			s := sim.ents_stats_get(&client.ents, e.stats)
			if int(e.team) >= len(counts) do continue
			alives[e.team] |= s.can_spawn_player
		}

		for t, i in client.ents.teams[team_prefix:] {
			tid := sim.Ent_Team_ID(team_prefix + i)
			selected := client.selected_team == tid
			color := rl.GetColor(auto_cast t.color)
			fcolor := rl.ColorAlpha(color, 0.8)
			margin: f32 = selected ? 0 : PADDING
			if ui_button(
				id("ship-selection-team-button", i),
				{
					width = orui.fixed(TEAM_BUTTON_SIZE - margin * 2),
					height = orui.fixed(TEAM_BUTTON_SIZE - margin * 2),
					margin = orui.margin(margin),
					background = ui_color_slot(.SLOT1, color),
					focused_color = ui_color_slot(.SLOT2, fcolor),
					disabled = !sim.team_spawnable(tid, counts) ||
					!alives[tid],
				},
			) {
				client.selected_team = tid
			}
		}
	}

	{box(
			id("ship-selection-team"),
			{width = orui.grow(), align_main = .Center, gap = PADDING},
		)

		spawn_parent := sim.NIL_ENT
		spawn_iter := sim.ents_iter(&client.ents)
		for e in sim.ents_iter_next(&spawn_iter) {
			s := sim.ents_stats_get(&client.ents, e.stats)
			if !s.can_spawn_player do continue
			if e.team != client.selected_team do continue
			spawn_parent = e
		}

		for &s, i in client.ents.stats {
			if !s.playable do continue

			if ui_button(
				id("ship-selection-ship", i),
				{
					label = nm.str(&s.name),
					width = orui.fixed(SHIP_BUTTON_SIZE),
					height = orui.fixed(SHIP_BUTTON_SIZE),
					margin = orui.margin(PADDING),
					background = .NONE,
					focused_color = .NONE,
					sprite = s.sprite.id,
					disabled = client.selected_team == 0,
				},
			) {
				tcp_send(
					client,
					sim.Client_Cmd {
						kind = .Spawn,
						parent = spawn_parent.net_id,
						id = s.id,
					},
				)
			}
		}
	}
}

ui_build_popup :: proc(client: ^Client, tile: sim.Map_Pos) {
	pos := rl.GetWorldToScreen2D(map_tile_center(tile), client.camera)

	box(
		id("building-selection-square"),
		{
			position = {.Fixed, pos},
			bounds = {.Window, .Shift, PADDING},
			placement = {origin = {0.5, 0.5}},
			layout = .Grid,
			gap = PADDING,
			cols = 5,
			rows = 5,
			padding = orui.padding(PADDING),
			background_color = ui_color(.SECONDARY),
		},
	)

	p := sim.ents_get(&client.ents, client.bs.src_building)

	for stat, i in client.ents.stats {
		if i == 0 do continue
		if stat.kind != .Building do continue
		if !stat.placable && !client.map_editing.expanded do continue
		if p == sim.NIL_ENT && !client.map_editing.expanded do continue

		BUILD_BUTTON_SIZE :: 64

		if ui_button(
			id("building-selection-square", i),
			{
				width = orui.fixed(BUILD_BUTTON_SIZE),
				height = orui.fixed(BUILD_BUTTON_SIZE),
				background = .NONE,
				focused_color = .NONE,
				padding = orui.Edges{},
				sprite = stat.sprite.id,
			},
		) {
			tcp_send(
				client,
				sim.Client_Cmd {
					kind = .Build,
					pos = map_tile_center(tile),
					id = sim.Ent_Stats_ID(i),
					parent = p.net_id,
					team = client.map_editing.team,
				},
			)

			client.bs = {}
		}
	}
}

ui_edit_popup :: proc(client: ^Client) {
	e := sim.ents_get(&client.ents, client.bs.src_building)

	pos := rl.GetWorldToScreen2D(e.pos, client.camera)

	box(
		id("edit-popup"),
		{
			position = {.Fixed, pos},
			bounds = {.Window, .Shift, PADDING},
			placement = {origin = {0.5, 0.5}},
			layout = .Grid,
			gap = PADDING,
			cols = 2,
			rows = 2,
			padding = orui.padding(PADDING),
			background_color = ui_color(.SECONDARY),
		},
	)

	if ui_icon_button(
		id("edit-popup-delete"),
		ROW_HEIGHT,
		.ICON_EXPLOSION,
		"Delete building",
	) {
		tcp_send(client, sim.Client_Cmd{kind = .Delete, ent = e.net_id})
		client.bs = {}
	}
}

ui_connect_popup :: proc(client: ^Client) {
	se := sim.ents_get(&client.ents, client.bs.src_building)
	de := sim.ents_get(&client.ents, client.bs.dst_building)

	pos := rl.GetWorldToScreen2D(de.pos, client.camera)

	box(
		id("connect-popup"),
		{
			position = {.Fixed, pos},
			bounds = {.Window, .Shift, PADDING},
			placement = {origin = {0.5, 0.5}},
			layout = .Grid,
			gap = PADDING,
			cols = 2,
			rows = 2,
			padding = orui.padding(PADDING),
			background_color = ui_color(.SECONDARY),
		},
	)

	if de.parent != se.id &&
	   ui_icon_button(
		   id("connect-popup-delete"),
		   ROW_HEIGHT,
		   .ICON_FILTER_POINT,
		   "Connect buildings",
	   ) {
		tcp_send(
			client,
			sim.Client_Cmd {
				kind = .Rewire,
				parent = se.net_id,
				ent = de.net_id,
			},
		)
		client.bs = {}
	}

	if de.parent == se.id &&
	   ui_icon_button(
		   id("connect-popup-rewire"),
		   ROW_HEIGHT,
		   .ICON_FILTER_BILINEAR,
		   "Disconnect buildings",
	   ) {
		tcp_send(client, sim.Client_Cmd{kind = .Rewire, ent = de.net_id})
		client.bs = {}
	}
}

ui_build :: proc(client: ^Client) {
	orui.begin(&client.orui_ctx, rl.GetScreenWidth(), rl.GetScreenHeight())

	for b in ([?]rl.MouseButton{.LEFT, .RIGHT}) {
		if rl.IsMouseButtonReleased(b) && b == client.last_handled_button {
			client.last_handled_button = {}
		}
	}

	for &color, vl in client.ui.colors.picker_rgbs {
		hsv := client.ui.colors.picker_hsvs[vl]
		color = ui_color_from_hsv(hsv)
	}
	UI_COLORS = &client.ui.colors.picker_rgbs

	{box(
			orui.id("window"),
			{
				width = orui.grow(),
				height = orui.grow(),
				padding = orui.padding(PADDING),
				direction = .TopToBottom,
				gap = PADDING,
				position = {.Relative, {}},
			},
		)

		stage_snapshot := client.connection_stage

		if stage_snapshot == .Connected {
			rl.SetExitKey(.KEY_NULL)

			ui_game_hud(client)

			box(
				id("game-panel"),
				{
					width = orui.grow(),
					height = orui.grow(),
					position = {.Relative, {}},
				},
			)

			ent := sim.ents_get(&client.ents, client.ent)
			if ent == sim.NIL_ENT && !client.map_editing.expanded {
				ui_ship_selection(client)
			}

			if client.map_editing.expanded {
				ui_map_editor(client)
			}

			if client.content_editing.expanded {
				ui_content_editor(client)
			}

			if pos, ok := client.bs.place_pos.?; ok {
				ui_build_popup(client, pos)
			}

			if client.bs.src_building == client.bs.dst_building &&
			   client.bs.src_building != {} {
				ui_edit_popup(client)
			}

			if sim.ents_is_valid(&client.ents, client.bs.src_building) &&
			   sim.ents_is_valid(&client.ents, client.bs.dst_building) &&
			   client.bs.src_building != client.bs.dst_building {
				ui_connect_popup(client)
			}

			ui_chat(client)
		}

		if stage_snapshot == .Disconnected {
			rl.SetExitKey(.ESCAPE)
			ui_connection_menu(client)
		}
	}

	for ev in client.events {
		switch ev.kind {
		case .Edit_Stat:
			ctx := &client.content_editing

			stats := sim.ents_stats_get(&client.ents, ev.stat)
			ctx.selected = stats.id
			clear(&ctx.edit_name.buf)
			append(&ctx.edit_name.buf, nm.str(&stats.name))
			ctx.stat_edit_state = stats^
		}
	}
	clear(&client.events)
}
