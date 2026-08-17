package client

import "../sim"
import "../util/bit_arr"
import orui "../vendored/orui/src"
import "core:fmt"
import la "core:math/linalg"
import "core:reflect"
import "core:slice"
import "core:sort"
import "core:strings"
import rl "vendor:raylib"

THICKNESS :: 2
CONTROL_SIZE :: 64

UI_Map_Editor :: struct {
	expanded:           bool,
	resizing:           bool,
	map_hash:           sim.Hash,
	changed_terrain:    bit_arr.Bit_Set,
	teams:              [dynamic]sim.Ent_Team,
	brush:              UI_Map_Editor_Brush,
	editing_brush:      bool,
	editing_brush_text: strings.Builder,
	team:               sim.Ent_Team_ID,
	editing_team:       bool,
	color_state:        UI_Color_Picker_State,
	width:              int,
	height:             int,
}

UI_Map_Editor_Brush :: enum int {
	Wall,
	Floor,
	Charger,
	Building,
}

ui_map_editor_destroy :: proc(editor: ^UI_Map_Editor) {
	bit_arr.destroy(editor.changed_terrain)
	delete(editor.teams)
}

ui_map_eats_input :: proc(ui: ^UI_Reactor) -> bool {
	return ui.map_editing.expanded && ui.map_editing.brush != .Building
}

ui_map_editor_sync :: proc(client: ^Client) {
	new_hash: sim.Hash
	sim.hash(client.map_buf, &new_hash)

	ctx := &client.map_editing

	if new_hash != ctx.map_hash {
		ctx.map_hash = new_hash

		bit_arr.destroy(ctx.changed_terrain)
		ctx.changed_terrain = bit_arr.init(
			int(client.ents.width * client.ents.height),
		)

		clear(&ctx.teams)
		append(&ctx.teams, ..client.ents.teams[:])

		ctx.width = client.ents.width
		ctx.height = client.ents.height
	}
}

ui_map_has_changes :: proc(client: ^Client) -> bool {
	context.allocator = context.temp_allocator

	mapa := ui_map_export(client)

	buf := sim.serialize_to_bytes(mapa)

	hash: sim.Hash
	sim.hash(buf, &hash)

	return hash != client.map_editing.map_hash
}

ui_map_export :: proc(client: ^Client) -> (mapa: sim.Map) {
	ctx := &client.map_editing

	context.allocator = context.temp_allocator

	mapa.width = client.ents.width
	mapa.height = client.ents.height
	mapa.sprites = client.ents.sprites

	mapa.tiles = make(
		[]int,
		min(
			sim.map_tile_storage_size(mapa.width, mapa.height),
			bit_arr.mask_len(ctx.changed_terrain.bit_length),
		),
	)

	for i in 0 ..< len(mapa.tiles) {
		mapa.tiles[i] =
			client.ents.mapa.tiles[i] ~ int(ctx.changed_terrain.masks[i])
	}

	if mapa.width != ctx.width || mapa.height != ctx.height {
		old_tiles := bit_arr.Bit_Set {
			raw_data(mapa.tiles),
			mapa.width * mapa.height,
		}
		new_tiles := bit_arr.init(ctx.width * ctx.height)
		for y in 0 ..< min(mapa.height, ctx.height) {
			for x in 0 ..< min(mapa.width, ctx.width) {
				vl := bit_arr.contains_unbounded(old_tiles, y * mapa.width + x)
				bit_arr.set(new_tiles, y * ctx.width + x, vl)
			}
		}
		mapa.width = ctx.width
		mapa.height = ctx.height
		len := sim.map_tile_storage_size(mapa.width, mapa.height)
		mapa.tiles = new_tiles.masks[:len]
	}

	ents: [dynamic]sim.Map_Ent
	append(&ents, sim.Map_Ent{})
	map_ent_to_ent: [dynamic]^sim.Ent
	append(&map_ent_to_ent, sim.NIL_ENT)

	ent_iter := sim.ents_iter(&client.ents)
	o: for e in sim.ents_iter_next(&ent_iter) {
		s := sim.ents_stats_get(&client.ents, e.stats)
		if s.kind != .Building do continue
		pos := sim.map_vec_to_pos(e.pos)
		if pos.x >= mapa.width do continue
		if pos.y >= mapa.height do continue
		append(&map_ent_to_ent, e)
		append(&ents, sim.Map_Ent{stat = e.stats, team = e.team, pos = pos})
	}

	Ctx :: struct {
		map_ents: []sim.Map_Ent,
		ents:     []^sim.Ent,
	}

	ctx_len :: proc(id: sort.Interface) -> int {
		return len(((^Ctx)(id.collection)).ents)
	}

	ctx_swap :: proc(id: sort.Interface, a: int, b: int) {
		cx := (^Ctx)(id.collection)
		cx.ents[a], cx.ents[b] = cx.ents[b], cx.ents[a]
		cx.map_ents[a], cx.map_ents[b] = cx.map_ents[b], cx.map_ents[a]
	}

	ctx_less :: proc(id: sort.Interface, a: int, b: int) -> bool {
		cx := (^Ctx)(id.collection)
		return transmute(u64)cx.ents[a].pos < transmute(u64)cx.ents[b].pos
	}

	cx := Ctx {
		ents     = map_ent_to_ent[:],
		map_ents = ents[:],
	}

	sort.sort(
		sort.Interface {
			len = ctx_len,
			swap = ctx_swap,
			less = ctx_less,
			collection = &cx,
		},
	)

	ent_to_map_ent := make([]int, len(client.ents.slots))

	for e, i in map_ent_to_ent {
		ent_to_map_ent[e.id.index] = i
	}

	for &me, i in ents {
		e := map_ent_to_ent[i]
		if !sim.ents_is_valid(&client.ents, e.parent) {
			continue
		}
		me.parent = ent_to_map_ent[e.parent.index]
	}

	mapa.ents = ents[:]
	mapa.chargers = client.ents.mapa.chargers[:]
	mapa.teams = ctx.teams[:]

	return
}

ui_map_editor :: proc(client: ^Client) {
	ctx := &client.map_editing

	if is_key_pressed(client, .Exit) {
		emit_event(client, .Close_Map_Editor, {priority = 2})
	}

	TEAM_SIZE :: 32

	{box(id("resize-nob"), {layer = 100})
		if !ctx.resizing {
			ctx.resizing = ui_button(
				id("resize-nob-button"),
				{
					width = orui.fixed(TEAM_SIZE),
					height = orui.fixed(TEAM_SIZE),
					position = {
						.Fixed,
						rl.GetWorldToScreen2D(
							{
								f32(ctx.width) * sim.TILE_SIZE,
								f32(ctx.height) * sim.TILE_SIZE,
							},
							client.camera,
						),
					},
					icon = .ICON_RESIZE,
				},
			)
		} else {
			ctx.resizing ~= rl.IsMouseButtonReleased(.LEFT)
		}
	}

	{box(
			id("map-editor-view"),
			{width = orui.grow(), height = orui.grow(), layer = -200},
		)
		if ctx.resizing {
			ui_label(
				id("map-editor-size-label"),
				{
					label = fmt.tprintf(
						"%vx%v - %v%%x%v%%",
						ctx.width,
						ctx.height,
						ctx.width * 100 / client.ents.width,
						ctx.height * 100 / client.ents.height,
					),
				},
			)
		}
	}

	box(
		id("map-editor-controls"),
		{
			direction = .TopToBottom,
			gap = PADDING,
			padding = orui.padding(PADDING),
			background_color = ui_color(.SECONDARY_FAINT),
			layer = 100,
		},
	)

	deselected := ui_color_slot(.SLOT1, rl.ColorAlpha(rl.WHITE, 0.8))

	tile_brashes := [?]UI_Map_Editor_Brush{.Wall, .Floor, .Building}
	tile_sprites := slice.enumerated_array(&client.ents.sprites)

	for brush, i in tile_brashes {
		selected := ctx.brush == brush

		if ui_button(
			id("map-editor-brush-select", i),
			{
				label = selected ? "" : reflect.enum_string(brush),
				width = orui.fixed(CONTROL_SIZE),
				height = orui.fixed(CONTROL_SIZE),
				sprite = tile_sprites[i],
				padding = orui.Edges{},
				background = .NONE,
				focused_color = .NONE,
				foreground = selected ? .FOREGROUND : deselected,
				border_color = selected ? .PRIMARY : .NONE,
				border = 1,
				icon = selected ? .ICON_PENCIL : .ICON_NONE,
				tooltip = reflect.enum_name_from_value(brush) or_else "",
			},
		) {
			emit_event(client, .Select_Brush, {brush = brush})
		}

		if ctx.editing_brush && selected {
			res, should_close := ui_sprite_select(
				client,
				id("mape-editor-brus-select", i),
				&ctx.editing_brush_text,
				{width = orui.fit()},
			)

			ctx.editing_brush &= !should_close

			if res >= 0 {
				tile_sprites[i] = ui_sprite_idx_to_id(client, res)
				ctx.editing_brush = false
			}
		}
	}

	{box(
			id("map-editor-teams"),
			{
				layout = .Grid,
				cols = 2,
				rows = i32((len(ctx.teams) + 1 + 1) / 2),
			},
		)

		prefix := min(1, len(client.ents.teams))

		all_teams := make([dynamic]^sim.Ent_Team, context.temp_allocator)

		for &team, i in ctx.teams[prefix:] {
			tid := sim.Ent_Team_ID(prefix + i)
			selected := ctx.team == tid
			editing := ctx.editing_team && selected

			if !editing {
				if ui_button(
					id("map-editor-team", i),
					{
						width = orui.fixed(TEAM_SIZE),
						height = orui.fixed(TEAM_SIZE),
						background = ui_color_slot(
							.SLOT2,
							rl.ColorAlpha(get_color(team.color), 0.8),
						),
						focused_color = ui_color_slot(
							.SLOT1,
							get_color(team.color),
						),
						icon = selected ? .ICON_PENCIL_BIG : .ICON_NONE,
					},
				) {
					emit_event(client, .Select_Map_Team, {team = tid})
				}
				continue
			}

			box(
				id("map-editor-team-selected", i),
				{
					width = orui.fixed(TEAM_SIZE),
					height = orui.fixed(TEAM_SIZE),
					gap = PADDING,
					position = {.Relative, {}},
				},
			)

			box(
				id("map-editor-team-selected-options", i),
				{
					background_color = ui_color(.SECONDARY),
					position = {.Absolute, {}},
					layer = 300,
					bounds = {.Window, .Shift, PADDING},
				},
			)

			if ui_clicked_off() {
				ctx.editing_team = false
			}

			{box(
					id("map-editor-team-slected-controls"),
					{direction = .TopToBottom},
				)

				{box(
						id("map-editor-team-selected-color", i),
						{
							width = orui.fixed(TEAM_SIZE),
							height = orui.fixed(TEAM_SIZE),
							background_color = get_color(team.color),
						},
					)}

				if ui_icon_button(
					id("map-editor-team-selected-delete", i),
					TEAM_SIZE,
					.ICON_BIN,
					"Delete team",
				) {
					emit_event(client, .Delete_Team, {team_idx = prefix + i})
				}

				if ui_icon_button(
					id("map-editor-team-selected-edit", i),
					TEAM_SIZE,
					icon = .ICON_CROSS_SMALL,
					tooltip = "Close team editor",
				) {
					emit_event(client, .Close_Team_Editor, {})
				}
			}

			ui_color_picker(
				id("map-editor-team-selected-color"),
				&ctx.color_state,
				{
					width = orui.fixed(TEAM_SIZE * 5),
					height = orui.fixed(TEAM_SIZE * 5),
					dest_color = &team.color,
				},
			)
		}

		if ui_button(
			id("map-editor-team-add"),
			{
				label = "+",
				width = orui.fixed(TEAM_SIZE),
				height = orui.fixed(TEAM_SIZE),
			},
		) {
			emit_event(client, .Add_Team, {})
		}
	}

	{box(
			id("map-editor-teams"),
			{
				layout = .Grid,
				cols = 2,
				rows = i32((len(ctx.teams) + 1 + 1) / 2),
			},
		)

		if ui_icon_button(
			id("map-export"),
			TEAM_SIZE,
			.ICON_FILE_EXPORT,
			"Export map to a file",
		) {

		}

		if ui_icon_button(
			id("map-save"),
			TEAM_SIZE,
			.ICON_FILE_EXPORT,
			"Export map to a file",
		) {

		}
	}
}

ui_map_editor_update :: proc(client: ^Client) {
	ctx := &client.map_editing

	ctx.expanded = false
	defer ctx.expanded = true

	if ctx.changed_terrain.bit_length !=
	   client.ents.width * client.ents.height {
		bit_arr.destroy(ctx.changed_terrain)
		ctx.changed_terrain = bit_arr.init(
			client.ents.width * client.ents.height,
		)
	}

	mouse_pos := client_mouse_pos(client)
	pos := sim.map_vec_to_pos(mouse_pos)
	pos = la.clamp(
		pos,
		sim.Map_Pos{0, 0},
		sim.Map_Pos{client.ents.width, client.ents.height} - 1,
	)

	if !ui_is_interacting(client) && ctx.brush != .Building {
		rl.DrawRectangleRec(map_tile_rect(pos), rl.ColorAlpha(rl.WHITE, 0.5))
	}

	server_current := sim.map_tile_is_solid(&client.ents, pos)
	client_current := bit_arr.contains_unbounded(
		ctx.changed_terrain,
		pos.x + pos.y * client.ents.width,
	)

	if is_key_down(&client.ui, .Map_Place) {
		#partial input: switch ctx.brush {
		case .Building:
			if server_current ~ client_current do break
			if client.bs == {} {
				append(&client.captured_key_binds, MousetButton.LEFT)
				client.bs.place_pos = pos
			}
		case .Wall, .Floor:
			has_building := false

			if sim.ents_building_get(&client.ents, pos) != sim.NIL_ENT do break

			server_current ~= ctx.brush == .Wall
			bit_arr.set_unbounded(
				ctx.changed_terrain,
				pos.x + pos.y * client.ents.width,
				server_current,
			)
		case:
		}
	}

	if is_key_down(&client.ui, .Map_Erase) {
		#partial switch ctx.brush {
		case .Building:
		case .Wall, .Floor:
			bit_arr.set(
				ctx.changed_terrain,
				pos.x + pos.y * client.ents.width,
				false,
			)
		}
	}

	if sim.ents_get(&client.ents, client.ent) == sim.NIL_ENT {
		CAMERA_SPEED :: 500

		client.camera.target +=
			sim.input_movement_dir(client.applied_input.keys) *
			(CAMERA_SPEED / client.camera.zoom * client.ents.delta)

		client.camera.target = la.clamp(
			client.camera.target,
			sim.Vec{0, 0},
			sim.Vec{f32(client.ents.width), f32(client.ents.height)} *
			sim.TILE_SIZE,
		)
	}

	if ctx.resizing {
		end_pos := sim.map_vec_to_pos(client_mouse_pos(client))
		ctx.width = end_pos.x
		ctx.height = end_pos.y
	}
}

draw_crossed_rect :: proc(
	rect: rl.Rectangle,
	thickness: f32,
	color: rl.Color,
) {
	rl.DrawRectangleLinesEx(rect, thickness, color)

	mix := rect.x + thickness
	miy := rect.y + thickness
	max := rect.x + rect.width - thickness
	may := rect.y + rect.height - thickness

	rl.DrawLineEx({mix, miy}, {max, may}, thickness, color)

	rl.DrawLineEx({mix, may}, {max, miy}, thickness, color)
}

ui_sprite_id_to_idx :: proc(
	client: ^Client,
	id: sim.Asset_ID,
) -> sim.Asset_Idx {
	return sim.asset_id_to_idx(client.assets[:], id)
}

ui_sprite_idx_to_id :: proc(
	client: ^Client,
	idx: sim.Asset_Idx,
) -> sim.Asset_ID {
	return sim.asset_idx_to_id(client.assets[:], idx)
}

map_draw :: proc(client: ^Client) {
	ctx := &client.map_editing

	for y in 0 ..< client.ents.height {
		for x in 0 ..< client.ents.width {
			building := client.ents.buildings[x + y * client.ents.width]
			rect := map_tile_rect({x, y})

			is_wall := sim.map_tile_is_solid(&client.ents, {x, y})
			sprite :=
				is_wall ? client.ents.sprites[.Wall] : client.ents.sprites[.Floor]

			if is_wall do rl.DrawRectangleRec(rect, rl.BLACK)
			texture, region := ui_get_sprite(&client.ui, sprite)
			rl.DrawTexturePro(texture, region, rect, {}, 0, rl.WHITE)

			e := &client.ents.slots[building]
			t := sim.ents_team_get(&client.ents, e.team)
			if sim.ent_is_alive(e) {
				rl.DrawRectangleRec(
					map_tile_rect({x, y}),
					rl.ColorAlpha(get_color(t.color), 0.5),
				)
			}

			if ctx.expanded {
				if bit_arr.contains_unbounded(
					ctx.changed_terrain,
					x + y * client.ents.width,
				) {
					opposite_sprite :=
						is_wall ? client.ents.sprites[.Floor] : client.ents.sprites[.Wall]
					texture, region := ui_get_sprite(
						&client.ui,
						opposite_sprite,
					)
					rl.DrawTexturePro(
						texture,
						region,
						rect,
						{},
						0,
						rl.ColorAlpha(rl.WHITE, 0.7),
					)

					mix := rect.x
					miy := rect.y
					max := rect.x + rect.width
					may := rect.y + rect.height
					tck := THICKNESS / client.camera.zoom / 2

					dirs := [?]sim.Map_Pos{{-1, 0}, {0, -1}, {1, 0}, {0, 1}}
					positions := [?][2]sim.Vec {
						{{mix + tck, miy}, {mix + tck, may}},
						{{mix, miy + tck}, {max, miy + tck}},
						{{max - tck, may}, {max - tck, miy}},
						{{max, may - tck}, {mix, may - tck}},
					}
					for dir, i in dirs {
						pos: sim.Map_Pos = {x, y} + dir
						if !bit_arr.contains_unbounded(
							ctx.changed_terrain,
							pos.x + pos.y * client.ents.width,
						) {
							rl.DrawLineEx(
								positions[i][0],
								positions[i][1],
								THICKNESS / client.camera.zoom,
								ui_color(.PRIMARY),
							)
						}
					}
				}
			}
		}
	}

	for charger in client.ents.chargers {
		rl.DrawRectangleRec(
			map_tile_rect(
				charger.pos - charger.radius,
				charger.radius * 2 + 1,
			),
			rl.ColorAlpha(rl.WHITE, 0.5),
		)
	}

	if ctx.resizing {
		end_pos := sim.map_vec_to_pos(client_mouse_pos(client))
		rl.DrawRectangleLinesEx(
			{
				0,
				0,
				f32(end_pos.x) * sim.TILE_SIZE,
				f32(end_pos.y) * sim.TILE_SIZE,
			},
			2 / client.camera.zoom,
			ui_color(.PRIMARY),
		)
	}

	if ctx.width != client.ents.width || ctx.height != client.ents.height {

		rl.DrawRectangleLinesEx(
			{
				0,
				0,
				f32(ctx.width) * sim.TILE_SIZE,
				f32(ctx.height) * sim.TILE_SIZE,
			},
			2 / client.camera.zoom,
			ui_color(.PRIMARY),
		)
	}
}

map_tile_rect :: proc(pos: sim.Map_Pos, size: int = 1) -> rl.Rectangle {
	return {
		f32(pos.x * sim.TILE_SIZE),
		f32(pos.y * sim.TILE_SIZE),
		f32(sim.TILE_SIZE * size),
		f32(sim.TILE_SIZE * size),
	}
}
