package client

import "../sim"
import "../util/b58"
import "../util/nm"
import "../util/packer"
import orui "../vendored/orui/src"
import "base:runtime"
import "core:fmt"
import "core:hash"
import "core:math"
import "core:reflect"
import "core:sort"
import "core:strconv"
import "core:strings"
import "pure"
import rl "vendor:raylib"

emit_set_event :: proc(
	client: ^Client,
	slot: ^$T,
	value: T,
	base: UI_Event = {},
) {
	base := base
	base.kind = .Set_Value
	base.set_target = {slot, typeid_of(T)}
	base.set_value = {new_clone(value, context.temp_allocator), typeid_of(T)}
	emit_event(client, .Set_Value, base)
}

ui_content_editor :: proc(client: ^Client) {
	ctx := &client.ui.content_editor

	if is_key_pressed(client, .Exit) {
		emit_set_event(client, &ctx.expanded, false, {priority = 3})
	}

	box(
		id("content-editor-centerer"),
		{
			height = orui.grow(),
			width = orui.grow(),
			align_main = .Center,
			position = {.Absolute, {}},
			layer = 100,
		},
	)

	if orui.hovered() && rl.IsMouseButtonPressed(.LEFT) {
		append(&client.captured_key_binds, MousetButton.LEFT)
		if !ctx.expanded do ctx.selected = 0
		ctx.expanded = false
		return
	}

	ce := id("content-editor")
	box(
		ce,
		{
			height = orui.grow(),
			width = orui.fixed(500),
			scroll = orui.scroll(.Vertical),
			direction = .TopToBottom,
			gap = PADDING,
			padding = orui.padding(PADDING * 2),
			background_color = ui_color(.SECONDARY_FAINT),
			clip = {.Intersect, {}},
		},
	)

	stats := sim.ents_stats_get(&client.ents, ctx.selected)
	if stats == sim.NIL_STATS {
		prev_scroll := orui.scroll_offset().y
		if ctx.prev_scroll != 0 {
			orui.set_scroll_offset(ctx.prev_scroll)
			ctx.prev_scroll = 0
		}

		query, confirmed := ui_text_input(
			id("content-editor-search"),
			&ctx.search,
			{
				width = orui.grow(),
				height = orui.fixed(ROW_HEIGHT),
				placeholder = "fuzzy search...",
				border = 1,
			},
		)

		prefix := min(1, len(client.ents.stats))
		stat_slots := client.ents.stats[prefix:]

		Slot :: struct {
			using ref: ^sim.Ent_Stats,
			score:     int,
		}

		order := make([]Slot, len(stat_slots), context.temp_allocator)
		for &o, i in order {
			o.ref = &stat_slots[i]
			o.score = pure.fuzzy_rank(nm.str(&o.name), query)
		}

		if len(query) != 0 {
			sort.merge_sort_proc(order, proc(a: Slot, b: Slot) -> int {
				return sort.compare_ints(b.score, a.score)
			})
		}

		{box(
				id("stat-selector-table"),
				{
					layout = .Grid,
					cols = 2,
					rows = 10000,
					width = orui.grow(),
					col_sizes = {orui.grow(), {}},
					gap = PADDING,
				},
			)

			for stats, i in order {
				name := nm.str(&stats.name)
				matched_chars := pure.fuzzy_rank_new_bitset(name, query)

				if ui_button(
					   id("stat-selector", i),
					   {
						   label = name,
						   width = orui.grow(),
						   height = orui.fixed(ROW_HEIGHT),
						   background = .SECONDARY,
						   focused_color = .PRIMARY,
						   custom_dc = draw_call_init_text_highlight(
							   matched_chars,
						   ),
					   },
				   ) ||
				   (i == 0 && confirmed) {
					ctx.prev_scroll = prev_scroll
					orui.set_scroll_offset(ce, 0)
					emit_event(client, .Select_Stat, {stats = stats.id})
				}

				if ui_icon_button(
					id("stat-selector-delete", i),
					ROW_HEIGHT,
					.ICON_BIN,
					"Delete the stats.",
				) {
					pure.tcp_send(
						client,
						sim.Client_Content_Action {
							type = .Delete_Stat,
							stats = {id = stats.id},
						},
					)
				}
			}
		}

		if ctx.create_stat {
			box(
				id("create-stat-frame"),
				{
					background_color = ui_color(.SECONDARY_FAINT),
					width = orui.grow(),
					gap = PADDING,
				},
			)

			text, confirmed := ui_text_input(
				id("create-stat-name-input"),
				&ctx.create_stat_name,
				{
					width = orui.grow(),
					height = orui.fixed(ROW_HEIGHT),
					placeholder = "name...",
					border = 1,
				},
			)

			already_taken := len(text) == 0
			for &stat in client.ents.stats {
				already_taken |= nm.str(&stat.name) == text
			}

			if ui_button(
				   id("create-stat-confirm"),
				   {
					   width = orui.fixed(ROW_HEIGHT),
					   height = orui.fixed(ROW_HEIGHT),
					   icon = .ICON_FILE_SAVE_CLASSIC,
					   disabled = already_taken,
				   },
			   ) ||
			   confirmed {
				pure.tcp_send(
					client,
					sim.Client_Content_Action {
						type = .Create,
						stats = {name = nm.from_str(text)},
					},
				)
			}

			ctx.create_stat ~=
				ui_icon_button(
					id("create-stat-close"),
					ROW_HEIGHT,
					.ICON_CROSS,
					"Cancel new stat",
				) ||
				confirmed
		} else {
			ctx.create_stat ~= ui_button(
				id("create-stat-expand"),
				{
					label = "+",
					width = orui.grow(),
					height = orui.fixed(ROW_HEIGHT),
				},
			)
		}

		ui_file_upload(client)
	} else {
		selector: {
			box(id("stat-selector-row"), {width = orui.grow(), gap = PADDING})

			text, _ := ui_text_input(
				id("stat-selector-name-edit"),
				&ctx.edit_name,
				{
					width = orui.grow(),
					height = orui.fixed(ROW_HEIGHT),
					placeholder = "name...",
					border = 1,
					dont_autofocus = true,
				},
			)

			ctx.stat_edit_state.name = nm.from_str(text)

			if !reflect.equal(stats^, ctx.stat_edit_state, true) {
				if ui_icon_button(
					   id("stat-selector-save"),
					   ROW_HEIGHT,
					   .ICON_FILE_OPEN,
					   "Save changes",
				   ) ||
				   is_key_pressed(client, .Save) {
					emit_event(client, .Apply_Content_Changes, {priority = 2})
				}
			}

			if ui_icon_button(
				   id("stat-selector-close"),
				   ROW_HEIGHT,
				   .ICON_CROSS,
				   "Close editor",
			   ) ||
			   is_key_pressed(client, .Exit) {
				emit_set_event(client, &ctx.selected, 0, {priority = 4})
			}
		}

		query, confirmed := ui_text_input(
			id("stat-prop-search"),
			&ctx.prop_search,
			{
				height = orui.fixed(ROW_HEIGHT),
				width = orui.grow(),
				placeholder = "fuzzy-search-properties... F to select...",
				dont_autofocus = true,
			},
		)

		just_focused :=
			orui.current_context.focus_id == orui.current_context.current_id &&
			orui.current_context.focus_id != orui.current_context.prev_focus_id

		if is_key_pressed(client, .Select_Finder) {
			emit_event(
				client,
				.Focus,
				{priority = 3, carret_index = len(ctx.prop_search.buf)},
			)
		}

		box(
			id("struct-editor-frame"),
			{
				background_color = ui_color(.SECONDARY_FAINT),
				width = orui.grow(),
				padding = orui.padding(PADDING),
				direction = .TopToBottom,
				gap = PADDING,
			},
		)

		if just_focused {
			ctx.stat_editor.current_field = 0
			ctx.stat_editor.last_field = 0
		}

		if len(query) != 0 {
			Field_Slot :: struct {
				score: int,
				name:  string,
				value: any,
				tag:   reflect.Struct_Tag,
			}

			props := make([dynamic]Field_Slot, context.temp_allocator)
			name_stack := make([dynamic]string, context.temp_allocator)

			collect_props(ctx.stat_edit_state, "", &name_stack, &props)

			for &prop in props {
				prop.score = pure.fuzzy_rank(prop.name, query)
			}

			sort.merge_sort_proc(
				props[:],
				proc(a: Field_Slot, b: Field_Slot) -> int {
					return sort.compare_ints(b.score, a.score)
				},
			)

			if confirmed {
				clear(&ctx.stat_editor.string_field.buf)
			}

			for prop, i in props {
				box(id("fuzzy-prop-row", i), {width = orui.grow()})
				matched_chars := pure.fuzzy_rank_new_bitset(prop.name, query)
				name_pressed :=
					ui_label(
						id("fuzzy-prop-name", i),
						{
							label = prop.name,
							custom_dc = draw_call_init_text_highlight(
								matched_chars,
							),
							background = .NONE,
						},
					) ||
					confirmed
				confirmed = false

				ui_content_field_edit(
					client,
					prop.value,
					{
						orui.id("fuzzy-prop-value", i),
						orui.id("fuzzy-prop-value-edit", i),
						name_pressed,
						prop.tag,
						orui.to_id("stat-prop-search"),
					},
				)
			}

			collect_props :: proc(
				value: any,
				tag: reflect.Struct_Tag,
				name_stack: ^[dynamic]string,
				props: ^[dynamic]Field_Slot,
			) {
				if reflect.is_struct(type_info_of(value.id)) &&
				   value.id != sim.Ent_Stats_ID &&
				   value.id != sim.Asset_ID {
					for field in reflect.struct_fields_zipped(value.id) {

						if vl, ok := reflect.struct_tag_lookup(
							field.tag,
							"gam",
						); ok && strings.contains(vl, "hidden") {
							continue
						}

						append(name_stack, field.name)
						value := reflect.struct_field_value(value, field)
						collect_props(value, field.tag, name_stack, props)
						pop(name_stack)
					}
				} else {
					append(
						props,
						Field_Slot {
							name = strings.join(
								name_stack[:],
								".",
								context.temp_allocator,
							),
							tag = tag,
							value = value,
						},
					)
				}
			}
		} else {
			ctx.stat_editor.root = id("stat-struct-editor")
			ctx.stat_editor.eidt_root = id("edit-struct-editor")
			ui_stat_editor(
				client,
				&ctx.stat_editor,
				ctx.stat_edit_state,
				stats^,
			)
		}
	}
}

ui_file_upload :: proc(client: ^Client) {
	ctx := &client.upload

	area_id := id("drop-sprite-area")

	rect := orui.bounding_rect()
	hovered := rl.CheckCollisionPointRec(rl.GetMousePosition(), rect)

	load: if hovered && rl.IsFileDropped() {

		raw_files := rl.LoadDroppedFiles()
		defer rl.UnloadDroppedFiles(raw_files)
		files := raw_files.paths[:raw_files.count]

		pure.prepare_upload(client, files)
	}

	box(
		area_id,
		{
			border = orui.border(1),
			border_color = ui_color(.PRIMARY),
			background_color = ui_color(
				hovered && len(ctx.assets) == 0 ? .SECONDARY : .PRIMARY_FAINT,
			),
			width = orui.grow(),
			height = {.Fit, 0, 200, 0},
			padding = orui.padding(PADDING),
			gap = PADDING,
			direction = .TopToBottom,
		},
	)

	all_uploaded := true

	if len(ctx.assets) == 0 {
		msg := "Drag and drop file here to upload to\n the server (*.png)"

		ui_label(
			id("drop-asset-area-text"),
			{
				label = msg,
				background = .NONE,
				width = orui.grow(),
				height = orui.grow(),
			},
		)
	} else {
		files := rl.LoadDroppedFiles()

		{box(
				id("drop-assets-upload-table"),
				{
					width = orui.grow(),
					layout = .Grid,
					col_sizes = {
						orui.grow(),
						orui.fit(),
						orui.fit(),
						orui.fit(),
					},
					gap = PADDING,
					cols = 4,
					rows = i32(len(ctx.assets)),
				},
			)

			for &asset, i in ctx.assets {
				if asset.base.hash == {} {
					box(
						id("asset-uploaded-row"),
						{col_span = 4, width = orui.grow()},
					)
					ui_label(
						id("asset-loading", i),
						{
							label = "loading...",
							height = orui.fixed(ROW_HEIGHT),
							width = orui.grow(),
						},
					)
					continue
				}

				if asset.uploaded {
					box(
						id("asset-uploaded-row"),
						{col_span = 4, width = orui.grow()},
					)
					ui_label(
						id("asset-uploaded", i),
						{
							label = "uploaded",
							foreground = .SUCCESS,
							height = orui.fixed(ROW_HEIGHT),
							width = orui.grow(),
						},
					)
					continue
				}

				all_uploaded = false

				if asset.issue != "" {
					ui_label(id("issue-idk", i), {label = asset.issue})
					continue
				}

				ui_label(
					id("dropped-file-name", i),
					{
						label = nm.str(&asset.base.name),
						height = orui.fixed(ROW_HEIGHT),
						width = orui.grow(),
						align = .Start,
					},
				)

				EXT_TO_ICON := [sim.Asset_Type]rl.GuiIconName {
					.Map    = .ICON_GRID,
					.Sprite = .ICON_FILETYPE_IMAGE,
				}

				ui_icon_button(
					id("dropped-file-type", i),
					ROW_HEIGHT,
					EXT_TO_ICON[asset.base.type],
					sim.EXT_BY_TYPE[asset.base.type],
					{background = .SECONDARY},
				)

				number := asset.base.size
				label := "b"
				switch asset.base.size {
				case 0 ..< 1 << 10:
				case 1 << 10 ..< 1 << 20:
					label = "k"
					number /= 1 << 10
				case 1 << 20 ..< 1 << 30:
					label = "m"
					number /= 1 << 20
				}

				ui_label(
					id("dropped-file-size", i),
					{
						label = fmt.tprint(number, label, sep = ""),
						height = orui.fixed(ROW_HEIGHT),
						width = orui.grow(),
					},
				)

				ui_label(
					id("dropped-file-hash", i),
					{
						label = b58.encode(asset.base.hash[:])[:8],
						height = orui.fixed(ROW_HEIGHT),
						width = orui.grow(),
					},
				)
			}
		}

		box(
			id("drop-assets-upload-spacer"),
			{
				height = orui.grow(),
				width = orui.grow(),
				direction = .TopToBottom,
			},
		)

		{box(
				id("drop-assets-shift"),
				{height = orui.grow(), width = orui.grow()},
			)}

		box(
			id("drop-assets-control-row"),
			{width = orui.grow(), gap = PADDING},
		)

		if ui_button(
			id("drop-assets-upload-button"),
			{
				label = "upload",
				width = orui.grow(),
				background = .SECONDARY,
				focused_color = .PRIMARY,
				disabled = all_uploaded,
			},
		) {
			pure.upload_assets(client, init = true)
		}

		if ui_button(
			id("drop-assets-clear-button"),
			{
				label = "clear",
				width = orui.grow(),
				background = .SECONDARY,
				focused_color = .PRIMARY,
			},
		) {
			ctx.assets = {}
		}
	}
}

// TODO(low): this should not be a select, showing more sprites on the screen
// is more usefull
ui_sprite_select :: proc(
	client: ^Client,
	uid: orui.Id,
	field: ^strings.Builder,
	config: Select_Config = {},
) -> (
	sim.Asset_Idx,
	bool,
) {
	config := config
	config.count = len(client.ui.sheet.frames)
	config.ctx = client
	config.virt = Virt_Config {
		item_height = CONTROL_SIZE,
	}
	config.name_of = proc(ctx: rawptr, i: int) -> string {
		client := (^Client)(ctx)
		if i == 0 {return "<none>"}
		return nm.str(&client.ui.sheet.frames[i].name)
	}
	config.build_of = proc(
		ctx: rawptr,
		uid: orui.Id,
		name: string,
		i: int,
	) -> bool {
		client := (^Client)(ctx)
		if i == 0 do return ui_select_default_build_of(ctx, uid, name, i)

		return ui_button(
			id("image", uid),
			{
				label = nm.str(&client.ui.sheet.frames[i].name),
				width = orui.fixed(CONTROL_SIZE),
				height = orui.fixed(CONTROL_SIZE),
				sprite = sim.asset_idx_to_id(
					client.assets[:],
					sim.Asset_Idx(i),
				),
				background = .SECONDARY,
				padding = orui.padding(PADDING),
			},
		)
	}
	idx, close := ui_select(uid, field, config)
	return sim.Asset_Idx(idx), close
}

ui_stat_editor :: proc(
	client: ^Client,
	seb: ^Stat_Editor_State,
	edited: any,
	original: any,
) {
	assert(edited.id == original.id)

	info := type_info_of(reflect.typeid_base(edited.id)).variant.(runtime.Type_Info_Struct)

	expanded_count: i32 = 0
	for i in 0 ..< info.field_count {
		sub_root := orui.to_id(seb.root, i)
		for exp in seb.expanded_substructs {
			if sub_root == exp do expanded_count += 1
		}
	}

	box(
		id("struct-editor-grid", seb.root),
		{
			layout = .Grid,
			padding = {left = PADDING * 4 * f32(seb.depth)},
			width = orui.grow(),
			cols = 2,
			col_span = 2,
			col_sizes = {orui.fit(), orui.grow()},
			rows = info.field_count + expanded_count,
		},
	)

	for field, i in reflect.struct_fields_zipped(edited.id) {
		name := field.name
		type := field.type
		tag := field.tag

		if vl, ok := reflect.struct_tag_lookup(tag, "gam");
		   ok && strings.contains(vl, "hidden") {
			continue
		}

		sub_root := orui.to_id(seb.root, i)
		sub_root_edit := orui.to_id(seb.eidt_root, i)
		_, is_struct := reflect.type_info_base(type).variant.(runtime.Type_Info_Struct)
		is_struct &= type.id != sim.Ent_Stats_ID
		is_struct &= type.id != sim.Asset_ID

		dest := reflect.struct_field_value(edited, field)
		original := reflect.struct_field_value(original, field)

		idx := -1
		for exp, i in seb.expanded_substructs {
			if exp == sub_root do idx = i
		}

		expanded := idx >= 0

		display_name, _ := strings.replace_all(
			name,
			"_",
			"-",
			context.temp_allocator,
		)
		display_name = strings.join(
			{display_name, ":"},
			"",
			context.temp_allocator,
		)

		differs := !reflect.equal(
			dest,
			original,
			including_indirect_array_recursion = true,
		)

		editing := seb.current_field == sub_root_edit

		name_pressed := ui_label(
			id("struct-editor-field-name", sub_root),
			{
				label = display_name,
				height = orui.fixed(HEIGHT),
				background = differs ? .PRIMARY_FAINT : .NONE,
			},
		)

		if is_struct {
			if ui_button(
				   id("struct-editor-value-elipsis", sub_root),
				   {
					   label = !expanded ? "..." : "-",
					   width = orui.grow(),
					   height = orui.fixed(HEIGHT),
					   align = orui.ContentAlignment.Start,
					   background = .NONE,
					   focused_color = .PRIMARY,
				   },
			   ) ||
			   name_pressed {
				if !expanded {
					append(&seb.expanded_substructs, sub_root)
				} else {
					unordered_remove(&seb.expanded_substructs, idx)
				}
			}

			if expanded {
				seb.depth += 1
				prev_root := seb.root
				prev_root_edit := seb.eidt_root
				seb.root = id("nested-struct-editor", sub_root)
				seb.eidt_root = id("edit-nested-struct-editor", sub_root_edit)
				ui_stat_editor(client, seb, dest, original)
				seb.depth -= 1
				seb.eidt_root = prev_root_edit
				seb.root = prev_root
			}

			continue
		}

		ui_content_field_edit(
			client,
			dest,
			{sub_root, sub_root_edit, name_pressed, tag, 0},
		)
	}
}

Content_Field_Ctx :: struct {
	sub_root:        orui.Id,
	sub_root_edit:   orui.Id,
	name_pressed:    bool,
	tag:             reflect.Struct_Tag,
	return_focus_to: orui.Id,
}

ui_content_field_edit :: proc(
	client: ^Client,
	dest: any,
	ctx: Content_Field_Ctx,
) {
	dest := dest
	seb := &client.content_editor.stat_editor
	sub_root := ctx.sub_root
	sub_root_edit := ctx.sub_root_edit
	editing := seb.current_field == sub_root_edit
	name_pressed := ctx.name_pressed
	tag := ctx.tag

	canceled_focus := false
	defer if canceled_focus {
		ui_text_focus(ctx.return_focus_to)
	}

	if !editing {
		switch &v in dest {
		case sim.Asset_ID:
			index := sim.asset_id_to_idx(client.assets[:], v)

			if index >= 0 && int(index) < len(client.ui.sheet.frames) {
				dest = nm.str(&client.ui.sheet.frames[index].name)
				if index == 0 do dest = "<none>"
			} else {
				dest = "<invalid>"
			}
		case sim.Ent_Stats_ID:
			if int(v) < len(client.ents.stats) {
				dest = nm.str(&client.ents.stats[v].name)
				if v == 0 do dest = "<none>"
			} else {
				dest = "<invalid>"
			}
		}
	}

	value := fmt.tprint(dest)

	if v, ok := &dest.(bool); ok {
		v^ ~=
			ui_button(
				id("struct-editor-checkbox", sub_root),
				{
					width = orui.fixed(HEIGHT - 2),
					height = orui.fixed(HEIGHT - 2),
					toggle = v^,
					border = 1,
					border_color = .PRIMARY,
					background = .SECONDARY,
					focused_color = .PRIMARY_FAINT,
					margin = orui.margin(1),
				},
			) ||
			name_pressed
		canceled_focus = name_pressed
		return
	}

	if v, ok := &dest.(sim.Color); ok && !editing {
		if ui_button(
			   id("struct-editor-color-value", sub_root),
			   {
				   width = orui.grow(),
				   height = orui.fixed(HEIGHT),
				   background = ui_color_slot(.SLOT1, get_color(v^)),
				   focused_color = .PRIMARY,
				   border = 1,
				   border_color = .PRIMARY,
			   },
		   ) ||
		   name_pressed {
			seb.current_field = sub_root_edit
		}
		return
	}

	if !editing {
		if ui_button(
			   id("struct-editor-field-value", sub_root),
			   {
				   label = value,
				   width = orui.grow(),
				   height = orui.fixed(HEIGHT),
				   align = orui.ContentAlignment.Start,
				   background = .NONE,
				   focused_color = .PRIMARY,
			   },
		   ) ||
		   name_pressed {
			seb.current_field = sub_root_edit
		}
		return
	}

	initial_select := seb.current_field != seb.last_field
	seb.last_field = seb.current_field

	if initial_select {
		clear(&seb.string_field.buf)
	}

	edit: switch &v in dest {
	case sim.Ent_Type:
		res, should_close := ui_select_enum(
			id("kind-picker"),
			&seb.string_field,
			sim.Ent_Type,
		)

		if should_close {
			seb.current_field = 0
		}

		if res, ok := res.?; ok {
			v = res
			seb.current_field = 0
			seb.last_field = 0
		}

		canceled_focus = should_close
	case sim.Asset_ID:
		res, should_close := ui_sprite_select(
			client,
			id("sprite-picker", sub_root),
			&seb.string_field,
		)

		if should_close {
			seb.current_field = 0
		}

		if res >= 0 {
			v = sim.asset_idx_to_id(client.assets[:], res)
			seb.current_field = 0
			seb.last_field = 0
		}
	case sim.Ent_Stats_ID:
		res, should_close := ui_select(
			id("ent-ref-picker", sub_root),
			&seb.string_field,
			{
				count = len(client.ents.stats),
				ctx = client,
				name_of = proc(ctx: rawptr, i: int) -> string {
					client := (^Client)(ctx)
					if i == 0 {return "<none>"}
					return nm.str(&client.ents.stats[i].name)
				},
			},
		)

		if should_close {
			seb.current_field = 0
		}

		if res >= 0 {
			v = sim.Ent_Stats_ID(res)
			seb.current_field = 0
			seb.last_field = 0
		}
	case sim.Color:
		box(
			id("ent-color-picker-anchor", sub_root),
			{
				width = orui.grow(),
				height = orui.fixed(HEIGHT),
				position = {.Relative, {}},
				background_color = get_color(v),
			},
		)

		box(
			id("ent-color-picker-popup", sub_root),
			{
				position = {.Absolute, {}},
				bounds = {.Window, .Flip, {}},
				layer = 100,
				placement = orui.placement(.BottomLeft, .TopLeft),
			},
		)

		if ui_clicked_off() {
			seb.current_field = 0
		}

		ui_color_picker(
			id("ent-color-picker", sub_root),
			&seb.color,
			{
				width = orui.fixed(ROW_HEIGHT * 5),
				height = orui.fixed(ROW_HEIGHT * 5),
				dest_color = &v,
			},
		)
	case f32, int:
		if initial_select {
			append(&seb.string_field.buf, value)
		}

		text, confirmed := ui_text_input(
			id("struct-editor-field-value-edit", sub_root_edit),
			&seb.string_field,
			{
				width = orui.grow(),
				height = orui.fixed(HEIGHT),
				foreground = seb.has_error ? .PRIMARY : .FOREGROUND,
			},
		)

		switch &v in dest {
		case f32:
			_, mult := sim.try_unwrap_rounded_float(dest, tag)

			new_value, ok := strconv.parse_f32(text)
			seb.has_error = !ok
			if ok do v = math.round(new_value * mult) / mult
		case int:
			new_value, ok := strconv.parse_u64(text)
			seb.has_error = !ok
			if ok do v = int(new_value)
		}

		if confirmed {
			seb.current_field = 0
		}
	case:
		ui_label(
			id("struct-editor-field-unhandled", sub_root),
			{
				label = "edinting is not supported",
				width = orui.grow(),
				height = orui.fixed(HEIGHT),
				align = .Start,
				background = .NONE,
				foreground = .PRIMARY,
			},
		)
	}

	canceled_focus = seb.current_field == 0
}
