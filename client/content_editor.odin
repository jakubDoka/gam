package client

import "../sim"
import "../util/nm"
import "../util/packer"
import orui "../vendored/orui/src"
import rt "base:runtime"
import "core:fmt"
import "core:math"
import "core:reflect"
import "core:strconv"
import "core:strings"
import rl "vendor:raylib"

ui_content_editor :: proc(client: ^Client) {
	ctx := &client.ui.content_editing

	box(
		id("content-ediitor-centerer"),
		{
			height = orui.grow(),
			width = orui.grow(),
			align_main = .Center,
			position = {.Absolute, {}},
		},
	)

	if orui.hovered() && rl.IsMouseButtonPressed(.LEFT) {
		client.ui.last_handled_button = .LEFT
		ctx.expanded = false
	}

	box(
		id("content-ediitor"),
		{
			height = orui.grow(),
			width = orui.fixed(500),
			scroll = orui.scroll(.Vertical),
			direction = .TopToBottom,
			gap = PADDING,
			padding = orui.padding(PADDING * 2),
			background_color = rl.ColorAlpha(UI_COLOR_SECONDARY, 0.4),
			clip = {.Intersect, {}},
		},
	)

	prefix := min(1, len(client.ents.stats))
	was_selected := false
	for &stats, i in client.ents.stats[prefix:] {
		selected := ctx.selected == stats.id
		was_selected |= selected

		selector: {
			box(id("stat-selector-row"), {width = orui.grow(), gap = PADDING})

			if !selected {
				if ui_button(
					id("stat-selector", i),
					{
						label = nm.str(&stats.name),
						width = orui.grow(),
						height = orui.fixed(ROW_HEIGHT),
						toggle = selected,
						background = .SECONDARY,
						focused_color = .PRIMARY,
					},
				) {
					ctx.selected = stats.id
					selected = !was_selected
					clear(&ctx.edit_name.buf)
					append(&ctx.edit_name.buf, nm.str(&stats.name))
					ctx.stat_edit_state = stats
				}

				break selector
			}

			text, _ := ui_text_input(
				id("stat-selector-name-edit", i),
				&ctx.edit_name,
				{
					width = orui.grow(),
					height = orui.fixed(ROW_HEIGHT),
					placeholder = "name...",
					border = 1,
				},
			)

			ctx.stat_edit_state.name = nm.from_str(text)

			if !reflect.equal(stats, ctx.stat_edit_state, true) {
				if ui_icon_button(
					id("stat-selector-save", i),
					ROW_HEIGHT,
					.ICON_FILE_OPEN,
					"Save changes",
				) {
					stats := ctx.stat_edit_state
					tcp_send(
						client,
						sim.Client_Content_Action {
							kind = .Edit,
							stats = ctx.stat_edit_state,
						},
					)
				}
			}

			if ui_icon_button(
				id("stat-selector", i),
				ROW_HEIGHT,
				.ICON_CROSS,
				"Close editor",
			) {
				ctx.selected = 0
			}
		}

		if selected {
			box(
				id("struct-editor-frame"),
				{
					background_color = rl.ColorAlpha(UI_COLOR_SECONDARY, 0.4),
					width = orui.grow(),
					padding = orui.padding(PADDING),
				},
			)

			ctx.stat_editor.root = id("stat-struct-editor")
			ctx.stat_editor.eidt_root = id("edit-struct-editor", i)
			ui_stat_editor(
				client,
				&ctx.stat_editor,
				ctx.stat_edit_state,
				stats,
			)
		}
	}

	if ctx.create_stat {
		box(
			id("create-stat-frame"),
			{
				background_color = rl.ColorAlpha(UI_COLOR_SECONDARY, 0.4),
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
			stats: sim.Ent_Stats
			stats.name = nm.from_str(text)
			tcp_send(
				client,
				sim.Client_Content_Action{kind = .Create, stats = stats},
			)
		}

		ctx.create_stat ~=
			ui_icon_button(
				id("create-stat-expand"),
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
}

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
	info := type_info_of(reflect.typeid_base(edited.id)).variant.(rt.Type_Info_Struct)

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
		_, is_struct := reflect.type_info_base(type).variant.(rt.Type_Info_Struct)
		is_struct &= type.id != sim.Ent_Stats_Ref
		is_struct &= type.id != sim.Asset_Ref

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

		if !editing {
			switch &v in dest {
			case sim.Asset_Ref:
				index := sim.asset_id_to_idx(client.assets[:], v.id)

				if index >= 0 && int(index) < len(client.ui.sheet.frames) {
					dest = nm.str(&client.ui.sheet.frames[index].name)
					if index == 0 do dest = "<none>"
				} else {
					dest = "<invalid>"
				}
			case sim.Ent_Stats_Ref:
				if int(v.id) < len(client.ents.stats) {
					dest = nm.str(&client.ents.stats[v.id].name)
					if v.id == 0 do dest = "<none>"
				} else {
					dest = "<invalid>"
				}
			}
		}

		value := fmt.tprint(dest)

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

		if v, ok := &dest.(bool); ok {
			v^ ~= ui_button(
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
			)
			continue
		}

		if v, ok := &dest.(sim.Color); ok && !editing {
			if ui_button(
				   id("struct-editor-color-value", sub_root),
				   {
					   width = orui.grow(),
					   height = orui.fixed(HEIGHT),
					   background = ui_color_slot(.SLOT1, get_color(v^)),
					   focused_color = .PRIMARY,
				   },
			   ) ||
			   name_pressed {
				seb.current_field = sub_root_edit
			}
			continue
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
			continue
		}

		initial_select := seb.current_field != seb.last_field
		seb.last_field = seb.current_field

		if initial_select {
			clear(&seb.string_field.buf)
		}

		edit: switch &v in dest {
		case sim.Ent_Kind:
			res, should_close := ui_select_enum(
				id("kind-picker"),
				&seb.string_field,
				sim.Ent_Kind,
			)

			if should_close {
				seb.current_field = 0
			}

			if res, ok := res.?; ok {
				v = res
				seb.current_field = 0
				seb.last_field = 0
			}
		case sim.Asset_Ref:
			res, should_close := ui_sprite_select(
				client,
				id("sprite-picker", sub_root),
				&seb.string_field,
			)

			if should_close {
				seb.current_field = 0
			}

			if res >= 0 {
				v.id = sim.asset_idx_to_id(client.assets[:], res)
				seb.current_field = 0
				seb.last_field = 0
			}
		case sim.Ent_Stats_Ref:
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
				v.id = sim.Ent_Stats_ID(res)
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
	}
}
