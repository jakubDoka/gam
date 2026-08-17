package client

import "../sim"
import "../util/bit_arr"
import "../util/packer"
import "../util/sqlite"
import orui "../vendored/orui/src"
import "base:runtime"
import "core:fmt"
import "core:math"
import la "core:math/linalg"
import "core:reflect"
import "core:slice"
import "core:strings"
import "pure"
import rl "vendor:raylib"

ui_color_from_hsv :: proc(hsv: rl.Vector4) -> (color: rl.Color) {
	color = rl.ColorFromHSV(hsv.x, hsv.y, hsv.z)
	color.a = u8(hsv.w * 255)
	return
}

ui_color_to_hsv :: proc(color: rl.Color) -> (hsv: rl.Vector4) {
	def_hsv := rl.ColorToHSV(color)
	return {def_hsv.x, def_hsv.y, def_hsv.z, f32(color.a) / 255}
}

is_key_down :: proc(r: ^UI_Reactor, key: Key_Bind) -> bool {
	return is_key(.Down, r, key)
}

is_key_pressed :: proc(r: ^UI_Reactor, key: Key_Bind) -> bool {
	return is_key(.Pressed, r, key)
}

is_key_released :: proc(r: ^UI_Reactor, key: Key_Bind) -> bool {
	return is_key(.Released, r, key)
}

Press_Kind :: enum {
	Pressed,
	Down,
	Released,
}

IS_KEY := [Press_Kind]proc "cdecl" (_: rl.KeyboardKey) -> bool {
	.Pressed  = rl.IsKeyPressed,
	.Down     = rl.IsKeyDown,
	.Released = rl.IsKeyReleased,
}

IS_MOUSE := [Press_Kind]proc "cdecl" (_: rl.MouseButton) -> bool {
	.Pressed  = rl.IsMouseButtonPressed,
	.Down     = rl.IsMouseButtonDown,
	.Released = rl.IsMouseButtonReleased,
}

is_key :: proc(kind: Press_Kind, r: ^UI_Reactor, key: Key_Bind) -> bool {
	key_mode := IS_KEY[kind]
	mouse_mode := IS_MOUSE[kind]

	bind := BIND_TO_KEY[key]
	_, ok := slice.linear_search(
		r.captured_key_binds[:],
		key_or_mouse_from_key(bind),
	)
	if ok do return false

	r.last_key_bind = key
	switch b in BIND_TO_KEY[key] {
	case rl.KeyboardKey:
		return key_mode(b) && (r.orui_ctx.prev_focus_id == 0 || b == .ESCAPE)
	case rl.MouseButton:
		return mouse_mode(b) && !ui_is_interacting(r, b)
	case Mod_And_Key:
		countermod := b.mod
		#partial switch b.mod {
		case .LEFT_CONTROL:
			countermod = .RIGHT_CONTROL
		case:
		}
		return(
			key_mode(b.key) &&
			(rl.IsKeyDown(b.mod) || rl.IsKeyDown(countermod)) \
		)
	case:
		panic("wut")
	}
}

Draw_Call :: bit_field uintptr {
	kind:     Draw_Call_Kind | 3,
	icon:     rl.GuiIconName | 8,
	expanded: bool           | 1,
}

draw_call_init_text_highlight :: proc(set: ^bit_arr.Bit_Set) -> Draw_Call {
	return Draw_Call(uintptr(set) | uintptr(Draw_Call_Kind.Text_Highlight_Set))
}

draw_call_extract_set :: proc(call: Draw_Call) -> ^bit_arr.Bit_Set {
	assert(call.kind == .Text_Highlight_Set)
	return auto_cast (uintptr(call) & ~uintptr(0b111))
}

draw_call_init_hsv :: proc(
	hsv: ^UI_Color_Picker_State,
	kind: Draw_Call_Kind,
) -> Draw_Call {
	return Draw_Call(uintptr(kind) | uintptr(hsv))
}

draw_call_extract_hsv :: proc(call: Draw_Call) -> ^UI_Color_Picker_State {
	return auto_cast (uintptr(call) & ~uintptr(0b111))
}

Draw_Call_Kind :: enum uint {
	Nil,
	Dropdown_Arrow,
	Rl_Icon,
	Rl_Color_Panel,
	Rl_Hue_Panel,
	Rl_Alpha_Panel,
	Text_Highlight_Set,
}

UI_Color :: enum {
	UNSET,
	NONE,
	PRIMARY,
	PRIMARY_FAINT,
	SECONDARY,
	SECONDARY_FAINT,
	SUCCESS,
	FOREGROUND,
	SLOT1,
	SLOT2,
	SLOT3,
}

UI_COLORS: ^[UI_Color]rl.Color

EDITABLE_COLORS := bit_set[UI_Color] {
	.PRIMARY,
	.PRIMARY_FAINT,
	.SECONDARY,
	.SECONDARY_FAINT,
	.SUCCESS,
	.FOREGROUND,
}

UI_COLORS_DEFAULT := #partial [UI_Color]rl.Color {
	.SUCCESS         = rl.GREEN,
	.PRIMARY_FAINT   = {255, 0, 0, 102},
	.SECONDARY       = {0, 0, 0, 204},
	.SECONDARY_FAINT = {0, 0, 0, 102},
	.PRIMARY         = rl.RED,
	.FOREGROUND      = rl.WHITE,
}

ui_colors :: proc() -> ^[UI_Color]rl.Color {
	if UI_COLORS != nil do return UI_COLORS
	return &UI_COLORS_DEFAULT
}

ui_color_alpha_slot :: proc(
	color: UI_Color,
	value: UI_Color,
	alpha: f32,
) -> UI_Color {
	return ui_color_slot(
		color,
		rl.ColorAlpha(ui_color(value), alpha * f32(ui_color(value).a) / 255),
	)
}

ui_color_slot :: proc(color: UI_Color, value: rl.Color) -> UI_Color {
	assert(color >= .SLOT1)
	ui_colors()[color] = value
	return color
}

ui_color :: proc(color: UI_Color, fallback: UI_Color = .NONE) -> rl.Color {
	if color == .UNSET do return ui_colors()[fallback]
	return ui_colors()[color]
}

ui_dropdown_arrow :: proc(
	center: sim.Vec,
	size: f32,
	rot: f32,
	color: rl.Color,
) {
	p1 := sim.Vec{0, size * 0.25}
	p2 := sim.Vec{-size * 0.5, -size * 0.25}
	p3 := sim.Vec{size * 0.5, -size * 0.25}

	rotate :: proc(v: sim.Vec, r: f32) -> sim.Vec {
		return la.matrix2_rotate(r) * v
	}

	p1 = rotate(p1, rot)
	p2 = rotate(p2, rot)
	p3 = rotate(p3, rot)

	p1 += center
	p2 += center
	p3 += center

	rl.DrawTriangle(p3, p2, p1, color)
}

ui_get_sprite :: proc(
	r: ^UI_Reactor,
	sprite: sim.Asset_ID,
) -> (
	texture: rl.Texture,
	region: rl.Rectangle,
) {
	sprite := sim.asset_id_to_idx(r.assets[:], sprite)

	if sprite < 0 || int(sprite) >= len(r.sheet.frames) {
		return {}, {}
	}

	texture = r.sheet.texture
	region = r.sheet.frames[sprite]
	region.x += 0.01
	region.y += 0.01
	region.width -= 0.02
	region.height -= 0.02

	return
}

Button_Config :: struct {
	label:         string,
	tooltip:       string,
	width:         orui.Size,
	height:        orui.Size,
	foreground:    UI_Color,
	background:    UI_Color,
	focused_color: UI_Color,
	toggle:        Maybe(bool),
	icon:          rl.GuiIconName,
	align:         Maybe(orui.ContentAlignment),
	margin:        orui.Edges,
	disabled:      bool,
	sprite:        sim.Asset_ID,
	border_color:  UI_Color,
	border:        f32,
	padding:       Maybe(orui.Edges),
	position:      orui.Position,
	custom_dc:     Draw_Call,
}

ui_button :: proc(uid: orui.Id, config: Button_Config) -> bool {
	foreground := ui_color(config.foreground, .FOREGROUND)
	background := ui_color(config.background, .PRIMARY)
	focused_color := ui_color(config.focused_color, .SECONDARY)
	border_color := ui_color(config.border_color)

	hovered := config.toggle.? or_else orui.hovered() && !orui.active()

	custom_event := rawptr(config.custom_dc)

	if config.icon != .ICON_NONE {
		custom_event = rawptr(Draw_Call{kind = .Rl_Icon, icon = config.icon})
	}

	r := (^UI_Reactor)(
		transmute(uintptr)orui.current_context -
		offset_of(UI_Reactor, orui_ctx),
	)

	alpha: f32 = config.disabled ? 0.5 : 1
	background_color := hovered ? focused_color : background
	configu := orui.ElementConfig {
		width            = config.width,
		height           = config.height,
		color            = rl.ColorAlpha(
			foreground,
			f32(foreground.a) / 255 * alpha,
		),
		background_color = rl.ColorAlpha(
			background_color,
			f32(background_color.a) / 255 * alpha,
		),
		align            = {config.align.? or_else .Center, .Center},
		font_size        = f32(font_medium.baseSize),
		custom_event     = custom_event,
		padding          = config.padding.? or_else orui.padding(PADDING * 2, PADDING),
		position         = config.position,
		margin           = config.margin,
		border           = orui.border(config.border),
		border_color     = border_color,
	}

	ui_tooltip_begin(uid, config.tooltip)

	if config.sprite == 0 {
		label := strings.clone(config.label, context.temp_allocator)
		orui.label(orui.id(uid), label, configu)
	} else {
		texture, region := ui_get_sprite(r, config.sprite)
		configu.texture_source = region
		tex := new(rl.Texture2D, context.temp_allocator)
		tex^ = texture
		orui.image(orui.id(uid), tex, configu)
	}

	pressed :=
		!config.disabled && orui.hovered() && rl.IsMouseButtonPressed(.LEFT)

	ui_tooltip_end(uid, config.tooltip)

	if pressed do append(&r.captured_key_binds, MousetButton.LEFT)

	return pressed
}

ui_tooltip_begin :: proc(uid: orui.Id, value: string) {
	show_tooltip := len(value) != 0 && orui.hovered(uid)
	if show_tooltip {
		orui.element(id("tooltip-wrap", uid), {position = {.Relative, {}}})
	}
}

ui_tooltip_end :: proc(uid: orui.Id, value: string, prefix: string = "") {
	show_tooltip := len(value) != 0 && orui.hovered(uid)
	if show_tooltip {
		orui.label(
			id("tooltip", uid),
			prefix != "" ? fmt.tprint(prefix, value) : value,
			{
				position = {.Absolute, {}},
				placement = orui.placement(.Bottom, .Top),
				bounds = {.Window, .Flip, PADDING},
				layer = 500,
				clip = {.None, {}},
				font_size = f32(font_medium.baseSize),
				color = ui_color(.FOREGROUND),
				background_color = ui_color(.SECONDARY_FAINT),
				padding = orui.padding(PADDING),
				border = orui.border(1),
				border_color = ui_color(.PRIMARY),
			},
		)

		orui.end_element()
	}
}

ui_icon_dropdown :: proc(
	id: orui.Id,
	state: ^bool,
	size: f32,
	icon: rl.GuiIconName,
	tooltip: string,
	config: Dropdown_Config = {},
) -> bool {
	config := config
	config.width = orui.fixed(size)
	config.height = orui.fixed(size)
	config.icon = icon
	config.tooltip = tooltip
	return ui_dropdown(id, state, config)
}

Dropdown_Config :: struct {
	label:        string,
	width:        orui.Size,
	height:       orui.Size,
	foreground:   UI_Color,
	background:   UI_Color,
	active_color: UI_Color,
	icon:         rl.GuiIconName,
	layer:        int,
	tooltip:      string,
}

ui_dropdown :: proc(
	uid: orui.Id,
	state: ^bool,
	config: Dropdown_Config,
) -> bool {
	foreground := ui_color(config.foreground, .FOREGROUND)
	background := ui_color(config.background, .SECONDARY)
	active_color := ui_color(config.active_color, .PRIMARY)

	arrow_cmd := Draw_Call {
		kind     = .Dropdown_Arrow,
		expanded = state^,
	}
	icon_cmd := Draw_Call {
		kind = .Rl_Icon,
		icon = config.icon,
	}

	ui_tooltip_begin(uid, config.tooltip)

	orui.label(
		orui.id(uid),
		config.label,
		{
			background_color = state^ ? active_color : background,
			width = config.width,
			height = config.height,
			color = foreground,
			font_size = f32(font_medium.baseSize),
			align = {.Center, .Center},
			custom_event = rawptr(
				config.icon == .ICON_NONE ? arrow_cmd : icon_cmd,
			),
			layer = config.layer,
		},
	)

	state^ ~= orui.hovered() && rl.IsMouseButtonPressed(.LEFT)

	ui_tooltip_end(uid, config.tooltip, state^ ? "Close" : "Open")

	return state^
}

ui_error_label :: proc(
	id: orui.Id,
	message: string,
	width: orui.Size,
	height: orui.Size,
) {
	if len(message) != 0 {
		ui_label(
			id,
			{
				label = message,
				width = width,
				height = height,
				foreground = .PRIMARY,
			},
		)
	}
}

Text_Input_Config :: struct {
	width:           orui.Size,
	height:          orui.Size,
	foreground:      UI_Color,
	background:      UI_Color,
	align:           Maybe(orui.ContentAlignment),
	default_text:    string,
	placeholder:     string,
	border:          f32,
	border_color:    UI_Color,
	layer:           int,
	dont_save_state: bool,
	dont_autofocus:  bool,
}

ui_text_input :: proc(
	id: orui.Id,
	state: ^strings.Builder,
	config: Text_Input_Config,
	loc := #caller_location,
) -> (
	string,
	bool,
) {
	background := ui_color(config.background, .SECONDARY)
	foreground := ui_color(config.foreground, .FOREGROUND)
	border_color := ui_color(config.border_color, .PRIMARY)
	align := config.align.? or_else .Start

	r := (^Client)(
		transmute(uintptr)orui.current_context -
		offset_of(UI_Reactor, orui_ctx) -
		offset_of(Client, ui),
	)

	_, already_initialized := orui.element_index_by_id(
		orui.current_context,
		orui.previous_buffer(orui.current_context),
		id,
	)

	if !config.dont_save_state && !already_initialized && len(state.buf) == 0 {
		sti: pure.Saved_Text_Input
		sti_res, s := sqlite.query_one(r.load_input_content, sti, int(id))
		clear(&state.buf)
		if sti_res == .OK {
			append(&state.buf, sti.content, loc = loc)
		} else if len(config.default_text) != 0 {
			append(&state.buf, config.default_text, loc = loc)
		}
		sqlite.reset(s)
	}

	placeholder := config.placeholder

	confirmed := orui.text_input(
		id,
		state,
		{
			width = config.width,
			height = config.height,
			background_color = background,
			color = foreground,
			font_size = f32(font_medium.baseSize),
			align = {align, .Center},
			overflow = .Visible,
			padding = orui.padding(PADDING * 2, PADDING),
			clip = {.Intersect, {}},
			scroll = orui.scroll(.Horizontal),
			custom_event = &placeholder,
			border = orui.border(config.border),
			border_color = border_color,
			layer = config.layer,
		},
		proc(e: ^orui.Element) {
			if len(e.text) == 0 && !orui.focused() {
				e.text = (^string)(e.custom_event)^
				e.color = rl.ColorAlpha(e.color, 0.5)
			}
			e.custom_event = nil
		},
	)

	if !already_initialized && !config.dont_autofocus {
		orui.current_context.focus_id = orui.current_context.current_id
		orui.current_context.caret_index = len(state.buf)
	}

	res := string(state.buf[:])

	if !config.dont_save_state {
		if res != config.default_text {
			_, err := sqlite.exec(r.save_input_content, int(id), res)
			sqlite.assert_ok(r.save_input_content, err)
		} else {
			_, err := sqlite.exec(r.delete_input_content, int(id))
			sqlite.assert_ok(r.delete_input_content, err)
		}
	}

	return res, confirmed && len(res) != 0 && rl.IsKeyPressed(.ENTER)
}

Label_Config :: struct {
	label:      string,
	width:      orui.Size,
	height:     orui.Size,
	foreground: UI_Color,
	background: UI_Color,
	align:      Maybe(orui.ContentAlignment),
	padding:    Maybe(orui.Edges),
	custom_dc:  Draw_Call,
}

ui_label :: proc(id: orui.Id, config: Label_Config) -> bool {
	foreground := ui_color(config.foreground, .FOREGROUND)
	background := ui_color(config.background, .SECONDARY)

	orui.label(
		id,
		strings.clone(config.label, context.temp_allocator),
		{
			width = config.width,
			height = config.height,
			background_color = background,
			color = foreground,
			font_size = f32(font_medium.baseSize),
			align = {config.align.? or_else .Center, .Center},
			padding = config.padding.? or_else orui.padding(
				PADDING * 2,
				PADDING,
			),
			custom_event = rawptr(config.custom_dc),
			overflow = .Wrap,
		},
	)

	return rl.IsMouseButtonPressed(.LEFT) && orui.hovered()
}

ui_select_enum :: proc(
	root: orui.Id,
	state: ^strings.Builder,
	$T: typeid,
	config: Select_Config = {},
) -> (
	Maybe(T),
	bool,
) {
	res, should_close := ui_select_generic_enum(root, state, T, config)
	if res == nil do return nil, should_close
	return T(res.?), should_close
}

ui_select_generic_enum :: proc(
	root: orui.Id,
	state: ^strings.Builder,
	enm: typeid,
	config: Select_Config = {},
) -> (
	Maybe(runtime.Type_Info_Enum_Value),
	bool,
) {
	config := config
	config.count = len(reflect.enum_field_names(enm))
	config.name_of = proc(_: rawptr, i: int) -> string {
		return reflect.enum_field_names(sim.Ent_Type)[i]
	}

	res, should_close := ui_select(root, state, config)

	if res < 0 do return nil, should_close

	return reflect.enum_field_values(enm)[res], should_close
}

Select_Config :: struct {
	count:        int,
	ctx:          rawptr,
	name_of:      proc(_: rawptr, _: int) -> string,
	build_of:     proc(_: rawptr, _: orui.Id, _: string, _: int) -> bool,
	border_color: UI_Color,
	width:        Maybe(orui.Size),
	virt:         Maybe(Virt_Config),
	dont_filter:  bool,
}

ui_select :: proc(
	root: orui.Id,
	state: ^strings.Builder,
	config: Select_Config,
) -> (
	res: int = -1,
	should_close: bool,
) {
	border_color := ui_color(config.border_color, .PRIMARY)
	width := config.width.? or_else orui.grow()

	box(id("select", root), {width = orui.grow(), position = {.Relative, {}}})

	_, already_initialized := orui.element_index_by_id(
		orui.current_context,
		orui.previous_buffer(orui.current_context),
		orui.current_context.current_id,
	)

	hovered := orui.hovered()

	box(
		id("select-float", root),
		{
			width = width,
			position = {.Absolute, {}},
			bounds = {.Window, .Squish, PADDING},
			clip = {.None, {}},
			border_color = border_color,
			border = orui.border(1),
			direction = .TopToBottom,
			layer = 300,
			background_color = ui_color(.SECONDARY),
		},
	)

	text, confirmed := ui_text_input(
		id(root),
		state,
		{width = orui.grow(), height = orui.fixed(HEIGHT), background = .NONE},
	)

	box(
		id("select-options-scroll-wrapper", root),
		{
			width = orui.grow(),
			height = orui.grow(),
			position = {.Relative, {}},
		},
	)

	options := id("select-options", root)
	{box(
			options,
			{
				scroll = orui.scroll(.Vertical),
				clip = {.Intersect, {}},
				direction = .TopToBottom,
				width = orui.grow(),
				height = orui.grow(),
				align_cross = .Center,
			},
		)

		real_count := 0
		for i in 0 ..< config.count {
			name := config.name_of(config.ctx, i)
			real_count += int(
				config.dont_filter || strings.contains(name, text),
			)
		}

		win: Virt_Window
		if virt, present := config.virt.?; present {
			virt := virt
			virt.total = real_count
			win = virtualize(virt)
		} else {
			win.first = 0
			win.last = config.count
		}

		gi := 0
		for i in 0 ..< config.count {
			name := config.name_of(config.ctx, i)
			if config.dont_filter || strings.contains(name, text) {
				gi += 1

				if gi - 1 < win.first || win.last <= gi - 1 do continue

				default :: ui_select_default_build_of
				build_of := config.build_of != nil ? config.build_of : default

				if build_of(config.ctx, root * orui.Id(i), name, i) ||
				   confirmed {
					confirmed = false

					res = i
				}
			}
		}

		if config.virt != nil {
			end_virtualized_elem(win)
		}
	}

	should_close =
		!hovered && already_initialized && rl.IsMouseButtonPressed(.LEFT)

	if can_scroll(options) {
		should_close &= !orui.scrollbar(
			options,
			{
				position = {.Absolute, {-4, 0}},
				placement = orui.placement(.Right, .Right),
				width = orui.fixed(8),
				height = orui.percent(0.98),
			},
			{
				direction = .TopToBottom,
				width = orui.percent(1),
				background_color = ui_color(.PRIMARY),
			},
		)
	}

	return
}

ui_select_default_build_of :: proc(
	_: rawptr,
	uid: orui.Id,
	name: string,
	i: int,
) -> bool {
	return ui_button(
		id("select-option", uid),
		{
			label = name,
			width = orui.grow(),
			height = orui.fixed(HEIGHT),
			background = .NONE,
			focused_color = .PRIMARY,
		},
	)
}

ui_hue_gradient :: proc(bounds: rl.Rectangle) {
	colors := [?]rl.Color {
		rl.Color{255, 0, 0, 255},
		rl.Color{255, 255, 0, 255},
		rl.Color{0, 255, 0, 255},
		rl.Color{0, 255, 255, 255},
		rl.Color{0, 0, 255, 255},
		rl.Color{255, 0, 255, 255},
		rl.Color{255, 0, 0, 255},
	}

	for i in 0 ..< len(colors) - 1 {
		rl.DrawRectangleGradientEx(
			{
				bounds.x,
				bounds.y + f32(i) * bounds.height / 6.0,
				bounds.width,
				bounds.height / 6.0,
			},
			colors[i],
			colors[i + 1],
			colors[i + 1],
			colors[i],
		)
	}
}

dragged_ui_color_panel: orui.Id
dragged_ui_color_hue: orui.Id
dragged_ui_color_alpha: orui.Id

ui_drag_capture :: proc(id: ^orui.Id) -> (sim.Vec, bool) {
	if orui.active() || (orui.hovered() && rl.IsMouseButtonPressed(.LEFT)) {
		id^ = orui.current_context.current_id
	}

	if rl.IsMouseButtonReleased(.LEFT) {
		id^ = 0
	}

	if id^ == orui.current_context.current_id {
		rect := orui.bounding_rect()
		mouse_pos := rl.GetMousePosition()

		pos := mouse_pos - {rect.x, rect.y}
		pos = la.clamp(pos, sim.Vec{0, 0}, sim.Vec{rect.width, rect.height})
		pos.x /= rect.width
		pos.y /= rect.height
		return pos, true
	}

	return {}, false
}

UI_Color_Picker_State :: struct #align (8) {
	using hsv: rl.Vector4,
}

Color_Picker_Config :: struct {
	width:       orui.Size,
	height:      orui.Size,
	hue_width:   Maybe(f32),
	alpha_width: Maybe(f32),
	position:    orui.PositionType,
	dest_color:  ^sim.Color,
}

ui_color_picker :: proc(
	root: orui.Id,
	hsv: ^UI_Color_Picker_State,
	config: Color_Picker_Config,
) {
	hue_width := config.hue_width.? or_else HEIGHT
	alpha_width := config.alpha_width.? or_else HEIGHT / 2

	prev_hsv := hsv^

	box(id(root), {width = config.width, height = config.height})

	color := ui_color_from_hsv(hsv)

	{box(
			id("color-panel", root),
			{
				width = orui.grow(),
				height = orui.grow(),
				custom_event = rawptr(
					draw_call_init_hsv(hsv, .Rl_Color_Panel),
				),
				background_color = color,
			},
		)}

	if pos, ok := ui_drag_capture(&dragged_ui_color_panel); ok {
		hsv.y = pos.x
		hsv.z = 1.0 - pos.y
	}

	{box(
			id("hue-panel", root),
			{
				width = orui.fixed(hue_width),
				height = orui.grow(),
				custom_event = rawptr(draw_call_init_hsv(hsv, .Rl_Hue_Panel)),
				background_color = color,
			},
		)}

	if pos, ok := ui_drag_capture(&dragged_ui_color_hue); ok {
		hsv.x = pos.y * 360.0
	}

	{box(
			id("alpha-panel", root),
			{
				width = orui.fixed(alpha_width),
				height = orui.grow(),
				custom_event = rawptr(
					draw_call_init_hsv(hsv, .Rl_Alpha_Panel),
				),
			},
		)}

	if pos, ok := ui_drag_capture(&dragged_ui_color_alpha); ok {
		hsv.w = 1.0 - pos.y
	}

	if config.dest_color != nil && prev_hsv != hsv^ {
		config.dest_color^ = sim.Color(rl.ColorToInt(ui_color_from_hsv(hsv)))
	}
}

Virt_Config :: struct {
	item_height: f32,
	gap:         f32,
	total:       int,
}

Virt_Window :: struct {
	first:         int,
	last:          int,
	top_spacer:    f32,
	bottom_spacer: f32,
}

virtualize :: proc {
	virtualize_raw,
	virtualize_elem,
}

@(deferred_out = end_virtualized_elem)
virtualize_scope :: proc(cfg: Virt_Config) -> Virt_Window {
	return virtualize_elem(cfg)
}

end_virtualized_elem :: proc(win: Virt_Window) {
	virtual_spacer(win.bottom_spacer)
}

virtualize_elem :: proc(cfg: Virt_Config) -> Virt_Window {
	win := virtualize_raw(
		orui.scroll_offset().y,
		orui.bounding_rect().height,
		cfg,
	)

	virtual_spacer(win.top_spacer)

	return win
}

virtualize_raw :: proc(
	offset, viewport: f32,
	cfg: Virt_Config,
) -> Virt_Window {
	OVERSCAN :: 4

	stride := cfg.item_height + cfg.gap

	first := int(offset / stride) - OVERSCAN
	if first < 0 do first = 0
	if first >= cfg.total do first = cfg.total - 1

	count := int(viewport / stride) + OVERSCAN * 2 + 2
	last := first + count
	if last > cfg.total do last = cfg.total

	top := f32(first) * stride
	bottom := f32(cfg.total - last) * stride
	if bottom > 0 do bottom -= cfg.gap

	return {
		first = first,
		last = last,
		top_spacer = top,
		bottom_spacer = bottom,
	}
}

can_scroll :: proc(id: orui.Id) -> bool {
	elem := orui.get_element(id)
	return(
		elem != nil &&
		(elem._size.y < elem._content_size.y ||
				elem._size.x < elem._content_size.x) \
	)
}

virtual_spacer :: proc(height: f32) {
	if height > 0 {
		orui.container(
			orui.id("spacer"),
			{width = orui.grow(), height = orui.fixed(height)},
		)
	}
}

ui_render :: proc() {
	for command in orui.end() {
		defer orui.render_command(command)

		if Draw_Call(command.source.custom_event).kind == .Text_Highlight_Set {
			call := Draw_Call(command.source.custom_event)
			set := draw_call_extract_set(call)

			text := command.data.(orui.RenderCommandDataText) or_continue

			start_idx := text.start_index

			start := -1
			for i in 0 ..= len(text.text) {
				global := start_idx + i
				if bit_arr.contains_unbounded(set^, global) {
					if start == -1 {
						start = i
					}
				} else if start != -1 {
					rect, _ := orui.measure_text_command_range(
						command,
						start,
						i,
					)

					rect.width += 2

					rl.DrawRectangleRec(rect, ui_color(.PRIMARY))
					start = -1
				}
			}
		}

		if command.type != .Custom do continue

		data := command.data.(orui.RenderCommandDataCustom)
		rect := data.rectangle
		elem := data.source
		call := Draw_Call(data.custom_event)

		auto_draw :=
			call.kind not_in bit_set[Draw_Call_Kind]{.Text_Highlight_Set}

		switch call.kind {
		case .Nil:
		case .Dropdown_Arrow:
			ui_dropdown_arrow(
				{rect.x, rect.y} +
				{rect.width - rect.height / 2, rect.height / 2},
				rect.height / 2,
				call.expanded ? math.PI : 0,
				elem.color,
			)
		case .Rl_Icon:
			pixel_size := math.floor(min(rect.height, rect.width) / 16)
			icon_size := pixel_size * 16
			icon_pos :=
				sim.Vec{rect.x, rect.y} +
				({rect.width, rect.height} - icon_size) * 0.5

			rl.GuiDrawIcon(
				call.icon & .ICON_255,
				i32(icon_pos.x),
				i32(icon_pos.y),
				i32(pixel_size),
				elem.color,
			)
		case .Rl_Color_Panel:
			hsv := draw_call_extract_hsv(call)
			max_hue_color := rl.ColorFromHSV(hsv.x, 1, 1)

			rl.DrawRectangleGradientEx(
				rect,
				rl.WHITE,
				rl.WHITE,
				max_hue_color,
				max_hue_color,
			)
			rl.DrawRectangleGradientEx(
				rect,
				rl.BLANK,
				rl.BLACK,
				rl.BLACK,
				rl.BLANK,
			)

			pos := sim.Vec {
				rect.x + hsv.y * rect.width,
				rect.y + (1.0 - hsv.z) * rect.height,
			}

			rl.DrawRectangleRec({pos.x - 3, pos.y - 3, 6, 6}, rl.WHITE)
		case .Rl_Hue_Panel:
			ui_hue_gradient(rect)

			hsv := draw_call_extract_hsv(call)

			rl.DrawRectangleRec(
				{
					rect.x,
					rect.y + hsv.x / 360.0 * rect.height - 1.5,
					rect.width,
					3,
				},
				rl.WHITE,
			)
		case .Rl_Alpha_Panel:
			hsv := draw_call_extract_hsv(call)
			color := rl.ColorFromHSV(hsv.x, hsv.y, hsv.z)

			rl.DrawRectangleGradientEx(rect, color, rl.BLANK, rl.BLANK, color)

			rl.DrawRectangleRec(
				{
					rect.x,
					rect.y + (1.0 - hsv.w) * rect.height - 1.5,
					rect.width,
					3,
				},
				rl.WHITE,
			)
		case .Text_Highlight_Set:
		}
	}
}
