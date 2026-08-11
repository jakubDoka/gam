package sim

import "../util/nm"
import rt "base:runtime"
import "core:fmt"
import "core:io"
import "core:log"
import "core:mem"
import "core:reflect"
import "core:strconv"
import "core:strings"
import "core:testing"

Asset_Loader :: struct {
	asoc_data:     rawptr,
	load_sprite:   proc(_: ^Asset_Loader, _: string) -> (Asset_ID, string),
	path:          string,
	source:        string,
	line:          int,
	stats:         [dynamic]Ent_Stats,
	ent_ref_names: [dynamic]string,
}

report :: proc(loader: ^Asset_Loader, fmt_str: string, args: ..any) {
	message := fmt.tprintf(fmt_str, ..args)

	log.warnf("%s:%v: %s", loader.path, loader.line, message)
}

load_config :: proc(loader: ^Asset_Loader) {
	clear(&loader.stats)
	append(&loader.stats, Ent_Stats{})
	loader.ent_ref_names = make([dynamic]string, 1, context.temp_allocator)

	segments: [dynamic; 8]any
	line_iter := loader.source
	loader.line = 0
	parse: for full_line in strings.split_iterator(&line_iter, "\n") {
		loader.line += 1

		line := strings.trim(full_line, "\t")
		if len(line) == 0 do continue

		depth, name, value, err := parse_line(line)

		parse_line :: proc(
			line: string,
		) -> (
			depth: int,
			name: string,
			value: string,
			err: string,
		) {
			indent_unit :: "  "

			line := line
			for strings.starts_with(line, indent_unit) {
				line = line[len(indent_unit):]
				depth += 1
			}

			colon_idx := strings.index(line, ":")
			if colon_idx < 0 {
				err = "missing ':' separator"
				return
			}

			name = line[:colon_idx]
			name = strings.trim(name, " \t\r")
			value = line[colon_idx + 1:]
			value = strings.trim(value, " \t\r")

			return
		}

		if err != "" {
			report(loader, "invalid line: %s", err)
			continue
		}

		if depth > len(segments) {
			report(
				loader,
				"expected at most %v levels of indentation, got %v",
				len(segments),
				depth,
			)
			continue
		}

		resize(&segments, depth)

		if len(segments) == 0 {
			if value != "" {
				context.allocator = context.temp_allocator

				report(
					loader,
					"expected root level declaration to be a object, got %s," +
					" example of a correct declaration:\n" +
					"object:\n" +
					"  name: test\n" +
					"  speed: 10\n" +
					"  playable: true\n",
					value,
				)
				continue
			}

			id := len(loader.stats)
			nm := nm.from_str(name)
			append(&loader.stats, Ent_Stats{id = Ent_Stats_ID(id), name = nm})
			append(&segments, loader.stats[len(loader.stats) - 1])
			continue
		}

		curr_segment := segments[len(segments) - 1]

		#partial switch info in
			type_info_of(reflect.typeid_base(curr_segment.id)).variant {
		case rt.Type_Info_Struct:
			field_idx := -1
			search: for nm, i in info.names[:info.field_count] {
				if len(nm) != len(name) do continue
				for i in 0 ..< len(nm) {
					if nm[i] != name[i] && (nm[i] != '_' || name[i] != '-') do continue search
				}

				field_idx = i
				break
			}

			if field_idx < 0 {
				context.allocator = context.temp_allocator
				builder: strings.Builder

				for nm in info.names[:info.field_count] {
					append(&builder.buf, "\t")
					vl, _ := strings.replace_all(nm, "_", "-")
					append(&builder.buf, vl)
					append(&builder.buf, "\n")
				}

				report(
					loader,
					"unknown field %s, skipping, available fields:\n%s",
					name,
					string(builder.buf[:]),
				)

				continue
			}

			dest := any {
				rawptr(uintptr(curr_segment.data) + info.offsets[field_idx]),
				info.types[field_idx].id,
			}

			if reflect.is_struct(type_info_of(dest.id)) &&
			   dest.id != Asset_ID {
				if value == "" {
					append(&segments, dest)
					continue
				}

				report(
					loader,
					"unexpected value after the ':' because the field is not simple",
				)
			}

			if value == "" {
				report(
					loader,
					"expected value after the ':' because the field is simple",
				)
				continue
			}

			parse_value(dest, value, loader)
		case:
			report(loader, "BUG: reached invalid parsing state: ", info)
		}
	}

	parse_value :: proc(dest: any, value: string, loader: ^Asset_Loader) {
		switch &a in dest {
		case bool:
			switch value {
			case "true":
				a = true
			case "false":
				a = false
			case:
				report(loader, "expected boolean (true/false), got %s", value)
			}
		case f32:
			vl, pok := strconv.parse_f32(value)
			if !pok {
				report(loader, "expected float, got %s", value)
			}
			a = vl
		case int:
			vl, pok := strconv.parse_u64(value)
			if !pok {
				report(loader, "expected unsigned integer, got %s", value)
			}
			a = int(vl)
		case Color:
			str, _ := strings.replace_all(
				value,
				"#",
				"0x",
				context.temp_allocator,
			)
			vl, pok := strconv.parse_u64(str)
			if !pok {
				report(loader, "expected color (red: #ff0000), got %s", value)
			}
			if len(str) == 8 {
				vl = vl << 8 | 0xFF
			}
			a = Color(vl)
		case Ent_Stats_ID:
			append(&loader.ent_ref_names, value)
			a = Ent_Stats_ID(len(loader.ent_ref_names) - 1)
		case Asset_ID:
			id, load_err := loader.load_sprite(loader, value)
			if len(load_err) != 0 {
				report(
					loader,
					"failed to load the sprite %s: %s",
					value,
					load_err,
				)
			}
			a = id
		case Ent_Type:
			v, ok := reflect.enum_from_name(Ent_Type, value)
			if !ok {
				report(loader, "invalid ent kind (TDOD: log options)")
			}
			a = v
		case:
			report(
				loader,
				"initializing this field is not supported (debug: %v)",
				dest.id,
			)
		}
	}

	for &e in loader.stats {
		post_proces_stats(
			loader,
			e,
			loader.stats[:],
			loader.path,
			loader.source,
		)
	}

	post_proces_stats :: proc(
		loader: ^Asset_Loader,
		dest: any,
		all: []Ent_Stats,
		path, source: string,
	) {
		switch &v in dest {
		case Ent_Stats_ID:
			name := loader.ent_ref_names[v]

			id := 0
			for &e, i in all {
				if name == nm.str(&e.name) do id = i
			}

			if id == 0 && name != "" {
				index := uintptr(raw_data(name)) - uintptr(raw_data(source))
				line_idx := strings.count(source[:index], "\n")
				log.warnf(
					"%s:%v: the reference %s does not exist",
					path,
					line_idx,
					name,
				)
			}

			v = Ent_Stats_ID(id)

			return
		case bool, f32, int, Asset_ID, Ent_Type, Ent_Stats_Name, Color:
			return
		case:
		}

		#partial switch info in
			type_info_of(reflect.typeid_base(dest.id)).variant {
		case rt.Type_Info_Struct:
			for field in reflect.struct_fields_zipped(dest.id) {
				if strings.contains(
					reflect.struct_tag_get(field.tag, "gam"),
					"hidden",
				) {continue}

				value := reflect.struct_field_value(dest, field)
				post_proces_stats(loader, value, all, path, source)
			}
		case:
			log.error("unhandled type for post processing:", dest.id)
		}
	}
}

assert_ml_string :: proc(
	t: ^testing.T,
	logs: string,
	source: string,
	loc := #caller_location,
) {
	normalized_source: strings.Builder
	line_iter := source
	for full_line in strings.split_iterator(&line_iter, "\n") {
		normalized_line := strings.trim(full_line, "\t")
		if len(normalized_line) == 0 do continue
		append(&normalized_source.buf, normalized_line)
		append(&normalized_source.buf, "\n")
	}

	testing.expect_value(
		t,
		strings.trim(logs, "\n"),
		strings.trim(string(normalized_source.buf[:]), "\n"),
		loc,
	)
}

@(test)
test_config_loading :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator

	Buffer_Logger :: struct {
		buf: [dynamic; 4096 * 2]byte,
	}

	file_logger_proc :: proc(
		logger_data: rawptr,
		level: log.Level,
		text: string,
		options: log.Options,
		location := #caller_location,
	) {
		buffer := (^Buffer_Logger)(logger_data)
		append(&buffer.buf, text)
		append(&buffer.buf, "\n")
	}

	run :: proc(
		logger: ^Buffer_Logger,
		loader: ^Asset_Loader,
		source: string,
	) {
		clear(&logger.buf)
		context.logger = {
			procedure = file_logger_proc,
			data      = logger,
		}

		loader.path = "test.conf"
		loader.source = source

		load_config(loader)
	}

	assert_logs :: proc(
		t: ^testing.T,
		logger: ^Buffer_Logger,
		source: string,
		loc := #caller_location,
	) {
		assert_ml_string(t, string(logger.buf[:]), source, loc)
	}

	logger: Buffer_Logger
	loader: Asset_Loader

	run(
		&logger,
		&loader,
		`
		arma:
		  playable: true
		foreign:
		  placable: true
	`,
	)

	testing.expect_value(t, len(loader.stats), 3)
	testing.expect_value(t, nm.str(&loader.stats[1].name), "arma")
	testing.expect_value(t, loader.stats[1].playable, true)
	testing.expect_value(t, nm.str(&loader.stats[2].name), "foreign")
	testing.expect_value(t, loader.stats[2].placable, true)
	assert_logs(t, &logger, "")

	run(&logger, &loader, `
		  foo:
	`)

	testing.expect_value(t, len(loader.stats), 1)
	assert_logs(
		t,
		&logger,
		`
		test.conf:2: expected at most 0 levels of indentation, got 1
	`,
	)

	run(&logger, &loader, `
		foo:
		  playable:
		    foo: bar
	`)

	testing.expect_value(t, len(loader.stats), 2)
	assert_logs(
		t,
		&logger,
		`
			test.conf:3: expected value after the ':' because the field is simple
			test.conf:4: expected at most 1 levels of indentation, got 2
		`,
	)

	run(&logger, &loader, `
		foo:
		  playable: 1
	`)

	testing.expect_value(t, len(loader.stats), 2)
	assert_logs(
		t,
		&logger,
		`
		test.conf:3: expected boolean (true/false), got 1
	`,
	)
}

Store_Ctx :: struct {
	asoc_data:   rawptr,
	sprite_name: proc(_: rawptr, id: Asset_ID) -> string,
	stats:       []Ent_Stats,
}

store_config :: proc(ctx: Store_Ctx, out: io.Writer) -> (err: io.Error) {
	prefix := min(1, len(ctx.stats))
	for &e in ctx.stats[prefix:] {
		io.write_full(out, nm.bytes(&e.name)) or_return
		write_string(out, ":") or_return
		write_value(out, e, ctx)
		write_string(out, "\n") or_return
	}

	return nil

	write_value :: proc(
		out: io.Writer,
		e: any,
		ctx: Store_Ctx,
		depth: int = 1,
	) -> (
		err: io.Error,
	) {
		switch _ in e {
		case f32,
		     int,
		     bool,
		     Color,
		     Asset_ID,
		     Ent_Stats_ID,
		     Ent_Type,
		     Ent_Stats_Name:
			write_string(out, " ")
		}

		matched := true

		switch &v in e {
		case f32, bool, Ent_Type, int:
			fmt.wprint(out, v)
		case Color:
			cl := v
			if cl & 0xFF == 0xFF do cl >>= 8
			fmt.wprintf(out, "#%x", cl)
		case Asset_ID:
			write_string(out, ctx.sprite_name(ctx.asoc_data, v))
		case Ent_Stats_ID:
			io.write_full(out, nm.bytes(&ctx.stats[v].name))
		case:
			matched = false
		}

		if matched do return nil

		#partial switch info in
			type_info_of(reflect.typeid_base(e.id)).variant {
		case rt.Type_Info_Struct:
			for field in reflect.struct_fields_zipped(e.id) {
				tag := reflect.struct_tag_get(field.tag, "gam")
				if strings.contains(tag, "hidden") do continue

				value := reflect.struct_field_value(e, field)

				if mem.check_zero(reflect.as_bytes(value)) do continue

				write_string(out, "\n") or_return

				for _ in 0 ..< depth do write_string(out, "  ") or_return
				write_string(out, field.name) or_return
				write_string(out, ":") or_return
				write_value(out, value, ctx, depth + 1)
			}
		case:
			log.error("unhandled type for storing:", e.id)
		}

		return nil

	}

	write_string :: proc(
		out: io.Writer,
		str: string,
	) -> (
		n: int,
		err: io.Error,
	) {
		return io.write_full(out, transmute([]u8)str)
	}
}

when false {
	@(test)
	test_store_config :: proc(t: ^testing.T) {
		context.allocator = context.temp_allocator

		names := []string{"", "arma", "foreign"}
		stats := []Ent_Stats {
			{},
			{kind = .Unit, speed = 100, sprite = {Asset_ID = 1}, id = 1},
			{
				kind = .PowerSource,
				energy = 10,
				sprite = {Asset_ID = 2},
				id = 2,
			},
		}

		for i in 0 ..< len(names) {
			stats[i].name = nm.from_str(names[i])
		}

		ctx: Store_Ctx
		ctx.asoc_data = &names
		ctx.sprite_name = proc(asoc_data: rawptr, id: Asset_ID) -> string {
			return (^[]string)(asoc_data)^[id.index]
		}
		ctx.stats = stats

		bl: strings.Builder
		writer := strings.to_writer(&bl)

		err := store_config(ctx, writer)
		assert(err == nil)

		assert_ml_string(
			t,
			string(bl.buf[:]),
			`
		arma:
		  kind: Unit
		  physics:
		    speed: 100
		    sprite: arma
		foreign:
		  kind: PowerSource
		  physics:
		    sprite: foreign
		  health:
		    energy: 10
	`,
		)

		loader: Asset_Loader
		loader.asoc_data = &names
		loader.load_sprite = proc(
			loader: ^Asset_Loader,
			name: string,
		) -> (
			id: Asset_Idx,
			err: string,
		) {
			names := (^[]string)(loader.asoc_data)^
			for i in 0 ..< len(names) {
				if names[i] == name {
					return Asset_Idx(i), ""
				}
			}
			panic("BUG: sprite not found")
		}
		loader.path = "test.conf"
		loader.source = string(bl.buf[:])

		load_config(&loader)

		for s, i in loader.stats {
			testing.expect(t, reflect.eq(s, stats[i], true))
		}
	}
}
