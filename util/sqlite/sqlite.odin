package sqlite

import "../nm"
import "base:runtime"
import "core:c"
import "core:fmt"
import "core:log"
import "core:os"
import "core:reflect"
import "core:strings"
import "core:testing"

stc :: strings.unsafe_string_to_cstring

Open_Filename :: union #no_nil {
	cstring,
	string,
}

open :: proc(
	filename: Open_Filename,
	flags := Open_Flags{.READWRITE, .CREATE},
	vfs: cstring = nil,
) -> (
	conn: Connection,
	res: Result_Code,
) {

	filename_cstr: cstring
	switch fn in filename {
	case cstring:
		filename_cstr = fn
	case string:
		db_path_cstr, db_path_cstr_err := strings.clone_to_cstring(
			fn,
			context.temp_allocator,
		)
		assert(db_path_cstr_err == nil)

		filename_cstr = db_path_cstr
	}

	res = _open_v2(filename_cstr, &conn, flags, vfs)
	return
}

exec :: proc {
	exec_batch,
	exec_prepared,
}

exec_batch :: proc(db: Connection, sql: cstring) {
	msg: cstring
	err := _exec(db, sql, nil, nil, &msg)
	if err != .OK do log.error("exec sqlite error:", err, msg)
	assert_ok(db, err, "while executing")
}

@(require_results)
exec_prepared :: proc(
	stmt: Statement,
	args: ..any,
	loc := #caller_location,
) -> (
	changes_: int,
	res: Result_Code,
) {
	bind_many(stmt, ..args, loc = loc)

	step_res := step(stmt)
	reset_res := reset(stmt)

	if step_res != .DONE {
		assert(step_res != .OK)
		return 0, step_res
	}
	if reset_res != .OK do return 0, reset_res

	return int(changes(db_handle(stmt))), res
}

bind :: proc(
	stmt: Statement,
	param_idx: int,
	arg: any,
	loc := #caller_location,
) {
	err: Result_Code
	pidx := c.int(param_idx)
	switch &a in arg {
	case cstring:
		err = _bind_text(stmt, pidx, a, -1, {})
	case string:
		if len(a) == 0 {
			err = _bind_text(stmt, pidx, "", 0, {})
		} else {
			err = _bind_text(stmt, pidx, stc(a), c.int(len(a)), {})
		}
	case nm.Name:
		va := nm.str(&a)
		if len(va) == 0 {
			err = _bind_text(stmt, pidx, "", 0, {})
		} else {
			err = _bind_text(stmt, pidx, stc(va), c.int(len(va)), {})
		}
	case int:
		err = _bind_int64(stmt, pidx, i64(a))
	case u32:
		err = _bind_int64(stmt, pidx, i64(a))
	case u64:
		err = _bind_int64(stmt, pidx, i64(a))
	case i64:
		err = _bind_int64(stmt, pidx, a)
	case f64:
		err = _bind_double(stmt, pidx, a)
	case f32:
		err = _bind_double(stmt, pidx, f64(a))
	case []u8:
		err = _bind_blob(stmt, pidx, raw_data(a), c.int(len(a)), {})
	case nil:
		err = _bind_null(stmt, pidx)
	case:
		#partial switch info in type_info_of(arg.id).variant {
		case runtime.Type_Info_Union:
			if !(^bool)(rawptr(uintptr(arg.data) + info.tag_offset))^ {
				err = _bind_null(stmt, pidx)
				break
			}

			opt_dest := any{arg.data, info.variants[0].id}
			bind(stmt, param_idx, opt_dest, loc)
		case runtime.Type_Info_Named:
			bind(stmt, param_idx, any{arg.data, info.base.id}, loc)
		case runtime.Type_Info_Array:
			assert(info.elem_size == 1)
			bind(stmt, param_idx, ([^]u8)(arg.data)[:info.count], loc)
		case runtime.Type_Info_Bit_Set:
			bind(stmt, param_idx, {arg.data, info.underlying.id}, loc)
		case runtime.Type_Info_Enum:
			bind(stmt, param_idx, {arg.data, info.base.id}, loc)
		case runtime.Type_Info_Fixed_Capacity_Dynamic_Array:
			len_slot := (^int)(rawptr(uintptr(arg.data) + info.len_offset))
			src := _bind_blob(
				stmt,
				i32(param_idx),
				([^]u8)(arg.data),
				i32(len_slot^),
				{},
			)
		case:
			log.error(
				"unsupported column type:",
				arg.id,
				type_info_of(arg.id).variant,
				location = loc,
			)
		}
	}
	assert_ok(stmt, err, "while binding", param_idx, "with", arg)
}

bind_many :: proc(stmt: Statement, args: ..any, loc := #caller_location) {
	assert(len(args) == int(bind_parameter_count(stmt)), loc = loc)
	for arg, i in args do bind(stmt, i + 1, arg, loc = loc)
}

prepare :: proc {
	prepare_stmt,
	prepare_struct,
}

prepare_stmt :: proc(
	slot: ^Statement,
	db: Connection,
	sql: string,
	loc := #caller_location,
) {
	err := _prepare_v2(db, stc(sql), c.int(len(sql)), slot, nil)
	assert_ok(db, err, "while preparing", sql, loc = loc)
}

prepare_struct :: proc(
	db: Connection,
	statements: any,
	loc := #caller_location,
) {
	info := runtime.type_info_base(type_info_of(statements.id)).variant.(runtime.Type_Info_Struct)

	for i in 0 ..< info.field_count {
		assert(info.types[i].id == typeid_of(Statement))
		offset := info.offsets[i]
		slot := (^Statement)(rawptr(uintptr(statements.data) + offset))
		prepare(slot, db, info.tags[i], loc)
	}
}

finalize :: proc {
	finalize_slot,
	finalize_stmt,
	finalize_struct,
}

finalize_slot :: proc(statement: ^Statement) {
	if statement^ == {} do return
	finalize(statement^)
	statement^ = {}
}

finalize_stmt :: proc(statement: Statement) {
	db := db_handle(statement)
	res := _finalize(statement)
	assert_ok(db, res)
}

finalize_struct :: proc(statements: any) {
	info := runtime.type_info_base(type_info_of(statements.id)).variant.(runtime.Type_Info_Struct)

	for i in 0 ..< info.field_count {
		assert(info.types[i].id == typeid_of(Statement))
		offset := info.offsets[i]
		slot := (^Statement)(rawptr(uintptr(statements.data) + offset))^
		finalize(slot)
	}
}

Connection_Or_Statement :: union {
	Connection,
	Statement,
}

@(disabled = ODIN_DISABLE_ASSERT)
assert_ok :: proc(
	dbos: Connection_Or_Statement,
	res: Result_Code,
	extra: ..any,
	message: string = #caller_expression(res),
	loc := #caller_location,
) {

	db: Connection
	switch v in dbos {
	case Connection:
		db = v
	case Statement:
		db = db_handle(v)
	case:
		log.error("invalid dbos type")
	}

	if res != .OK {
		extra := fmt.tprint(..extra)
		log.error("sqlite error:", res, errmsg(db), extra, location = loc)
	}
	assert(res == .OK, message, loc)
}

resolve_column_projection :: proc(stmt: Statement, R: typeid) -> []u8 {
	buf: [dynamic]u8
	buf.allocator = context.temp_allocator
	fill_fields(R, stmt, &buf)
	return buf[:]

	fill_fields :: proc(T: typeid, stmt: Statement, buf: ^[dynamic]u8) {
		for f in reflect.struct_fields_zipped(T) {
			if f.is_using {
				fill_fields(f.type.id, stmt, buf)
			} else {
				append(buf, column_index(stmt, f.name))
			}
		}
	}
}

Query :: struct(R: typeid) {
	stmt:              Statement,
	slot:              R,
	column_projection: []u8,
}

column_index :: proc(stmt: Statement, name: string) -> u8 {
	for j in 0 ..< column_count(stmt) {
		if name == string(column_name(stmt, j)) {
			return u8(j + 1)
		}
	}
	return 0
}

query :: proc {
	query_iter,
	query_one,
}

query_one :: proc(
	stmt: Statement,
	slot: any,
	args: ..any,
	column_projection: []u8 = nil,
	loc := #caller_location,
) -> (
	Result_Code,
	Statement,
) {
	res := reset(stmt)
	assert_ok(stmt, res, "while query_one reset", loc = loc)

	bind_many(stmt, ..args, loc = loc)

	return query_next_parts(stmt, slot, column_projection), stmt
}

query_iter :: proc(
	stmt: Statement,
	$R: typeid,
	args: ..any,
	loc := #caller_location,
) -> (
	res: Query(R),
	s: Statement,
) {
	rs := reset(stmt)
	assert_ok(stmt, rs, "while query_itering")

	res.stmt = stmt

	bind_many(stmt, ..args, loc = loc)

	res.column_projection = resolve_column_projection(stmt, R)

	s = stmt

	return
}

query_next :: proc {
	query_next_iter,
	query_next_parts,
}

query_next_iter :: proc(
	query: ^Query($R),
	loc := #caller_location,
) -> (
	slot: ^R,
	ok: bool,
) {
	slot = &query.slot
	res := query_next_parts(query.stmt, query.slot, query.column_projection)
	ok = res == .OK
	if res == .DONE do return

	assert_ok(
		query.stmt,
		res,
		"while stepping trough the query",
		typeid_of(type_of(query.slot)),
		loc = loc,
	)

	return
}

query_next_parts :: proc(
	stmt: Statement,
	slot: any,
	column_projection: []u8 = nil,
) -> (
	res: Result_Code,
) {
	res = step(stmt)

	#partial switch res {
	case .ROW:
		_, ok := runtime.type_info_base(type_info_of(slot.id)).variant.(runtime.Type_Info_Struct)

		if ok && slot.id != nm.Name {
			i := 0
			struct_column(stmt, slot, &i, column_projection)
		} else {
			column(stmt, 1, slot)
		}

		res = .OK
	case:
	}

	return
}

struct_column :: proc(
	stmt: Statement,
	dest: any,
	i: ^int,
	column_projection: []u8,
) {
	for field in reflect.struct_fields_zipped(dest.id) {
		dest := reflect.struct_field_value(dest, field)

		if field.is_using {
			struct_column(stmt, dest, i, column_projection)
		} else {
			colmn: u8
			if column_projection != nil {
				colmn = column_projection[i^]
				i^ += 1
			} else {
				colmn = column_index(stmt, field.name)
			}
			column(stmt, colmn, dest)
		}

	}
}

column :: proc(stmt: Statement, #any_int colmn: int, dest: any) {
	if colmn == 0 do return

	clmn := c.int(colmn - 1)

	bytes := column_bytes(stmt, clmn)

	switch &a in dest {
	case cstring:
		a = cstring(_column_text(stmt, clmn))
	case string:
		a = string(_column_text(stmt, clmn)[:bytes])
	case nm.Name:
		a = nm.from_str(string(_column_text(stmt, clmn)[:bytes]))
	case []u8:
		a = _column_blob(stmt, clmn)[:bytes]
	case int:
		a = int(_column_int64(stmt, clmn))
	case u32:
		a = u32(_column_int64(stmt, clmn))
	case i64:
		a = _column_int64(stmt, clmn)
	case f64:
		a = f64(_column_double(stmt, clmn))
	case f32:
		a = f32(_column_double(stmt, clmn))
	case:
		#partial switch info in type_info_of(dest.id).variant {
		case runtime.Type_Info_Union:
			if column_type(stmt, clmn) == .NULL do return

			opt_dest := any{dest.data, info.variants[0].id}
			column(stmt, colmn, opt_dest)

			(^bool)(rawptr(uintptr(dest.data) + info.tag_offset))^ = true
		case runtime.Type_Info_Named:
			column(stmt, colmn, any{dest.data, info.base.id})
		case runtime.Type_Info_Array:
			assert(info.elem_size == 1)
			src := _column_blob(stmt, clmn)[:bytes]
			dst := ([^]u8)(dest.data)[:info.count]
			copy(dst, src)
		case runtime.Type_Info_Bit_Set:
			column(stmt, colmn, {dest.data, info.underlying.id})
		case runtime.Type_Info_Fixed_Capacity_Dynamic_Array:
			assert(info.elem_size == 1)

			src := _column_blob(stmt, clmn)[:bytes]
			dst := ([^]u8)(dest.data)[:info.capacity]
			copy(dst, src)

			len_slot := (^int)(rawptr(uintptr(dest.data) + info.len_offset))
			len_slot^ = len(src)
		case runtime.Type_Info_Enum:
			column(stmt, colmn, any{dest.data, info.base.id})
		case:
			log.error(
				"unsupported column type:",
				dest.id,
				type_info_of(dest.id).variant,
			)
		}
	}
}

@(test)
test_bindings :: proc(t: ^testing.T) {
	tmp_dir, tmp_dir_err := os.temp_dir(context.temp_allocator)
	assert(tmp_dir_err == nil)

	tmp_path, tmp_path_err := os.join_path(
		{tmp_dir, "test.db"},
		context.temp_allocator,
	)
	assert(tmp_path_err == nil)

	conn, sqlite_open_err := open(tmp_path)
	assert_ok(conn, sqlite_open_err)

	{
		exec(
			conn,
			`
			CREATE TABLE IF NOT EXISTS entities (
				name TEXT PRIMARY KEY,
				foo INTEGER NOT NULL,
				bar REAL NOT NULL,
				baz BLOB NOT NULL,
				qux INTEGER NULL
			);

			DELETE FROM entities;
		`,
		)

		Entity :: struct {
			name: string,
			bar:  f64,
			foo:  int,
			baz:  []u8,
			qux:  Maybe(int),
		}

		stmts: struct {
			insert_entity:        Statement `
				INSERT INTO entities VALUES (?, ?, ?, ?, ?)
			`,
			query_entity:         Statement `
				SELECT * FROM entities
			`,
			query_entity_by_name: Statement `
				SELECT * FROM entities WHERE name = ?
			`,
		}
		prepare(conn, stmts)

		blob := "test"

		cnt, insert_err := exec(
			stmts.insert_entity,
			"test",
			123,
			1.234,
			transmute([]u8)blob,
			nil,
		)
		assert_ok(conn, insert_err)
		assert(cnt == 1)

		cnt, insert_err = exec(
			stmts.insert_entity,
			"test2",
			123,
			1.2,
			transmute([]u8)blob,
			1,
		)
		assert_ok(conn, insert_err)
		assert(cnt == 1)

		query_ent, qs := query(stmts.query_entity, Entity)
		for row in query_next(&query_ent) {
			log.debug(row)
		}
		reset(qs)

		query_ent_filt, qfs := query(
			stmts.query_entity_by_name,
			Entity,
			"test",
		)
		for row in query_next(&query_ent_filt) {
			log.debug(row)
		}
		reset(qfs)

		slot: Entity
		ok, s := query(stmts.query_entity_by_name, slot, "test")
		assert_ok(conn, ok)
		log.debug(slot)
		reset(s)

		simple_slot: struct {
			name: cstring,
		}
		ok, s = query(stmts.query_entity_by_name, simple_slot, "test")
		assert_ok(conn, ok)
		log.debug(simple_slot)
		reset(s)
	}

	{
		exec(
			conn,
			`
			CREATE TABLE IF NOT EXISTS note (
				id INTEGER PRIMARY KEY,
				text TEXT NOT NULL
			);

			DELETE FROM note;
		`,
		)

		stmts: struct {
			insert_note: Statement `
				INSERT INTO note (text) VALUES (?) RETURNING id
			`,
		}
		prepare(conn, stmts)

		id: int
		ok, s := query_one(stmts.insert_note, id, "test note")
		assert_ok(conn, ok)
		assert(id == 1)
		reset(s)

		ok, s = query_one(stmts.insert_note, id, "another note")
		assert_ok(conn, ok)
		assert(id == 2)
		reset(s)
	}

	{
		exec(
			conn,
			`
			CREATE TABLE IF NOT EXISTS fixed_blob (
				id INTEGER PRIMARY KEY,
				blob BLOB NOT NULL
			);
			DELETE FROM fixed_blob;
		`,
		)

		Fixed_Blob :: struct {
			id:   int,
			blob: [32]u8,
		}

		stmts: struct {
			insert_fixed_blob: Statement `
				INSERT INTO fixed_blob (blob) VALUES (?) RETURNING id
			`,
			query_fixed_blob:  Statement `
				SELECT * FROM fixed_blob WHERE id = ?
			`,
		}
		prepare(conn, stmts)

		id: int
		blob: [32]u8
		ok, s := query_one(stmts.insert_fixed_blob, id, blob)
		assert_ok(conn, ok)
		assert(id == 1)
		reset(s)

		row: Fixed_Blob
		ok, s = query_one(stmts.query_fixed_blob, row, id)
		assert_ok(conn, ok)
		assert(row.blob == blob)
		reset(s)
	}

	return
}
