package sim

import "../util/nm"
import "base:intrinsics"
import "base:runtime"
import "core:log"
import "core:mem"
import "core:reflect"
import "core:slice"
import "core:testing"

SPRITE_DIR :: "config/sprites"
MAP_DIR :: "config/maps"
MAP_EXT :: ".gmap"
SPRITE_EXT :: ".png"

@(rodata)
EXT_BY_TYPE := [Asset_Type]string {
	.Map    = MAP_EXT,
	.Sprite = SPRITE_EXT,
}

@(rodata)
DIR_BY_TYPE := [Asset_Type]string {
	.Map    = MAP_DIR,
	.Sprite = SPRITE_DIR,
}

Relative_File_Slice :: struct {
	offset: int,
	len:    int,
}

Any_File_Slice :: struct #raw_union {
	custom:      Any_Encoding,
	absolute:    runtime.Raw_Slice,
	using inner: Relative_File_Slice,
}

match_slice :: proc(
	id: typeid,
) -> (
	slice: ^runtime.Type_Info_Slice,
	ok: bool,
) {
	id := id
	if id == string do id = ([]u8)
	if id == Custom_Encoding do return nil, true
	return(
		&type_info_of(reflect.typeid_base(id)).variant.(runtime.Type_Info_Slice) \
	)
}

unmarshall_as :: proc($T: typeid, data: []u8) -> (res: T, ok: bool) {
	unmarshall(res, data) or_return
	ok = true
	return
}

unmarshall :: proc(header: any, data: []u8) -> (ok: bool) {
	if bytes, ok := &header.([]u8); ok {
		bytes^ = data
		return true
	}

	copy(reflect.as_bytes(header), data)

	{
		context.user_ptr = raw_data(data)
		context.user_index = len(data)
		traverse_recur(
			header,
			{pre_slice = pre_slice, enum_ = enum_},
		) or_return

		pre_slice :: proc(
			info: ^runtime.Type_Info_Slice,
			slice: ^Any_File_Slice,
		) -> bool {
			info := info
			data := ([^]u8)(context.user_ptr)[:context.user_index]

			if info == nil do info = match_slice([]u8) or_else panic("")

			if slice.offset < 0 {
				log.error("slice offset is negative")
				return false
			}

			if slice.len < 0 {
				log.error("slice len is negative")
				return false
			}

			flen, flov := intrinsics.overflow_mul(slice.len, info.elem_size)
			if flov do return false
			ubound, ubov := intrinsics.overflow_add(slice.offset, flen)
			if ubov do return false

			if ubound > len(data) {
				log.error("slice extends beyond data")
				return false
			}

			slice.absolute.data = raw_data(data[slice.offset:])
			if !mem.is_aligned(slice.absolute.data, info.elem.align) {
				log.error("slice data is not aligned")
				return false
			}

			return true
		}

		enum_ :: proc(info: ^runtime.Type_Info_Enum, value: int) -> bool {
			for v in info.values {
				if v == runtime.Type_Info_Enum_Value(value) do return true
			}

			log.error("enum has invalid value")
			return false
		}
	}

	return true

}

Custom_Encoding :: struct #raw_union {
	raw:   []u8,
	value: Any_Encoding,
}

Any_Encoding :: struct {
	data:   rawptr,
	encode: proc(data: rawptr, encoder: ^Encoder) -> bool,
}

serialize_to_bytes :: proc(
	header: any,
	allocator := context.allocator,
) -> []u8 {
	e: Encoder

	ok := serialize(header, &e)
	assert(ok)

	buf, _ := mem.alloc_bytes(encoded_len(&e), 8, allocator)

	e = {buf}
	ok = serialize(header, &e)
	assert(ok)

	return buf
}

serialize :: proc(
	header: any,
	e: ^Encoder,
	buffer_len: int = -1,
) -> (
	ok: bool,
) {
	if bytes, ok := header.([]u8); ok {
		return encode_slice(e, bytes)
	}

	buffer_len := buffer_len if buffer_len != -1 else len(e.remining)

	header_slot := encoder_reserve(e, reflect.size_of_typeid(header.id))

	{
		context.user_ptr = e
		context.user_index = buffer_len
		traverse_recur(header, {post_slice = post_slice}) or_return

		post_slice :: proc(
			info: ^runtime.Type_Info_Slice,
			slice: ^Any_File_Slice,
		) -> (
			ok: bool,
		) {
			info := info
			e := (^Encoder)(context.user_ptr)
			buffer_len := context.user_index

			was_custom := info == nil
			if was_custom do info = match_slice([]u8) or_else panic("")

			tmp_data := slice.absolute.data

			offset :=
				encoder_is_measuring(e) ? encoded_len(e) : buffer_len - len(e.remining)
			aligned := mem.align_forward_int(offset, info.elem.align)
			encoder_reserve(e, aligned - offset)

			if !encoder_is_measuring(e) {
				slice.offset = aligned
			}

			if was_custom {
				prev := len(e.remining)
				slice.custom.encode(tmp_data, e) or_return
				if !encoder_is_measuring(e) {
					slice.len = prev - len(e.remining)
				}
			} else {
				encode_slice(
					e,
					([^]u8)(tmp_data)[:slice.len * info.elem_size],
				) or_return
			}

			return true
		}
	}

	copy(header_slot, reflect.as_bytes(header))

	written := buffer_len - len(e.remining)
	aligned := mem.align_forward_int(written, 8)
	encoder_reserve(e, aligned - written)

	return true
}

Visitor :: struct {
	pre_slice:  proc(_: ^runtime.Type_Info_Slice, _: ^Any_File_Slice) -> bool,
	post_slice: proc(_: ^runtime.Type_Info_Slice, _: ^Any_File_Slice) -> bool,
	enum_:      proc(_: ^runtime.Type_Info_Enum, _: int) -> bool,
}

traverse_recur :: proc(header: any, visitor: Visitor) -> (ok: bool) {
	switch &h in header {
	case int,
	     [2]int,
	     Color,
	     Ent_Team_ID,
	     Ent_ID,
	     Ent_Stats_ID,
	     Vec,
	     u32,
	     f32,
	     nm.Name,
	     Hash,
	     Secret_Key,
	     Ping_ID,
	     Ping_Tag,
	     bool,
	     Ent_Stats_Ref,
	     Identity,
	     Player_Permissions,
	     bit_set[Client_Input_Key],
	     Asset_ID,
	     [Map_Sprite_Kind]Asset_ID:
		return true
	}

	if slice_info, ok := match_slice(header.id); ok {
		slice := (^Any_File_Slice)(header.data)

		if visitor.pre_slice != nil do visitor.pre_slice(slice_info, slice) or_return

		if slice_info != nil && slice_info.elem.id != u8 {
			i := 0
			for elem, _ in reflect.iterate_array(header, &i) {
				if !traverse_recur(elem, visitor) {
					log.error("failed to traverse slice")
					return false
				}
			}
		}

		if visitor.post_slice != nil do visitor.post_slice(slice_info, slice) or_return

		return true
	}

	#partial switch &info in
		type_info_of(reflect.typeid_base(header.id)).variant {
	case runtime.Type_Info_Struct:
		if .raw_union in info.flags do break

		for field in reflect.struct_fields_zipped(header.id) {
			value := reflect.struct_field_value(header, field)
			if !traverse_recur(value, visitor) {
				log.error("failed to traverse struct", field.name)
				return false
			}
		}
		return true
	case runtime.Type_Info_Union:
		if !info.no_nil do break

		tag := reflect.get_union_variant_raw_tag(header)
		if tag < 0 || int(tag) >= len(info.variants) {
			log.error("failed to traverse union, invalid tag", tag)
			return false
		}

		header := reflect.get_union_variant(header)
		return traverse_recur(header, visitor)
	case runtime.Type_Info_Enum:
		value := reflect.as_int(header) or_return

		if visitor.enum_ != nil {
			if visitor.enum_(&info, value) do return true
		} else {
			return true
		}
	}

	log.error("unhandled type for serialization:", header.id)
	return false
}

@(test)
test_serialize_populate :: proc(t: ^testing.T) {
	Bundle_Header :: struct {
		version: int,
		files:   []Bundle_File_Header,
		smh:     union #no_nil {
			i32,
			[]u8,
		},
		cust:    Custom_Encoding,
	}

	Bundle_File_Type :: enum int {
		Config,
		Sprite,
		Map,
	}

	Bundle_File_Header :: struct {
		type: Bundle_File_Type,
		name: string,
		data: []u8,
	}

	files := Bundle_Header {
		version = 1,
		files = {
			{
				type = .Config,
				name = "test",
				data = transmute([]u8)string("oneon"),
			},
			{
				type = .Sprite,
				name = "foo",
				data = transmute([]u8)string("bazos"),
			},
		},
		smh = transmute([]u8)string("sm"),
		cust = {value = {nil, encode_cust}},
	}

	encode_cust :: proc(vl: rawptr, e: ^Encoder) -> bool {
		return encode(e, u8(0))
	}

	buf: [256]u8
	e := Encoder{buf[:]}

	okk := serialize(files, &e)
	testing.expect(t, okk)

	bufa := buf[:len(buf) - len(e.remining)]

	d := Decoder{buf[:]}
	nfiles, ok := decode(&d, Bundle_Header)
	testing.expect(t, ok)

	ok = unmarshall(nfiles, bufa)
	testing.expect(t, ok)
	testing.expect(t, slice.equal(nfiles.cust.raw, []u8{0}))
}
