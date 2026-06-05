package sim

import "base:intrinsics"
import "base:runtime"
import "core:log"
import "core:mem"
import "core:reflect"
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

Bundle_Header :: struct {
	version: int,
	files:   []Bundle_File_Header,
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

File_Slice :: struct($T: typeid) #raw_union {
	absolute:       []T,
	using relative: Relative_File_Slice,
}

Relative_File_Slice :: struct {
	offset: int,
	len:    int,
}

Any_File_Slice :: struct #raw_union {
	absolute:    runtime.Raw_Slice,
	using inner: Relative_File_Slice,
}

load_sprite :: proc(
	loader: ^Asset_Loader,
	path: string,
) -> (
	Asset_ID,
	string,
) {
	files := (^[]Bundle_File_Header)(loader.asoc_data)^

	id: int
	for file in files {
		if file.type != .Sprite do continue
		id += 1
		if file.name == path {
			return Asset_ID(id), ""
		}
	}

	return 0, "sprite not found in the bundle"
}

match_slice :: proc(
	id: typeid,
) -> (
	slice: ^runtime.Type_Info_Slice,
	ok: bool,
) {
	id := id
	if id == string do id = ([]u8)
	return(
		&type_info_of(reflect.typeid_base(id)).variant.(runtime.Type_Info_Slice) \
	)
}

header_populate :: proc(header: any, data: []u8) -> (ok: bool) {
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
			data := ([^]u8)(context.user_ptr)[:context.user_index]

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

header_serialize :: proc(
	header: any,
	e: ^Encoder,
	buffer_len: int = -1,
) -> (
	ok: bool,
) {
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
			e := (^Encoder)(context.user_ptr)
			buffer_len := context.user_index

			tmp_data := slice.absolute.data

			offset :=
				encoder_is_measuring(e) ? encoded_len(e) : buffer_len - len(e.remining)
			aligned := mem.align_forward_int(offset, info.elem.align)
			encoder_reserve(e, aligned - offset)

			if !encoder_is_measuring(e) {
				slice.offset = aligned
			}

			encode_slice(
				e,
				([^]u8)(tmp_data)[:slice.len * info.elem_size],
			) or_return

			return true
		}
	}

	copy(header_slot, reflect.as_bytes(header))

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
	     Asset_ID,
	     [Map_Sprite_Kind]Asset_ID:
		return true
	}

	if slice_info, ok := match_slice(header.id); ok {
		slice := (^Any_File_Slice)(header.data)

		if visitor.pre_slice != nil do visitor.pre_slice(slice_info, slice) or_return

		if slice_info.elem.id != u8 {
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
		for field in reflect.struct_fields_zipped(header.id) {
			value := reflect.struct_field_value(header, field)
			if !traverse_recur(value, visitor) {
				log.error("failed to traverse struct", field.name)
				return false
			}
		}
		return true
	case runtime.Type_Info_Enum:
		if info.base.id != int do break

		value := (^int)(header.data)^

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
	files := Bundle_Header {
		version = 1,
		files   = {
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
	}

	buf: [256]u8
	e := Encoder{buf[:]}

	okk := header_serialize(files, &e)
	testing.expect(t, okk)

	bufa := buf[:len(buf) - len(e.remining)]

	d := Decoder{buf[:]}
	nfiles, ok := decode(&d, Bundle_Header)
	testing.expect(t, ok)

	ok = header_populate(nfiles, bufa)
	testing.expect(t, ok)
}
