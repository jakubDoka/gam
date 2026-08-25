package sim

import "../util/arna"
import "base:runtime"
import "core:log"
import "core:mem"
import "core:reflect"
import "core:slice"
import "core:strconv"
import "core:strings"
import "core:testing"

CC_FACTORS := [CC_Float_Prec]f32 {
	.Full_Prec = 0,
	.Prec2     = 100,
	.Prec1     = 10,
	.Fixed     = 1,
}

CC_Float_Prec :: enum uint {
	Full_Prec,
	Prec2,
	Prec1,
	Fixed,
}

Version :: u32

CC_Ctx :: struct {
	presence:    Field_Presence,
	using flags: CC_Flags,
}

CC_Flags :: bit_field int {
	version:    Version       | 32,
	float_prec: CC_Float_Prec | 2,
	leb:        bool          | 1,
	is_version: bool          | 1,
}

MAX_ALIGN :: 8

// NOTE: you can later just deallocate the slot to deallocate all
cc_decode_single_alloc :: proc(
	$T: typeid,
	dec: ^Decoder,
	buff: ^arna.Allocator,
	allc := context.allocator,
) -> (
	slot: ^T,
	ok: bool,
) {
	#assert(align_of(T) <= MAX_ALIGN)

	context.allocator = arna.allocator(buff)
	prev_pos := buff.pos
	err: runtime.Allocator_Error
	slot, err = new_aligned(T, MAX_ALIGN)
	if err != nil do return
	idec := dec^
	cc_decode(slot^, &idec, {}) or_return

	context.allocator = allc
	// NOTE: this can be bigger then nescessary, but eh?
	buf, errr := mem.alloc_bytes(int(buff.pos - prev_pos), MAX_ALIGN)
	assert(errr == nil)
	buff.pos = prev_pos

	buf_arna := arna.init_from_buffer(buf)
	context.allocator = arna.allocator(&buf_arna)
	slot, err = new_aligned(T, MAX_ALIGN)
	assert(err == nil)

	ok = cc_decode(slot^, dec, {})
	assert(ok)

	return slot, true
}

@(require_results)
cc_decode :: proc(vl: any, e: ^Decoder, flags: CC_Ctx) -> (ok: bool) {
	defer {
		assert(ok)
	}

	info := type_info_of(vl.id)

	bytes := reflect.as_bytes(vl)

	assert(reflect.align_of_typeid(vl.id) <= MAX_ALIGN)

	@(require_results)
	decode_fixed :: proc(vl: any, e: ^Decoder) -> bool {
		copy(
			reflect.as_bytes(vl),
			decode_slice(e, reflect.size_of_typeid(vl.id)) or_return,
		)
		return true
	}

	switch t in info.variant {
	case runtime.Type_Info_Named:
		cc_decode({vl.data, t.base.id}, e, flags) or_return
	case runtime.Type_Info_Integer:
		if flags.leb {
			slt: i128
			if t.signed {
				slt = decode_leb128(e, i128) or_return
			} else {
				slt = i128(decode_leb128(e, u128) or_return)
			}
			copy(bytes, mem.ptr_to_bytes(&slt))
		} else {
			decode_fixed(vl, e) or_return
		}
	case runtime.Type_Info_Float:
		switch flags.float_prec {
		case .Full_Prec:
			decode_fixed(vl, e) or_return
		case .Prec2, .Prec1, .Fixed:
			iv := decode_leb128(e, i128) or_return
			(&vl.(f32))^ = f32(iv) / CC_FACTORS[flags.float_prec]
		}
	case runtime.Type_Info_Rune,
	     runtime.Type_Info_Complex,
	     runtime.Type_Info_Quaternion,
	     runtime.Type_Info_Boolean,
	     runtime.Type_Info_Enum,
	     runtime.Type_Info_Bit_Set,
	     runtime.Type_Info_Bit_Field:
		decode_fixed(vl, e) or_return
	case runtime.Type_Info_String:
		ln := int(decode_leb128(e, uint) or_return)
		if ln < 0 do return false
		(&vl.(string))^ = string(slice.clone(decode_slice(e, ln) or_return))
	case runtime.Type_Info_Pointer:
		if (decode_leb128(e, u8) or_return) != 0 {
			slot, err := mem.alloc(reflect.size_of_typeid(vl.id), MAX_ALIGN)
			if err != nil do return false
			cc_decode({slot, t.elem.id}, e, flags) or_return
			(^rawptr)(vl.data)^ = slot
		}
	case runtime.Type_Info_Enumerated_Array:
		if t.is_sparse {
			panic("unsupported type: sparse enumerated array")
		}
		for i in 0 ..< t.count {
			elem := any {
				rawptr(uintptr(vl.data) + uintptr(t.elem_size * i)),
				t.elem.id,
			}
			cc_decode(elem, e, flags) or_return
		}
	case runtime.Type_Info_Array:
		for i: int; el, _ in reflect.iterate_array(vl, &i) {
			cc_decode(el, e, flags) or_return
		}
	case runtime.Type_Info_Fixed_Capacity_Dynamic_Array:
		ln := int(decode_leb128(e, uint) or_return)
		if ln < 0 do return false

		(^int)(uintptr(vl.data) + t.len_offset)^ = ln
		for i: int; el, _ in reflect.iterate_array(vl, &i) {
			cc_decode(el, e, flags) or_return
		}
	case runtime.Type_Info_Slice:
		ln := int(decode_leb128(e, uint) or_return)
		if ln < 0 do return false

		raw := (^runtime.Raw_Slice)(vl.data)
		raw.len = ln

		err: mem.Allocator_Error
		raw.data, err = mem.alloc(ln * t.elem_size, MAX_ALIGN)
		if err != nil do return false

		for i: int; el, _ in reflect.iterate_array(vl, &i) {
			cc_decode(el, e, flags) or_return
		}
	case runtime.Type_Info_Struct:
		if .raw_union in t.flags {
			panic("unsupported type: raw union struct")
		}
		flags := flags
		for field in reflect.struct_fields_zipped(vl.id) {
			value := reflect.struct_field_value(vl, field)
			collect_flags(&flags, field.tag) or_continue
			cc_decode(value, e, flags) or_return
			if flags.is_version {
				flags.version = value.(Version)
				flags.is_version = false
			}
		}
	case runtime.Type_Info_Union:
		var_idx := decode_leb128(e, uint) or_return
		var_idx -= uint(!t.no_nil)

		if var_idx > len(t.variants) do return false
		reflect.set_union_variant_raw_tag(vl, i64(var_idx))

		cc_decode(reflect.get_union_variant(vl), e, flags) or_return
	case runtime.Type_Info_Any:
		panic("unsupported type: any")
	case runtime.Type_Info_Type_Id:
		panic("unsupported type: typeid")
	case runtime.Type_Info_Multi_Pointer:
		panic("unsupported type: multi pointer")
	case runtime.Type_Info_Procedure:
		panic("unsupported type: proc")
	case runtime.Type_Info_Dynamic_Array:
		panic("unsupported type: dyn array")
	case runtime.Type_Info_Parameters:
		panic("unsupported type: parameters")
	case runtime.Type_Info_Map:
		panic("unsupported type: map")
	case runtime.Type_Info_Simd_Vector:
		panic("unsupported type: simd")
	case runtime.Type_Info_Matrix:
		panic("unsupported type: matrix")
	case runtime.Type_Info_Soa_Pointer:
		panic("unsupported type: soa pointer")
	}

	return true
}

@(require_results)
cc_encode :: proc(vl: any, e: ^Encoder, flags: CC_Ctx) -> bool {
	info := type_info_of(vl.id)

	bytes := reflect.as_bytes(vl)

	switch t in info.variant {
	case runtime.Type_Info_Named:
		cc_encode({vl.data, t.base.id}, e, flags) or_return
	case runtime.Type_Info_Integer:
		if flags.leb {
			slt: i128
			copy(mem.ptr_to_bytes(&slt), bytes)
			if t.signed {
				encode_leb128(e, slt) or_return
			} else {
				encode_leb128(e, u128(slt)) or_return
			}
		} else {
			encode_slice(e, bytes) or_return
		}
	case runtime.Type_Info_Float:
		switch flags.float_prec {
		case .Full_Prec:
			encode_slice(e, bytes) or_return
		case .Prec2, .Prec1, .Fixed:
			v := vl.(f32)
			encode_leb128(e, i128(v * CC_FACTORS[flags.float_prec]))
		}
	case runtime.Type_Info_Rune,
	     runtime.Type_Info_Complex,
	     runtime.Type_Info_Quaternion,
	     runtime.Type_Info_Boolean,
	     runtime.Type_Info_Enum,
	     runtime.Type_Info_Bit_Set,
	     runtime.Type_Info_Bit_Field:
		encode_slice(e, bytes) or_return
	case runtime.Type_Info_String:
		v := vl.(string)
		encode_leb128(e, uint(len(v))) or_return
		encode_slice(e, transmute([]u8)v) or_return
	case runtime.Type_Info_Pointer:
		if reflect.is_nil(vl) {
			encode_leb128(e, u8(0)) or_return
		} else {
			encode_leb128(e, u8(1)) or_return
			cc_encode(reflect.deref(vl), e, flags) or_return
		}
	case runtime.Type_Info_Enumerated_Array:
		if t.is_sparse {
			panic("unsupported type: sparse enumerated array")
		}
		for i in 0 ..< t.count {
			elem := any {
				rawptr(uintptr(vl.data) + uintptr(t.elem_size * i)),
				t.elem.id,
			}
			cc_encode(elem, e, flags) or_return
		}
	case runtime.Type_Info_Array:
		for i: int; el, _ in reflect.iterate_array(vl, &i) {
			cc_encode(el, e, flags) or_return
		}
	case runtime.Type_Info_Fixed_Capacity_Dynamic_Array,
	     runtime.Type_Info_Slice:
		encode_leb128(e, uint(reflect.length(vl))) or_return
		for i: int; el, _ in reflect.iterate_array(vl, &i) {
			cc_encode(el, e, flags) or_return
		}
	case runtime.Type_Info_Struct:
		flags := flags
		for field in reflect.struct_fields_zipped(vl.id) {
			value := reflect.struct_field_value(vl, field)
			collect_flags(&flags, field.tag) or_continue
			if flags.is_version {
				flags.version = value.(Version)
				flags.is_version = false
			}
			cc_encode(value, e, flags) or_return
		}
	case runtime.Type_Info_Union:
		encode_leb128(e, uint(reflect.get_union_variant_raw_tag(vl)))
		cc_encode(reflect.get_union_variant(vl), e, flags) or_return
	case runtime.Type_Info_Any:
		panic("unsupported type: any")
	case runtime.Type_Info_Type_Id:
		panic("unsupported type: typeid")
	case runtime.Type_Info_Multi_Pointer:
		panic("unsupported type: multi pointer")
	case runtime.Type_Info_Procedure:
		panic("unsupported type: proc")
	case runtime.Type_Info_Dynamic_Array:
		panic("unsupported type: dyn array")
	case runtime.Type_Info_Parameters:
		panic("unsupported type: parameters")
	case runtime.Type_Info_Map:
		panic("unsupported type: map")
	case runtime.Type_Info_Simd_Vector:
		panic("unsupported type: simd")
	case runtime.Type_Info_Matrix:
		panic("unsupported type: matrix")
	case runtime.Type_Info_Soa_Pointer:
		panic("unsupported type: soa pointer")
	}

	return true
}

collect_flags :: proc(
	base: ^CC_Flags,
	tag: reflect.Struct_Tag,
) -> (
	active := true,
) {
	field_flags := reflect.struct_tag_get(tag, "cc")
	for flg in strings.split_iterator(&field_flags, ",") {
		if flg == "version_field" {
			base.is_version = true
		} else if strings.starts_with(flg, "v") {
			version := Version(
				strconv.parse_int(flg[1:]) or_else panic(
					"version must be a number",
				),
			)
			active &= base.version >= version
			base.version = max(base.version, version)
		} else if flg == "fixed" {
			base.float_prec = .Fixed
		} else if flg == "round1" {
			base.float_prec = .Prec1
		} else if flg == "round2" {
			base.float_prec = .Prec2
		} else if flg == "leb" {
			base.leb = true
		}
	}

	return
}

@(test)
sanity_cc :: proc(t: ^testing.T) {

	Idx :: enum {
		A,
		B,
	}

	Example :: struct {
		version:    Version `cc:"version_field"`,
		vls:        []int `cc:"leb"`,
		flts:       [6]f32 `cc:"round1"`,
		fixed_flts: [Idx]f32 `cc:"fixed"`,
		nested:     struct {
			a: int `cc:"leb"`,
			c: f32,
			d: f32,
		} `cc:"round2"`,
		uni:        union #no_nil {
			int,
			f32,
		},
		ptr:        ^int `cc:"leb"`,
		str:        string,
		sup:        [dynamic; 8]u8,
	}

	vl := 1
	ex := Example {
		vls = {1, 2, 1000},
		flts = {0.5, 0.6, 0.1, 60.1, 0.1, 0.4},
		fixed_flts = {.A = 100, .B = 200},
		nested = {a = 1, c = 100.01, d = 0.11},
		uni = f32(1),
		str = "foor",
		ptr = &vl,
		sup = {0, 1, 2, 4},
	}

	gpa := context.allocator

	scratch: [100]u8
	e := Encoder{scratch[:]}

	ok := cc_encode(ex, &e, {})
	assert(ok)

	ExampleV2 :: struct {
		version:    Version `cc:"version_field"`,
		vls:        []int `cc:"leb"`,
		flts:       [6]f32 `cc:"round1"`,
		fixed_flts: [Idx]f32 `cc:"fixed"`,
		nested:     struct {
			a:   int `cc:"leb"`,
			add: f32 `cc:"v1"`,
			c:   f32,
			d:   f32,
		} `cc:"round2"`,
		uni:        union #no_nil {
			int,
			f32,
		},
		ptr:        ^int,
		str:        string,
		sup:        [dynamic; 8]u8,
	}

	space: [300]u8
	arena := arna.init_from_buffer(space[:])
	context.allocator = arna.allocator(&arena)

	slot: ExampleV2
	d := Decoder{scratch[:len(scratch) - len(e.remining)]}

	ok = cc_decode(slot, &d, {})
	assert(ok)

	compare :: proc(
		t: ^testing.T,
		ex: Example,
		slot: ExampleV2,
		loc := #caller_location,
	) {
		testing.expect(
			t,
			reflect.equal(ex.version, slot.version, true),
			loc = loc,
		)
		testing.expect(t, reflect.equal(ex.vls, slot.vls, true), loc = loc)
		testing.expect(t, reflect.equal(ex.flts, slot.flts, true), loc = loc)
		testing.expect(
			t,
			reflect.equal(ex.fixed_flts, slot.fixed_flts, true),
			loc = loc,
		)
		testing.expect(
			t,
			reflect.equal(ex.nested.a, slot.nested.a, true),
			loc = loc,
		)
		testing.expect(
			t,
			reflect.equal(ex.nested.c, slot.nested.c, true),
			loc = loc,
		)
		testing.expect(
			t,
			reflect.equal(ex.nested.d, slot.nested.d, true),
			loc = loc,
		)
		testing.expect(t, reflect.equal(ex.uni, slot.uni, true), loc = loc)
		testing.expect(t, reflect.equal(ex.str, slot.str, true), loc = loc)
		testing.expect(t, reflect.equal(ex.ptr^, slot.ptr^, true), loc = loc)
	}

	compare(t, ex, slot)

	free_all(context.allocator)
	context.allocator = gpa

	d = Decoder{scratch[:len(scratch) - len(e.remining)]}
	slota, oka := cc_decode_single_alloc(ExampleV2, &d, &arena)
	assert(oka)

	compare(t, ex, slota^)

	free(slota)
}
