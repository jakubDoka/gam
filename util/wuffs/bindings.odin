package wuffs

import "core:c"

// Opaque handle to a `wuffs_png__decoder`. It is upcast-compatible with
// `wuffs_base__image_decoder`, which is why the same handle is passed to
// both the `Decoder`- and `Image_Decoder`-prefixed procs below.
Decoder :: rawptr

Slice_U8 :: struct {
	ptr: [^]u8,
	len: c.size_t,
}

Io_Buffer_Meta :: struct {
	wi:     c.size_t,
	ri:     c.size_t,
	pos:    u64,
	closed: bool,
}

// Mirrors `wuffs_base__io_buffer`. Built directly in Odin (see `io_buffer_from_slice`)
// since `wuffs_base__ptr_u8__reader`, its C constructor, is a "static inline" function
// with no linkable symbol.
Io_Buffer :: struct {
	data: Slice_U8,
	meta: Io_Buffer_Meta,
}

// Mirrors `wuffs_base__pixel_config`'s private_impl. Manipulated directly
// (see `pixel_config_set`) for the same reason as `Io_Buffer` above.
Pixel_Config :: struct {
	pixfmt_repr: u32,
	pixsub_repr: u32,
	width:       u32,
	height:      u32,
}
#assert(size_of(Pixel_Config) == 16)

// Mirrors `wuffs_base__image_config`. `pixcfg` is a real (non-private) field
// in the C struct, at offset 0, so it can be read/written directly.
Image_Config :: struct {
	pixcfg:  Pixel_Config,
	_opaque: [16]u8, // first_frame_io_position, first_frame_is_opaque
}
#assert(size_of(Image_Config) == 32)

Table_U8 :: struct {
	ptr:    [^]u8,
	width:  c.size_t,
	height: c.size_t,
	stride: c.size_t,
}

// Mirrors `wuffs_base__pixel_buffer`. Only ever populated via
// `pixel_buffer_set_from_slice` and passed opaquely to `decode_frame`, so
// its `planes` are never accessed from Odin.
Pixel_Buffer :: struct {
	pixcfg:  Pixel_Config,
	_opaque: [4]Table_U8, // planes
}
#assert(size_of(Pixel_Buffer) == 144)

// Mirrors `wuffs_base__frame_config`. Opaque: we never read a decoded
// frame's metadata, just need scratch space of the right size to pass in.
Frame_Config :: struct #align (8) {
	_opaque: [48]u8,
}

// A `wuffs_base__status`. A nil `repr` means "ok"; otherwise it is a
// NUL-terminated, statically-allocated C string prefixed with '$' (a
// suspension, e.g. "short read"), '#' (an error) or '@' (a note).
Status :: struct {
	repr: cstring,
}

status_is_ok :: proc(s: Status) -> bool {
	return s.repr == nil
}

Range_Ii_U64 :: struct {
	min_incl: u64,
	max_incl: u64,
}

Pixel_Blend :: enum c.uint32_t {
	SRC      = 0,
	SRC_OVER = 1,
}

// Common interleaved pixel formats (`WUFFS_BASE__PIXEL_FORMAT__*`).
Pixel_Format :: enum u32 {
	INVALID        = 0x00000000,
	RGB            = 0xA0000888,
	RGBA_NONPREMUL = 0xA1008888,
	RGBA_PREMUL    = 0xA2008888,
	BGR            = 0x80000888,
	BGRA_NONPREMUL = 0x81008888,
	BGRA_PREMUL    = 0x82008888,
}

PIXEL_SUBSAMPLING_NONE :: u32(0)

WUFFS_SHARED :: #config(WUFFS_SHARED, false)

when WUFFS_SHARED {
	foreign import wuffs "../../lib/libwuffs.so"
} else {
	when ODIN_OS == .Linux {
		foreign import wuffs "../../lib/libwuffs.a"
	} else when ODIN_OS == .Windows {
		foreign import wuffs "../../lib/wuffs.lib"
	}
}

foreign wuffs {
	wuffs_base__note__end_of_data: [0]u8
}

@(link_prefix = "wuffs_png__decoder__")
foreign wuffs {
	@(require_results)
	initialize :: proc "c" (dec: Decoder, sizeof_star_dec: uint, wuffs_version: u64, options: u32) -> Status ---
}

foreign wuffs {
	@(require_results)
	sizeof__wuffs_png__decoder :: proc "c" () -> uint ---
}

WUFFS_VERSION :: 0x000000000000000
INITIALIZE__ALREADY_ZEROED :: u32(0x00000002)

@(link_prefix = "wuffs_base__image_decoder__")
foreign wuffs {
	decode_image_config :: proc "c" (self: Decoder, dst: ^Image_Config, src: ^Io_Buffer) -> Status ---
	decode_frame_config :: proc "c" (self: Decoder, dst: ^Frame_Config, src: ^Io_Buffer) -> Status ---
	decode_frame :: proc "c" (self: Decoder, dst: ^Pixel_Buffer, src: ^Io_Buffer, blend: Pixel_Blend, workbuf: Slice_U8, opts: rawptr = nil) -> Status ---
	workbuf_len :: proc "c" (self: Decoder) -> Range_Ii_U64 ---
}

@(link_prefix = "gam_wuffs_")
foreign wuffs {
	// Wraps `wuffs_base__pixel_config__pixbuf_len`, a "static inline" C
	// function with no linkable symbol of its own.
	pixel_config__pixbuf_len :: proc "c" (c: ^Pixel_Config) -> u64 ---
	// Wraps `wuffs_base__pixel_buffer__set_from_slice`, likewise inline-only.
	pixel_buffer__set_from_slice :: proc "c" (pb: ^Pixel_Buffer, pixcfg: ^Pixel_Config, ptr: [^]u8, len: c.size_t) -> Status ---
}
