package wuffs

import "core:mem"
import "core:os" // test
import "core:testing"

io_buffer_from_slice :: proc(data: []u8, closed := true) -> Io_Buffer {
	return {
		data = {ptr = raw_data(data), len = len(data)},
		meta = {wi = len(data), ri = 0, pos = 0, closed = closed},
	}
}

pixel_config_set :: proc(
	c: ^Pixel_Config,
	pixfmt: Pixel_Format,
	pixsub: u32,
	width, height: u32,
) {
	if pixfmt == .INVALID {
		c^ = {}
		return
	}
	c.pixfmt_repr = u32(pixfmt)
	c.pixsub_repr = pixsub
	c.width = width
	c.height = height
}

validate_png :: proc(
	data: []u8,
	allocator := context.temp_allocator,
) -> (
	width, height: u32,
	ok: bool,
) {
	context.allocator = allocator

	MAX_DIMENSIONS :: 1024 * 1024 * 8

	// NOTE: this can be generalized if we change the decoder initialization
	// step

	dec_size := sizeof__wuffs_png__decoder()

	dec, err := mem.alloc(int(dec_size), 16)
	if err != nil do return

	if !status_is_ok(
		initialize(dec, dec_size, WUFFS_VERSION, INITIALIZE__ALREADY_ZEROED),
	) {return}

	src := io_buffer_from_slice(data)

	image_config: Image_Config
	if !status_is_ok(decode_image_config(dec, &image_config, &src)) do return

	width = image_config.pixcfg.width
	height = image_config.pixcfg.height

	if width * height > MAX_DIMENSIONS do return

	pixel_config_set(
		&image_config.pixcfg,
		.RGBA_NONPREMUL,
		PIXEL_SUBSAMPLING_NONE,
		width,
		height,
	)

	pixbuf_len := pixel_config__pixbuf_len(&image_config.pixcfg)
	pixbuf_mem, pixbuf_err := mem.alloc_bytes(int(pixbuf_len), 16)
	if pixbuf_err != nil do return

	pixel_buffer: Pixel_Buffer
	if !status_is_ok(
		pixel_buffer__set_from_slice(
			&pixel_buffer,
			&image_config.pixcfg,
			raw_data(pixbuf_mem),
			len(pixbuf_mem),
		),
	) {return}

	for {
		frame_config: Frame_Config
		status := decode_frame_config(dec, &frame_config, &src)
		if status.repr ==
		   cstring(raw_data(&wuffs_base__note__end_of_data)) {break}
		if !status_is_ok(status) do return

		workbuf_range := workbuf_len(dec)
		workbuf_mem, workbuf_err := mem.alloc_bytes(
			int(workbuf_range.max_incl),
			16,
		)
		if workbuf_err != nil do return

		src_slc := Slice_U8 {
			ptr = raw_data(workbuf_mem),
			len = len(workbuf_mem),
		}

		if !status_is_ok(
			decode_frame(dec, &pixel_buffer, &src, .SRC, src_slc),
		) {return}
	}

	return width, height, true
}

@(test)
test_validate_png :: proc(t: ^testing.T) {
	data, read_err := os.read_entire_file(
		"assets/wall.png",
		context.temp_allocator,
	)
	testing.expect(t, read_err == nil)

	width, height, ok := validate_png(data)
	testing.expect(t, ok)
	testing.expect(t, width > 0 && height > 0)

	garbage := []u8{1, 2, 3, 4, 5}
	_, _, garbage_ok := validate_png(garbage)
	testing.expect(t, !garbage_ok)

	truncated := data[:len(data) / 2]
	_, _, truncated_ok := validate_png(truncated)
	testing.expect(t, !truncated_ok)
}
