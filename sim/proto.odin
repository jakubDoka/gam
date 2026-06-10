package sim

import "../util/nm"
import "base:intrinsics"
import "base:runtime"
import "core:encoding/varint"
import "core:log"
import "core:mem"
import "core:reflect"
import "core:strings"
import "core:time"

TPS :: 20
TICK_INTERVAL :: time.Second / TPS
DECRYPTED_TAG :: Tag{}
CLIENT_RECV_BUF_SIZE :: 1024 * 64
SERVER_RECV_BUF_SIZE :: 1024 * 16
SERVER_REQUEST_BUF_SIZE :: 1024 * 4
ENT_SYNCED_PRESENCE_CAP :: 16

Broadcast_Packet :: union {
	Chat_Msg,
}

Broadcast_Packet_Tag :: enum u8 {
	Chat_Msg,
}

Chat_Msg :: struct {
	name:    Player_Name,
	id:      Identity,
	content: string,
}

Client_Request_Header_Fields :: struct {
	kind:           Client_Request_Type,
	content_length: int,
}

Client_Request_Header :: struct {
	using _:     Client_Request_Header_Fields,
	inline_body: [size_of(Payload) - size_of(Client_Request_Header_Fields)]u8,
}

Client_Request_Type :: enum int {
	Watch_Server_Info,
	Download_Content_Headers,
	Download_Content,
	Upload_Content,
	Play,
}

Asset_Type :: enum int {
	Map,
	Sprite,
}

Asset :: struct {
	name: nm.Name,
	hash: Hash,
	size: int,
	type: Asset_Type,
}

Client_Content_Action :: struct {
	kind:    Content_Action_Kind,
	using _: struct #raw_union {
		stats: Ent_Stats,
	},
}

Content_Action_Kind :: enum {
	Create,
	Edit,
	Save,
}

Client_Input :: struct {
	seq:                int,
	relative_mouse_pos: Vec,
	using state:        struct {
		keys: Client_Input_Keys,
	},
}

Client_Input_Keys :: bit_set[Client_Input_Key]

Client_Input_Key :: enum {
	Up,
	Down,
	Right,
	Left,
	Shoot,
	Parry,
}

Client_Cmd_Kind :: enum i32 {
	Abandon,
	Build,
	Delete,
	Rewire,
	Spawn,
}

Client_Cmd :: struct {
	kind:   Client_Cmd_Kind,
	pos:    Vec,
	id:     Ent_Stats_ID,
	parent: Ent_Net_ID,
	ent:    Ent_Net_ID,
	team:   Ent_Team_ID,
}

Client_Control_Cmd :: enum i32 {
	Move,
	Attack,
}

Client_Control :: struct {
	using objective: Ent_Objective,
	ents:            []Ent_Net_ID,
}

Client_Cold_State :: struct {
	username: Player_Name,
}

Client_Map_Edit :: struct {
	mapa: Map,
}

Client_Asset_Request :: struct {
	inverted: bool,
	assets:   []Asset_ID,
}

Client_Asset_Upload :: struct {
	token: Hash,
	metas: []Asset,
}

Client_Packet :: union #no_nil {
	Client_Input,
	Client_Cmd,
	Client_Control,
	Client_Cold_State,
	Client_Content_Action,
	Client_Map_Edit,
	Client_Asset_Request,
	Client_Asset_Upload,
	Broadcast_Packet,
}

Server_Info :: struct {
	player_count: int,
}

Server_Ping :: struct {
	sk: Secret_Key,
	id: Ping_ID,
}

compute_next_ping_tag :: proc(
	secret: ^Secret_Key,
	nonce: u8,
) -> (
	tag: Ping_Tag,
) {
	arr: [size_of(secret) + size_of(nonce)]u8
	copy(arr[:], secret[:])
	arr[len(arr) - 1] = nonce

	hash(arr[:], auto_cast &tag)

	return
}

Server_State :: struct {
	tps:              int,
	you:              Ent_Net_ID,
	your_next_net_id: Ent_Net_ID,
	ents:             Custom_Encoding,
	players:          []Client_Input_Keys,
}

Server_Config :: struct {
	stats: Custom_Encoding,
}

Server_Map :: struct {
	bytes: []u8,
}

// TODO: maybe make this a 0 padded array
Player_Name :: nm.Name

Player_Permission :: enum int {
	Edit_Content,
}

Player_Permissions :: distinct bit_set[Player_Permission;int]

Player :: struct {
	id:          int,
	pk:          Identity,
	name:        Player_Name,
	permissions: Player_Permissions,
	net_ent:     Ent_Net_ID,
}

Server_Cold_State :: struct {
	dirty_stats: bool,
	players:     []Player,
}

// TODO: the naming is lacking
Server_Cmd_Kind :: enum int {
	Laser,
	Token,
	Ack,
}

Server_Cmd :: struct {
	kind:        Server_Cmd_Kind,
	pos:         Vec,
	dir:         f32,
	team:        Ent_Team_ID,
	stats:       Ent_Stats_ID,
	token:       Hash,
	global_hash: Hash,
	count:       int,
}

Server_Stats :: struct {
	stats:   Custom_Encoding,
	sprites: []u32,
}

custom_encoding_stats :: proc(stats: ^[]Ent_Stats) -> Custom_Encoding {
	return {value = {stats, encode_stats}}

	encode_stats :: proc(data: rawptr, e: ^Encoder) -> bool {
		stats := (^[]Ent_Stats)(data)^

		for stat in stats {
			ent_stats_encode(stat, e) or_return
		}

		return true
	}
}

Server_Packet :: union #no_nil {
	Server_Ping,
	Server_State,
	Server_Map,
	Server_Cold_State,
	Server_Stats,
	Server_Cmd,
	Broadcast_Packet,
}

Crypt_Header :: struct {
	len: u32,
	tag: Tag,
}

Decrypt_Error :: enum {
	Ok,
	Auth,
	Incomplete,
}

Any_Packet :: struct {
	data:   rawptr,
	encode: proc(packet: rawptr, en: ^Encoder) -> bool,
}

Ping_ID :: distinct [16]u8
Ping_Tag :: distinct Hash

Ping :: struct {
	id:  Ping_ID,
	tag: Ping_Tag,
}

crypt_header_to_ping :: proc(buf: []u8) -> (id: Ping, ok: bool) {
	if len(buf) < size_of(Crypt_Header) + size_of(id) do return

	header := (^Crypt_Header)(raw_data(buf))
	if header^ != {} do return

	copy(reflect.as_bytes(id), buf[size_of(Crypt_Header):])
	ok = true

	return
}

decrypt_packet :: proc(
	sk: ^Secret_Key,
	buf: []u8,
) -> (
	plain: []u8,
	err: Decrypt_Error,
) {
	if len(buf) < size_of(Crypt_Header) do return {}, .Incomplete

	header := (^Crypt_Header)(raw_data(buf))
	if len(buf) < int(size_of(Crypt_Header) + header.len) do return {}, .Incomplete

	cipher := buf[size_of(Crypt_Header):][:header.len]

	if !decrypt(sk, &header.tag, cipher) {
		return {}, .Auth
	}

	return cipher, .Ok
}

Decoder :: struct {
	remining: []u8,
}

decode :: proc(
	d: ^Decoder,
	$T: typeid,
	loc := #caller_location,
) -> (
	vl: T,
	ok: bool,
) {
	if len(d.remining) < size_of(T) {
		log.errorf(
			"cant take %v bytes, remining %v",
			size_of(T),
			len(d.remining),
			location = loc,
		)
		return
	}
	defer d.remining = d.remining[size_of(T):]
	return intrinsics.unaligned_load((^T)(raw_data(d.remining))), true
}

decode_aligned_slice :: proc(
	d: ^Decoder,
	$T: typeid,
	#any_int elems: int,
	loc := #caller_location,
) -> (
	vl: []T,
	ok: bool,
) {
	if !mem.is_aligned(raw_data(d.remining), align_of(T)) {
		log.error(
			"unaligned slice, expected",
			align_of(T),
			"got",
			1 <<
			intrinsics.count_trailing_zeros(uintptr(raw_data(d.remining))),
		)
		return
	}

	if len(d.remining) < size_of(T) * elems {
		log.errorf(
			"cant slice out %v bytes, remining %v",
			size_of(T) * elems,
			len(d.remining),
			location = loc,
		)
		return
	}
	defer d.remining = d.remining[size_of(T) * elems:]
	return ([^]T)(raw_data(d.remining))[:elems], true
}

decode_slice :: proc(d: ^Decoder, #any_int elems: int) -> ([]u8, bool) {
	return decode_aligned_slice(d, u8, elems)
}

decode_leb128 :: proc(d: ^Decoder, $T: typeid) -> (vl: T, ok: bool) {
	decode_proc ::
		varint.decode_uleb128_buffer when intrinsics.type_is_unsigned(
			T,
		) else varint.decode_ileb128_buffer

	val, len, err := decode_proc(d.remining)
	if err != nil do return
	defer d.remining = d.remining[len:]
	return T(val), true
}

/// if zero initialized, the encoder will measure the size instead in the
/// data encoded
Encoder :: struct {
	remining: []u8,
}

encoder_reserve :: proc(e: ^Encoder, size: int) -> []u8 {
	if encoder_is_measuring(e) {
		_ = encoder_add_measurement(e, size)
		return nil
	}

	if len(e.remining) < size do return nil

	defer e.remining = e.remining[size:]
	return e.remining[:size]
}

encode :: proc(d: ^Encoder, v: $T) -> bool {
	return encode_slice(d, []T{v})
}

encoder_is_measuring :: proc(d: ^Encoder) -> bool {
	return raw_data(d.remining) == nil
}

encoder_add_measurement :: proc(d: ^Encoder, size: int) -> bool {
	d.remining = raw_data(d.remining)[:len(d.remining) + size]
	return true
}

encode_slice :: proc(d: ^Encoder, v: []$T) -> bool {
	if encoder_is_measuring(d) {
		return encoder_add_measurement(d, size_of(T) * len(v))
	}

	if len(d.remining) < size_of(T) * len(v) {
		return false
	}
	copy(d.remining, mem.slice_data_cast([]u8, v))
	d.remining = d.remining[size_of(T) * len(v):]
	return true
}

encoded_len :: proc(d: ^Encoder) -> int {
	assert(raw_data(d.remining) == nil)
	return len(d.remining)
}

encode_leb128 :: proc(d: ^Encoder, v: $T) -> bool {
	encoder_proc ::
		varint.encode_uleb128 when intrinsics.type_is_unsigned(
			T,
		) else varint.encode_ileb128
	encoder_int :: u128 when intrinsics.type_is_unsigned(T) else i128

	if encoder_is_measuring(d) {
		buf: [varint.LEB128_MAX_BYTES]u8
		size, err := encoder_proc(buf[:], encoder_int(v))
		assert(err == nil)
		return encoder_add_measurement(d, size)
	}

	size, err := encoder_proc(d.remining, encoder_int(v))
	if err != nil do return false
	d.remining = d.remining[size:]
	return true
}

client_packet_encode_dyn :: proc(packet: rawptr, e: ^Encoder) -> bool {
	return header_serialize((^Client_Packet)(packet)^, e)
}

client_packet_encode :: proc {
	client_packet_encode_to_slice,
	client_packet_encode_to_encoder,
}

client_packet_encode_to_slice :: proc(
	packet: Client_Packet,
	buf: []u8,
) -> (
	bytes: []u8,
	ok: bool,
) {
	e: Encoder = {buf}
	client_packet_encode_to_encoder(packet, &e) or_return
	return buf[:len(buf) - len(e.remining)], true
}

client_packet_encode_to_encoder :: proc(
	packet: Client_Packet,
	e: ^Encoder,
) -> (
	ok: bool,
) {
	return header_serialize(packet, e)
}

client_packet_decode :: proc(d: []u8) -> (packet: Client_Packet, ok: bool) {
	header_populate(packet, d) or_return
	ok = true
	return
}

server_packet_encode :: proc {
	server_packet_encode_to_encoder,
	server_packet_encode_to_slice,
}

server_packet_encode_to_slice :: proc(
	packet: Server_Packet,
	buf: []u8,
) -> (
	bytes: []u8,
	ok: bool,
) {
	e: Encoder = {buf}
	server_packet_encode_to_encoder(packet, &e) or_return
	return buf[:len(buf) - len(e.remining)], true
}

server_packet_encode_to_encoder :: proc(
	packet: Server_Packet,
	e: ^Encoder,
) -> bool {
	return header_serialize(packet, e)
}

server_packet_decode :: proc(buf: []u8) -> (res: Server_Packet, ok: bool) {
	header_populate(res, buf) or_return
	ok = true
	return
}

server_packet_encode_dyn :: proc(packet: rawptr, bytes: ^Encoder) -> bool {
	return server_packet_encode((^Server_Packet)(packet)^, bytes)
}

arbitrary_packet_encode_dyn :: proc(packet: rawptr, bytes: ^Encoder) -> bool {
	return encode_slice(bytes, (^[]u8)(packet)^)
}

ent_synced_encode :: proc(ent: ^Ent, ents: ^Ents, e: ^Encoder) -> (ok: bool) {
	s := ents_stats_get(ents, ent.stats)

	set_slot := encoder_reserve(e, ENT_SYNCED_PRESENCE_CAP / 8)

	slots: [1]int
	presence: Field_Presence
	field_presence_init(&presence, slots[:])

	encode_leb128(e, ent.stats) or_return

	encode_leb128(e, ent.net_id.peer) or_return
	encode_leb128(e, ent.net_id.seq) or_return

	if field_presence_set(&presence, ents_is_valid(ents, ent.parent)) {
		encode_leb128(e, ent.parent_net_id.peer) or_return
		encode_leb128(e, ent.parent_net_id.seq) or_return
	}

	encode(e, ent.pos) or_return
	if field_presence_set(&presence, ent.vel != {}) {
		encode(e, ent.vel) or_return
	}

	encode(e, ent.age) or_return

	if s.bullet.id != 0 && field_presence_set(&presence, ent.reload > 0) {
		encode(e, ent.reload) or_return
	}

	if field_presence_set(&presence, ent.parry_progress > 0) {
		encode(e, ent.parry_progress) or_return
	}

	if field_presence_set(&presence, ent.rot != 0) {
		encode(e, ent.rot) or_return
	}

	encode_leb128(e, ent.team) or_return

	if s.energy != 0 &&
	   field_presence_set(&presence, ent.energy_consumed != 0) {
		encode(e, ent.energy_consumed) or_return
	}

	if field_presence_set(&presence, ent.counter != 0) {
		encode_leb128(e, ent.counter) or_return
	}

	#assert(intrinsics.type_struct_field_count(Ent_Synced) == 12)
	assert(presence.cursor <= ENT_SYNCED_PRESENCE_CAP)

	copy(set_slot, mem.slice_data_cast([]u8, slots[:]))

	return true
}

ent_synced_decode :: proc(
	ents: ^Ents,
	d: ^Decoder,
) -> (
	ent: Ent_Synced,
	ok: bool,
) {
	set_slot := decode_slice(d, ENT_SYNCED_PRESENCE_CAP / 8) or_return

	slots: [1]int
	copy(mem.slice_data_cast([]u8, slots[:]), set_slot)
	presence: Field_Presence
	field_presence_init(&presence, slots[:])

	ent.stats = decode_leb128(d, Ent_Stats_ID) or_return

	s := ents_stats_get(ents, ent.stats)

	ent.net_id.peer = decode_leb128(d, u32) or_return
	ent.net_id.seq = decode_leb128(d, u32) or_return

	if field_presence_get(&presence) {
		ent.parent_net_id.peer = decode_leb128(d, u32) or_return
		ent.parent_net_id.seq = decode_leb128(d, u32) or_return
	}

	ent.pos = decode(d, Vec) or_return
	if field_presence_get(&presence) {
		ent.vel = decode(d, Vec) or_return
	}

	ent.age = decode(d, f32) or_return

	if s.bullet.id != 0 && field_presence_get(&presence) {
		ent.reload = decode(d, f32) or_return
	}

	if field_presence_get(&presence) {
		ent.parry_progress = decode(d, f32) or_return
	}

	if field_presence_get(&presence) {
		ent.rot = decode(d, f32) or_return
	}

	ent.team = decode_leb128(d, Ent_Team_ID) or_return

	if s.energy != 0 && field_presence_get(&presence) {
		ent.energy_consumed = decode(d, f32) or_return
	}

	if field_presence_get(&presence) {
		ent.counter = decode_leb128(d, int) or_return
	}

	#assert(intrinsics.type_struct_field_count(Ent_Synced) == 12)
	assert(presence.cursor <= ENT_SYNCED_PRESENCE_CAP)

	ok = true

	return
}

ent_stats_encode :: proc(stat: Ent_Stats, e: ^Encoder) -> bool {
	Ctx :: struct {
		e:        ^Encoder,
		presence: Field_Presence,
	}

	ctx: Ctx
	ctx.e = e
	slot: [2]int
	field_presence_init(&ctx.presence, slot[:])

	reserved := encoder_reserve(e, size_of(slot))
	context.user_ptr = &ctx
	recurse(stat, visit) or_return
	copy(reserved, mem.slice_data_cast([]u8, slot[:]))

	return true

	visit :: proc(
		val: any,
		tag: reflect.Struct_Tag,
	) -> (
		go_deeper: bool,
		ok: bool,
	) {
		ctx := (^Ctx)(context.user_ptr)
		e := ctx.e
		presence := &ctx.presence

		switch &v in val {
		case bool:
			field_presence_set(presence, v)
		case Ent_Stats_Ref:
			if field_presence_set(presence, v.id != 0) {
				encode_leb128(e, int(v.id)) or_return
			}
		case Ent_Stats_ID:
		case Asset_ID:
			if field_presence_set(presence, v != {}) {
				encode(e, v) or_return
			}
		case int:
			if field_presence_set(presence, v != 0) {
				encode_leb128(e, v) or_return
			}
		case f32, Ent_Kind, Color:
			zeroed := mem.check_zero(reflect.as_bytes(val))
			if field_presence_set(presence, !zeroed) {
				if v, prec := try_unwrap_rounded_float(val, tag); v != nil {
					encode_leb128(e, int(v^ * prec)) or_return
				} else {
					encode_slice(e, reflect.as_bytes(val)) or_return
				}
			}
		case Ent_Stats_Name:
			b := nm.bytes(&v)
			if field_presence_set(presence, len(b) != 0) {
				encode(e, u8(len(b))) or_return
				encode_slice(e, b) or_return
			}
		case:
			go_deeper = true
		}

		ok = true

		return
	}
}

try_unwrap_rounded_float :: proc(
	val: any,
	tag: reflect.Struct_Tag,
) -> (
	slot: ^f32,
	precision: f32 = 1,
) {
	v, is_float := &val.(f32)
	if !is_float do return

	slot = v

	str, ok := reflect.struct_tag_lookup(tag, "gam")
	if !ok do return

	KEY :: "round"

	idx := strings.index(str, KEY)
	if idx < 0 do return

	p := 0
	if idx + len(KEY) < len(str) &&
	   '0' <= str[idx + len(KEY)] &&
	   str[idx + len(KEY)] <= '9' {
		p = int(str[idx + len(KEY)] - '0')
	}

	for _ in 0 ..< p {
		precision *= 10
	}

	return
}

ent_stats_decode :: proc(
	stat: ^Ent_Stats,
	id: Ent_Stats_ID,
	d: ^Decoder,
) -> bool {
	stat.id = id

	Ctx :: struct {
		d:        ^Decoder,
		presence: Field_Presence,
	}

	ctx: Ctx
	ctx.d = d
	slot := decode(d, [2]int) or_return
	field_presence_init(&ctx.presence, slot[:])

	context.user_ptr = &ctx
	return recurse(stat^, visit)

	visit :: proc(
		val: any,
		tag: reflect.Struct_Tag,
	) -> (
		go_deeper: bool,
		ok: bool,
	) {
		ctx := (^Ctx)(context.user_ptr)
		presence := &ctx.presence
		d := ctx.d

		switch &v in val {
		case bool:
			v = field_presence_get(presence)
		case Ent_Stats_Ref:
			if field_presence_get(presence) {
				vl := decode_leb128(d, int) or_return
				v = Ent_Stats_Ref {
					id = Ent_Stats_ID(vl),
				}
			}
		case Ent_Stats_ID:
		case Asset_ID:
			if field_presence_get(presence) {
				v = decode(d, Asset_ID) or_return
			}
		case int:
			if field_presence_get(presence) {
				v = decode_leb128(d, int) or_return
			}
		case f32, Ent_Kind, Color:
			if field_presence_get(presence) {
				if v, prec := try_unwrap_rounded_float(val, tag); v != nil {
					v^ = f32(decode_leb128(d, int) or_return) / prec
				} else {
					bytes := decode_slice(
						d,
						reflect.size_of_typeid(val.id),
					) or_return
					copy(reflect.as_bytes(val), bytes)
				}
			}
		case Ent_Stats_Name:
			if field_presence_get(presence) {
				len := decode(d, u8) or_return
				bytes := decode_slice(d, len) or_return
				v = nm.from_bytes(bytes)
			}
		case:
			go_deeper = true
		}

		ok = true

		return
	}
}

recurse :: proc(
	val: any,
	visit: proc(_: any, _: reflect.Struct_Tag) -> (bool, bool),
	tag: reflect.Struct_Tag = "",
	ignore_unknown := false,
) -> bool {
	go_deeper := visit(val, tag) or_return

	if !go_deeper do return true

	#partial switch info in type_info_of(reflect.typeid_base(val.id)).variant {
	case runtime.Type_Info_Struct:
		for field in reflect.struct_fields_zipped(val.id) {
			value := reflect.struct_field_value(val, field)
			if !recurse(value, visit, field.tag, ignore_unknown) do return false
		}
	case:
		if ignore_unknown do return true

		log.error("unhandled type for decoding:", val.id)
		return false
	}

	return true
}
