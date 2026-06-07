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
	relative_mouse_pos: [2]f32,
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
	Click_Left,
	Click_Right,
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
	using _:         struct #raw_union {
		ents: []Ent_Net_ID,
		raw:  []u8,
	},
}

Client_Cold_State :: struct {
	using _: struct #raw_union {
		state:  struct {
			username: Player_Name,
		},
		packed: []u8,
	},
}

Client_Map_Edit :: struct {
	using _: struct #raw_union {
		mapa:   Map,
		packed: []u8,
	},
}

Client_Asset_Request :: struct {
	inverted: bool,
	using _:  struct #raw_union {
		using body: Client_Asset_Request_Body,
		packed:     []u8,
	},
}

Client_Asset_Request_Body :: struct {
	assets: []Asset_ID,
}

client_asset_request_body_encode :: proc(
	req: Client_Asset_Request_Body,
	e: ^Encoder,
) -> bool {
	encode(e, u32(len(req.assets))) or_return
	encode_slice(e, req.assets) or_return

	return true
}

client_asset_request_body_decode :: proc(
	d: ^Decoder,
) -> (
	b: Client_Asset_Request_Body,
	ok: bool,
) {
	return {
			assets = decode_aligned_slice(
				d,
				Asset_ID,
				decode(d, u32) or_return,
			) or_return,
		},
		true
}

Client_Asset_Upload :: struct {
	token:   Hash,
	using _: struct #raw_union {
		using body: Client_Asset_Upload_Body,
		packed:     []u8,
	},
}

client_asset_upload_body_encode :: proc(
	req: Client_Asset_Upload_Body,
	e: ^Encoder,
) -> bool {
	encode(e, len(req.metas)) or_return
	encode_slice(e, req.metas) or_return

	return true
}

client_asset_upload_body_decode :: proc(
	d: ^Decoder,
	loc := #caller_location,
) -> (
	b: Client_Asset_Upload_Body,
	ok: bool,
) {
	return {
			metas = decode_aligned_slice(
				d,
				Asset,
				decode(d, int, loc = loc) or_return,
				loc = loc,
			) or_return,
		},
		true
}

Client_Asset_Upload_Body :: struct {
	metas: []Asset,
}

Client_Packet_Tag :: enum u8 {
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
	ctx:              ^Ents,
	using _:          struct #raw_union {
		state:  struct {
			ents:    []Ent,
			players: []Client_Input_Keys,
		},
		packed: []u8,
	},
}

Server_Config :: struct {
	using _: struct #raw_union {
		stats:  []Ent_Stats,
		packed: []u8,
	},
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

Server_Cold_State_Header :: struct {
	dirty_stats: bool,
}

Server_Cold_State :: struct {
	header:  Server_Cold_State_Header,
	using _: struct #raw_union {
		state:  struct {
			players: []Player,
		},
		packed: []u8,
	},
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
	using _: struct #raw_union {
		using _: struct {
			stats:   []Ent_Stats,
			sprites: []u32,
		},
		packed:  []u8,
	},
}

Server_Packet_Tag :: enum u8 {
	Server_Ping,
	Server_State,
	Server_Map,
	Server_Cold_State,
	Server_Stats,
	Server_Cmd,
	Broadcast_Packet,
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
	len: u16,
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
	assert(mem.is_aligned(raw_data(d.remining), align_of(T)))
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

broadcast_packet_encode :: proc(p: Broadcast_Packet, e: ^Encoder) -> bool {
	encode_kind :: proc(e: ^Encoder, kind: Broadcast_Packet_Tag) -> bool {
		return encode(e, kind)
	}

	switch p in p {
	case Chat_Msg:
		encode_kind(e, .Chat_Msg) or_return
		encode(e, p.name) or_return
		encode(e, p.id) or_return
		encode(e, u16(len(p.content))) or_return
		encode_slice(e, transmute([]u8)p.content) or_return
	}

	return true
}

broadcast_packet_decode :: proc(
	d: ^Decoder,
) -> (
	p: Broadcast_Packet,
	ok: bool,
) {
	switch decode(d, Broadcast_Packet_Tag) or_return {
	case .Chat_Msg:
		return Chat_Msg {
				name = decode(d, Player_Name) or_return,
				id = decode(d, Identity) or_return,
				content = string(
					decode_slice(d, decode(d, u16) or_return) or_return,
				),
			},
			true
	case:
		return
	}
}

client_packet_encode :: proc {
	client_packet_encode_to_encoder,
	client_packet_encode_to_slice,
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
	// TODO: This is annoying as fuck

	encode_kind :: proc(e: ^Encoder, kind: Client_Packet_Tag) -> bool {
		return encode(e, kind)
	}

	switch p in packet {
	case Client_Input:
		encode_kind(e, .Client_Input) or_return
		encode(e, p) or_return
	case Client_Cmd:
		encode_kind(e, .Client_Cmd) or_return
		encode(e, p) or_return
	case Client_Control:
		encode_kind(e, .Client_Control) or_return
		encode(e, p)
		for ent in p.ents {
			encode(e, ent)
		}
	case Client_Cold_State:
		encode_kind(e, .Client_Cold_State) or_return
		username := p.state.username
		name := nm.bytes(&username)
		encode(e, u16(len(name))) or_return
		encode_slice(e, name) or_return
	case Client_Content_Action:
		encode_kind(e, .Client_Content_Action) or_return
		encode(e, p) or_return
	case Client_Map_Edit:
		encode_kind(e, .Client_Map_Edit) or_return
		map_store(p.mapa, e) or_return
	case Client_Asset_Request:
		encode_kind(e, .Client_Asset_Request) or_return
		encode(e, p.inverted) or_return
		client_asset_request_body_encode(p.body, e) or_return
	case Client_Asset_Upload:
		encode_kind(e, .Client_Asset_Upload) or_return
		encode(e, p.token) or_return
		client_asset_upload_body_encode(p.body, e) or_return
	case Broadcast_Packet:
		encode_kind(e, .Broadcast_Packet) or_return
		broadcast_packet_encode(p, e) or_return
	}

	return true
}

client_packet_encode_dyn :: proc(packet: rawptr, bytes: ^Encoder) -> bool {
	return client_packet_encode((^Client_Packet)(packet)^, bytes)
}

client_packet_decode :: proc(d: ^Decoder) -> (res: Client_Packet, ok: bool) {
	switch decode(d, Client_Packet_Tag) or_return {
	case .Client_Input:
		return decode(d, Client_Input)
	case .Client_Cmd:
		return decode(d, Client_Cmd)
	case .Client_Control:
		p := decode(d, Client_Control) or_return
		p.raw = d.remining
		return p, true
	case .Client_Cold_State:
		return Client_Cold_State{packed = d.remining}, true
	case .Client_Content_Action:
		return decode(d, Client_Content_Action)
	case .Client_Map_Edit:
		return Client_Map_Edit{packed = d.remining}, true
	case .Client_Asset_Request:
		return Client_Asset_Request {
				inverted = decode(d, bool) or_return,
				packed = d.remining,
			},
			true
	case .Client_Asset_Upload:
		return Client_Asset_Upload {
				token = decode(d, Hash) or_return,
				packed = d.remining,
			},
			true
	case .Broadcast_Packet:
		return broadcast_packet_decode(d)
	case:
		return
	}
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
	encode_kind :: proc(e: ^Encoder, kind: Server_Packet_Tag) -> bool {
		return encode(e, kind)
	}

	switch p in packet {
	case Server_Ping:
		encode_kind(e, .Server_Ping) or_return
		encode(e, p) or_return
	case Server_State:
		encode_kind(e, .Server_State) or_return
		encode(e, p.tps)
		encode(e, p.you)
		encode(e, p.your_next_net_id)

		count := 0
		for &ent in p.state.ents {
			if ent_is_alive(&ent) do count += 1
		}

		encode(e, u16(count)) or_return

		encode_iter := p.state.ents
		for ent in ents_iter_next(&encode_iter) {
			ent_synced_encode(ent, p.ctx, e) or_return
		}

		encode(e, u16(len(p.state.players)))
		encode_slice(e, p.state.players)
	case Server_Map:
		encode_kind(e, .Server_Map) or_return
		encode_slice(e, p.bytes) or_return
	case Server_Cold_State:
		encode_kind(e, .Server_Cold_State) or_return

		encode(e, p.header) or_return

		encode(e, u16(len(p.state.players)))
		for &player in p.state.players {
			encode(e, player.pk)
			name := nm.bytes(&player.name)
			encode(e, u8(len(name)))
			encode_slice(e, name)
			encode(e, player.permissions)
			encode(e, player.net_ent)
		}
	case Server_Stats:
		encode_kind(e, .Server_Stats) or_return

		encode(e, u16(len(p.stats))) or_return
		for &stat in p.stats {
			ent_stats_encode(stat, e) or_return
		}

		encode(e, u16(len(p.sprites))) or_return
		encode_slice(e, p.sprites) or_return
	case Server_Cmd:
		encode_kind(e, .Server_Cmd) or_return
		encode(e, p) or_return
	case Broadcast_Packet:
		encode_kind(e, .Broadcast_Packet) or_return
		broadcast_packet_encode(p, e) or_return
	}

	return true
}

server_packet_decode :: proc(buf: []u8) -> (res: Server_Packet, ok: bool) {
	d: Decoder = {buf}

	t := decode(&d, Server_Packet_Tag) or_return

	switch t {
	case .Server_Ping:
		return decode(&d, Server_Ping)
	case .Server_State:
		return Server_State {
				tps = decode(&d, int) or_return,
				you = decode(&d, Ent_Net_ID) or_return,
				your_next_net_id = decode(&d, Ent_Net_ID) or_return,
				packed = d.remining,
			},
			true
	case .Server_Map:
		return Server_Map{d.remining}, true
	case .Server_Cold_State:
		return Server_Cold_State {
				header = decode(&d, Server_Cold_State_Header) or_return,
				packed = d.remining,
			},
			true
	case .Server_Stats:
		return Server_Stats{packed = d.remining}, true
	case .Server_Cmd:
		return decode(&d, Server_Cmd)
	case .Broadcast_Packet:
		return broadcast_packet_decode(&d)
	case:
		log.error("invalid packet kind from server:", t)
		return
	}
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
		case Asset_Ref:
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
		case Asset_Ref:
			if field_presence_get(presence) {
				v = decode(d, Asset_Ref) or_return
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
