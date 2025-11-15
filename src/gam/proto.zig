const std = @import("std");

const utils = @import("utils");
const xev = @import("xev");
const gam = @import("../gam.zig");
const sim = gam.sim;
const vec = gam.vec;
const Id = sim.Id;

pub const sps = 20;
pub const max_conns = 32;

pub const message_queue_size = 8;

pub fn bufferPacket(packet: Packet, gpa: std.mem.Allocator) !Crypt {
    const len = packet.size();
    const size = Crypt.packetSize(len);
    const buf = try gpa.alloc(u8, size);

    const epacket = Crypt.init(buf, .to_encode) catch
        unreachable;
    var writer = std.Io.Writer.fixed(epacket.getPlain().data);
    packet.encode(&writer) catch unreachable;
    epacket.getPlain().header.seq = Stream.unordered_seq;

    return epacket;
}

pub fn bufferPacketRelyable(
    packet: Packet,
    loop: *xev.Loop,
    stream: *Stream,
) !void {
    const len = packet.size();
    const size = Crypt.packetSize(len);

    const frag = stream.allocFragment(size) orelse return error.OutOfMemory;

    const epacket = Crypt.init(frag.body(), .to_encode) catch
        unreachable;
    var writer = std.Io.Writer.fixed(epacket.getPlain().data);
    packet.encode(&writer) catch unreachable;
    epacket.getPlain().header.seq = Stream.unordered_seq;

    stream.commitFragment(frag, loop);
}

pub fn unbufferPacket(packet: []const u8) !Packet {
    var reader = std.Io.Reader.fixed(packet);
    return Packet.decode(&reader);
}

pub const Packet = union(enum) {
    ping: PingPayload,
    pong: PingPayload,
    chat_message: ChatMessage,
    state: struct {
        seq: u32,
        conns: []align(1) ConnSync,
        present: []align(1) std.DynamicBitSetUnmanaged.MaskInt,
        ents: []align(1) sim.Ent.Compact,
    },
    player_input: sim.InputState,
    spawn: extern struct {
        content_id: usize,
    },

    pub const ConnSync = struct {
        id: gam.auth.Identity,
        ent: sim.Id,
        input: sim.InputState,
    };

    pub const ChatMessage = struct {
        id: gam.auth.Identity,
        content: []const u8,
    };

    pub const PingPayload = extern struct {
        tps: usize,
    };

    pub fn size(self: Packet) usize {
        var counting = std.Io.Writer.Discarding.init(&.{});
        self.encode(&counting.writer) catch unreachable;
        return @intCast(counting.count);
    }

    pub fn encode(self: Packet, writer: *std.Io.Writer) !void {
        try writer.writeByte(@intFromEnum(self));
        switch (self) {
            inline .ping,
            .pong,
            .player_input,
            .spawn,
            => |p| try writer.writeStruct(p, .little),
            .chat_message => |c| {
                try writer.writeAll(std.mem.asBytes(&c.id));
                try writer.writeAll(c.content);
            },
            .state => |ps| {
                try writer.writeInt(u32, ps.seq, .little);
                try writer.writeInt(u16, @intCast(ps.conns.len), .little);
                try writer.writeAll(@ptrCast(ps.conns));
                try writer.writeInt(u16, @intCast(ps.present.len), .little);
                try writer.writeAll(@ptrCast(ps.present));
                try writer.writeAll(@ptrCast(ps.ents));
            },
        }
    }

    pub fn decode(reader: *std.Io.Reader) !Packet {
        const tag: u8 = try reader.takeByte();
        switch (try std.meta.intToEnum(std.meta.Tag(Packet), tag)) {
            inline .ping,
            .pong,
            .player_input,
            .spawn,
            => |t| {
                return @unionInit(
                    Packet,
                    @tagName(t),
                    try reader.takeStruct(std.meta.TagPayload(Packet, t), .little),
                );
            },
            .chat_message => return .{ .chat_message = .{
                .id = .{
                    .bytes = (try reader.takeArray(@sizeOf(gam.auth.Identity))).*,
                },
                .content = reader.buffered(),
            } },
            .state => return .{ .state = .{
                .seq = try reader.takeInt(u32, .little),
                .conns = b: {
                    const len = try reader.takeInt(u16, .little) *
                        @sizeOf(Packet.ConnSync);
                    if (reader.buffered().len < len) {
                        return error.ReadFailed;
                    }

                    defer reader.seek += len;
                    break :b @ptrCast(reader.buffered()[0..len]);
                },
                .present = b: {
                    const len = try reader.takeInt(u16, .little) *
                        @sizeOf(std.DynamicBitSetUnmanaged.MaskInt);
                    if (reader.buffered().len < len) {
                        return error.ReadFailed;
                    }

                    defer reader.seek += len;
                    break :b @ptrCast(reader.buffered()[0..len]);
                },
                .ents = b: {
                    if (reader.buffered().len % @sizeOf(sim.Ent.Compact) != 0) {
                        return error.ReadFailed;
                    }

                    defer reader.seek = reader.end;
                    break :b @ptrCast(reader.buffered());
                },
            } },
        }
    }
};

pub const max_datagram_size = (1 << 16) - 20 - 8;

pub const Plain = struct {
    header: *align(1) Header,
    data: []u8,

    pub const Header = struct {
        seq: u32,
    };

    pub const max_data_size = Crypt.max_data_size - @sizeOf(Header);
};

pub const Crypt = struct {
    header: *Header,
    data: []u8,

    pub const Header = extern struct {
        tag: [gam.auth.cipher.tag_length]u8 = @splat(0),
        nonce: [gam.auth.cipher.nonce_length]u8 = @splat(0),
    };

    pub const max_data_size = max_datagram_size - @sizeOf(Header);

    pub fn deinit(self: *Crypt, gpa: std.mem.Allocator) void {
        gpa.free(self.asBytes());
    }

    pub fn asBytes(self: Crypt) []u8 {
        return std.mem.asBytes(self.header)
            .ptr[0 .. @sizeOf(Header) + self.data.len];
    }

    pub fn packetSize(body_len: usize) usize {
        return @sizeOf(Header) + @sizeOf(Plain.Header) + body_len;
    }

    pub fn init(packet: []u8, mode: enum { to_encode, to_decode }) !Crypt {
        if (packet.len < @sizeOf(Header) + @sizeOf(Plain.Header)) {
            return error.IncompletePacket;
        }

        if (mode == .to_encode) @memset(packet[0..@sizeOf(Header)], 0);

        return .fromBytes(packet);
    }

    pub fn fromBytes(packet: []u8) Crypt {
        return .{
            .header = @ptrCast(packet[0..@sizeOf(Header)]),
            .data = packet[@sizeOf(Header)..],
        };
    }

    pub fn encrypt(self: Crypt, rng: std.Random, key: gam.auth.CipherKey) void {
        std.debug.assert(std.mem.allEqual(u8, &self.header.tag, 0));
        std.debug.assert(std.mem.allEqual(u8, &self.header.nonce, 0));

        rng.bytes(&self.header.nonce);
        gam.auth.cipher.encrypt(
            self.data,
            &self.header.tag,
            self.data,
            gam.auth.asoc_data,
            self.header.nonce,
            key,
        );
    }

    pub fn decrypt(self: Crypt, key: gam.auth.CipherKey) !void {
        if (std.mem.allEqual(u8, &self.header.tag, 0) and
            std.mem.allEqual(u8, &self.header.nonce, 0))
        {
            return error.AlreadyDecrypted;
        }

        try gam.auth.cipher.decrypt(
            self.data,
            self.data,
            self.header.tag,
            gam.auth.asoc_data,
            self.header.nonce,
            key,
        );

        @memset(&self.header.tag, 0);
        @memset(&self.header.nonce, 0);
    }

    pub fn getPlain(self: Crypt) Plain {
        std.debug.assert(std.mem.allEqual(u8, &self.header.tag, 0));
        std.debug.assert(std.mem.allEqual(u8, &self.header.nonce, 0));
        return .{
            .header = @ptrCast(self.data[0..@sizeOf(Plain.Header)].ptr),
            .data = self.data[@sizeOf(Plain.Header)..],
        };
    }
};

pub const Stream = struct {
    send_head: u32 = undefined,
    send_tail: u32 = undefined,
    send_buffer: []Fragment,

    recv_head: u32 = undefined,
    recv_tail: u32 = undefined,
    recv_buffer: []Fragment,
    recv_set: std.bit_set.IntegerBitSet(missing_packet_cap) = undefined,

    ping: extern struct {
        header: Crypt.Header = undefined,
        plain_header: u32 = ping_seq,
        inner: Ping,
    } = undefined,
    ping_interop: gam.UdpInterop = .{},
    ping_timeout: gam.Timeout = .{ .deadline = 150 },

    sock: xev.UDP = undefined,
    addr: std.net.Address = undefined,
    key: gam.auth.CipherKey = undefined,
    rng: std.Random,

    schedule_lock: std.debug.SafetyLock = .{},

    pub const ping_seq = std.math.maxInt(u32);
    pub const unordered_seq = ping_seq - 1;
    pub const missing_packet_cap = 64;

    pub const Ping = extern struct {
        remote_seq: u32,
        unused: u32 = 0,
        // this are missing packets ahead of remote_seq
        present_set: std.bit_set.IntegerBitSet(missing_packet_cap),
    };

    pub const Fragment = struct {
        // TODO: pool these instead
        // TODO: and also, the recv q does not need this
        sender: gam.UdpInterop = .{},
        len: u32,
        bytes: [optimal_size]u8 = undefined,

        pub const optimal_size = 1200;

        pub fn body(self: *Fragment) []u8 {
            return self.bytes[0..self.len];
        }
    };

    pub fn init(
        scratch: *utils.Arena,
        rng: std.Random,
        max_packet_queue: usize,
    ) Stream {
        return .{
            .rng = rng,
            .send_buffer = scratch.alloc(Fragment, max_packet_queue),
            .recv_buffer = scratch.alloc(Fragment, max_packet_queue),
        };
    }

    pub fn schedule(
        self: *Stream,
        loop: *xev.Loop,
        sock: xev.UDP,
        key: gam.auth.CipherKey,
        addr: std.net.Address,
    ) void {
        self.schedule_lock.lock();
        self.sock = sock;
        self.key = key;
        self.addr = addr;
        self.send_tail = 0;
        self.send_head = 0;
        self.recv_tail = 0;
        self.recv_head = 0;
        self.recv_set = .initEmpty();
        self.ping_timeout.run(loop, null, pingTimeoutDriver);
    }

    pub fn unschedule(self: *Stream, loop: *xev.Loop) void {
        self.ping_timeout.cancel(loop, cancelDriver);
    }

    pub fn cancelDriver(
        ud: *gam.Timeout,
        _: *xev.Loop,
        wut: xev.Timer.CancelError!void,
    ) xev.CallbackAction {
        wut catch {
            if (ud.comp.state() == .active) return .disarm;
        };

        const self: *Stream = @fieldParentPtr("ping_timeout", ud);
        self.schedule_lock.unlock();

        return .disarm;
    }

    pub const Closer = struct {
        task: gam.Task(xev.CloseError!void) = .{},
        comp: xev.Completion = .{},

        pub fn schedule(self: *Closer, loop: *xev.Loop, sock: xev.UDP) void {
            sock.close(loop, &self.comp, Closer, self, closeDriver);
        }

        pub fn closeDriver(
            ud: ?*Closer,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.UDP,
            r: xev.CloseError!void,
        ) xev.CallbackAction {
            return ud.?.task.ret(r);
        }
    };

    pub fn pingTimeoutDriver(
        ud: *gam.Timeout,
        loop: *xev.Loop,
        res: xev.CancelError!void,
    ) xev.CallbackAction {
        const self: *Stream = @fieldParentPtr("ping_timeout", ud);

        res catch unreachable;

        self.sendPing(loop);

        self.ping_timeout.run(loop, null, pingTimeoutDriver);

        return .disarm;
    }

    pub fn sendPing(self: *Stream, loop: *xev.Loop) void {
        if (self.ping_interop.comp.state() != .dead) return;

        self.ping = .{
            .inner = .{
                .remote_seq = self.recv_head,
                .present_set = self.recv_set,
            },
        };

        const crypt = Crypt.init(std.mem.asBytes(&self.ping), .to_encode) catch
            unreachable;
        crypt.encrypt(self.rng, self.key);

        self.ping_interop.send(
            loop,
            self.sock,
            self.addr,
            std.mem.asBytes(&self.ping),
            null,
        );
    }

    pub fn allocFragment(
        self: *Stream,
        len: usize,
    ) ?*Fragment {
        if (self.send_tail - self.send_head == self.send_buffer.len) return null;

        std.debug.assert(std.math.isPowerOfTwo(self.send_buffer.len));

        const frag = &self.send_buffer[self.send_tail % self.send_buffer.len];

        std.debug.assert(Fragment.optimal_size >= len);

        frag.* = .{ .len = @intCast(len) };

        return frag;
    }

    pub fn commitFragment(
        self: *Stream,
        frag: *Fragment,
        loop: *xev.Loop,
    ) void {
        const packet = Crypt.fromBytes(frag.body());
        packet.getPlain().header.seq = self.send_tail;
        packet.encrypt(self.rng, self.key);

        frag.sender.send(loop, self.sock, self.addr, frag.body(), null);

        std.debug.assert(std.math.isPowerOfTwo(self.send_buffer.len));
        self.send_tail += 1;
    }

    pub fn handlePing(
        self: *Stream,
        loop: *xev.Loop,
        packet: Plain,
    ) !void {
        if (packet.data.len != @sizeOf(Ping)) {
            return error.InvalidPingSize;
        }

        var ping: Ping = @bitCast(packet.data[0..@sizeOf(Ping)].*);
        self.send_head = @max(self.send_head, ping.remote_seq);

        if (self.send_head > ping.remote_seq) return;

        if (self.send_tail - self.send_head > ping.present_set.capacity()) {
            return error.MissingCapOveflow;
        }

        const mask = ~((@as(@TypeOf(ping.present_set.mask), 1) <<
            @intCast(self.send_tail - self.send_head)) - 1);

        ping.present_set.mask |= mask;

        ping.present_set.toggleAll();

        var iter = ping.present_set.iterator(.{});

        while (iter.next()) |i| {
            const index = self.send_head + i;

            std.debug.assert(std.math.isPowerOfTwo(self.send_buffer.len));
            const frag = &self.send_buffer[index % self.send_buffer.len];

            if (frag.sender.comp.state() == .dead) {
                frag.sender.send(
                    loop,
                    self.sock,
                    self.addr,
                    frag.body(),
                    null,
                );
            }
        }
    }

    pub const pressure_trashold_factor = 4;

    pub fn handlePacket(
        self: *Stream,
        loop: *xev.Loop,
        packet: Plain,
    ) !enum { relyable, unrelyable, handled } {
        switch (packet.header.seq) {
            ping_seq => {
                try self.handlePing(loop, packet);
                return .handled;
            },
            unordered_seq => return .unrelyable,
            else => {},
        }

        const insert_index = packet.header.seq;

        if (insert_index < self.recv_head) return .handled;

        if (insert_index - self.recv_head >= self.recv_buffer.len) {
            return error.TooMuchPressure;
        }

        std.debug.assert(std.math.isPowerOfTwo(self.recv_buffer.len));

        if (packet.data.len > Fragment.optimal_size) {
            return error.PacketSizeOverflow;
        }

        const slot = &self.recv_buffer[insert_index % self.recv_buffer.len];
        slot.* = .{ .len = @intCast(packet.data.len) };
        @memcpy(slot.body(), packet.data);

        if (insert_index - self.recv_head > missing_packet_cap) {
            return error.MissingPacketOverflow;
        }

        self.recv_set.set(insert_index - self.recv_head);
        self.ping_timeout.run(loop, null, pingTimeoutDriver);

        if (self.recv_set.count() > self.recv_buffer.len / pressure_trashold_factor) {
            self.sendPing(loop);
        }

        return .relyable;
    }

    pub fn next(self: *Stream) ?[]u8 {
        std.debug.assert(std.math.isPowerOfTwo(self.recv_buffer.len));

        if (!self.recv_set.isSet(0)) return null;

        const fragment = &self.recv_buffer[self.recv_head % self.recv_buffer.len];

        self.recv_head += 1;
        self.recv_set.mask >>= 1;

        return fragment.body();
    }
};
