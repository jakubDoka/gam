const std = @import("std");
const gam = @import("gam");
const xev = @import("xev");
const utils = @import("utils");

pub const max_conns = 30;
pub const tps = 60;
pub const stale_conn_trashold = 100 * std.time.ns_per_ms;
pub const pong_period = 500;

pub const Connection = struct {
    handshake: ServerHandshake,
    id: gam.auth.Identity = undefined,
    stream: gam.proto.Stream = undefined,
    last_packet: std.time.Instant,
    negotiated: bool = false,

    state: gam.proto.PlayerState,
    input: gam.proto.PlayerInput,
};

pub const AddrCtx = struct {
    key: [16]u8,

    pub fn hash(self: *@This(), vl: std.net.Address) u32 {
        var hasher = std.hash.SipHash64(2, 4).init(&self.key);
        hasher.update(std.mem.asBytes(&vl)[0..vl.getOsSockLen()]);
        return @truncate(hasher.finalInt());
    }

    pub fn eql(_: *@This(), a: std.net.Address, b: std.net.Address, _: usize) bool {
        return a.eql(b);
    }
};

pub const ServerHandshake = struct {
    kp: *const gam.auth.KeyPair,
    interop: gam.UdpInterop = .{},
    task: gam.Task(Error!void) = .{},
    ch: gam.auth.ClientHello = undefined,
    sh: gam.auth.ServerHello = undefined,

    pub const Error = xev.WriteError;

    pub fn init(
        self: *ServerHandshake,
        loop: *xev.Loop,
        socket: xev.UDP,
        rng: std.Random,
        packet: gam.UdpReader.Packet,
    ) !void {
        if (packet.body.len != @sizeOf(gam.auth.ClientHello)) return error.IncompleteHelloPacket;
        var client_hello: *const gam.auth.ClientHello = @ptrCast(packet.body.ptr);
        if (!std.mem.eql(u8, &client_hello.kw, gam.auth.ClientHello.keyword))
            return error.KeywordMismatch;

        self.ch = client_hello.*;
        self.sh = gam.auth.ServerHello.init(rng, self.kp.*, self.ch);
        self.interop.send(
            loop,
            socket,
            packet.from.toStd(),
            std.mem.asBytes(&self.sh),
            afterHello,
        );
    }

    pub fn afterHello(
        ud: *gam.UdpInterop,
        _: *xev.Loop,
        _: xev.UDP,
        _: []const u8,
        r: xev.WriteError!usize,
    ) xev.CallbackAction {
        const self: *ServerHandshake = @fieldParentPtr("interop", ud);

        const written = r catch |err| return self.task.ret(err);
        std.debug.assert(written == @sizeOf(gam.auth.ServerHello));

        return self.task.ret({});
    }

    pub fn poll(
        self: *ServerHandshake,
        packet: gam.UdpReader.Packet,
    ) !gam.auth.Verified {
        if (packet.body.len != @sizeOf(gam.auth.Finished))
            return error.IncompleteFinished;
        var finished: *const gam.auth.Finished = @ptrCast(packet.body.ptr);

        return try finished.verify(self.kp.*, self.ch, self.sh);
    }
};

pub const Server = struct {
    pool: utils.SclassPool,
    loop: xev.Loop,
    reader: gam.UdpReader,

    free_conns: gam.List(Connection) = .{},
    free_oneoffs: gam.List(gam.OneOffPacket) = .{},

    pong_tick: gam.Sleep = .{},
    tick_timer: xev.Timer = .{},
    tick: xev.Completion = .{},

    q: gam.Queue(union(enum) {
        sh: *ServerHandshake,
        one_off: *gam.OneOffPacket,
        const_one_off: *gam.OneOffPacket,
        pong: *gam.Sleep,
    }) = .{},

    conns: std.ArrayHashMapUnmanaged(std.net.Address, *Connection, *AddrCtx, false) =
        .empty,

    packet_counter: usize = 0,
    tps: usize = 0,

    rng: std.Random,
    hash_ctx: AddrCtx,
    sock: xev.UDP,
    kp: gam.auth.KeyPair,

    pub fn schedule(self: *Server, loop: *xev.Loop, sock: xev.UDP) void {
        self.reader.schedule(loop, sock);
        self.pong_tick.schedule(&self.loop, pong_period);
        self.q.queue(.{ .pong = &self.pong_tick });
    }

    pub const SendMode = enum { relyable, unrelyable };

    pub fn send(
        self: *Server,
        to: *Connection,
        comptime mode: SendMode,
        packet: gam.proto.Packet,
    ) !void {
        if (mode == .unrelyable) {
            const pack = gam.proto.bufferPacket(
                packet,
                self.pool.allocator(),
            ) catch unreachable;

            pack.encrypt(to.stream.rng, to.stream.key);

            self.sendRaw(to.stream.addr, .alloced, pack.asBytes());
        } else {
            gam.proto.bufferPacketRelyable(
                packet,
                &self.loop,
                &to.stream,
            ) catch return error.ServerOverload;
        }
    }

    pub fn broadcast(
        self: *Server,
        comptime mode: SendMode,
        packet: gam.proto.Packet,
    ) void {
        for (@as([]*Connection, self.conns.entries.items(.value))) |o| {
            if (!o.negotiated) continue;
            self.send(o, mode, packet) catch |err| {
                std.log.debug(
                    "can't send the chat message to {f}: {}",
                    .{ o.stream.addr, err },
                );
            };
        }
    }

    pub fn sendRaw(
        self: *Server,
        addr: std.net.Address,
        cnst: enum { constant, alloced },
        message: []const u8,
    ) void {
        const one_off = self.free_oneoffs.pop() orelse
            self.pool.arena.create(gam.OneOffPacket);
        one_off.* = .{};
        one_off.schedule(&self.loop, self.sock, addr, message);

        if (cnst == .constant) {
            self.q.queue(.{ .const_one_off = one_off });
        } else {
            self.q.queue(.{ .one_off = one_off });
        }
    }

    pub fn handleTask(self: *Server) void {
        while (self.q.next()) |task| switch (task) {
            .sh => {},
            .one_off => |oo| {
                self.pool.allocator().free(oo.task.res[1]);
                self.free_oneoffs.push(oo);
            },
            .const_one_off => |oo| {
                self.free_oneoffs.push(oo);
            },
            .pong => |p| {
                self.broadcast(.unrelyable, .{ .ping = .{ .tps = self.tps } });
                p.schedule(&self.loop, pong_period);
                self.q.queue(.{ .pong = p });
            },
        };
    }

    pub fn handleConnPacket(
        self: *Server,
        conn: *Connection,
        p: gam.UdpReader.Packet,
    ) !void {
        conn.last_packet = try .now();

        var killed = true;
        defer if (killed) {
            _ = self.conns.swapRemoveContext(p.from.toStd(), &self.hash_ctx);
            conn.stream.unschedule(&self.loop);
            self.free_conns.push(conn);
        };

        if (!conn.negotiated) {
            if (conn.handshake.poll(p)) |verified| {
                conn.id = verified.id;
                conn.stream.schedule(
                    &self.loop,
                    verified.secret,
                    p.from.toStd(),
                );
                conn.negotiated = true;

                std.log.debug("authenticated a connection", .{});
                killed = false;
            } else |_| {}
        }

        var enc_packet = gam.proto.Crypt.init(p.body, .to_decode) catch |err| {
            std.log.debug(
                "invalid encrypted packet: {}: {x}",
                .{ err, p.body },
            );
            return;
        };

        enc_packet.decrypt(conn.stream.key) catch |err| {
            std.log.debug("failed to decrypt packet: {}", .{err});
            return;
        };

        const res = conn.stream.handlePacket(
            &self.loop,
            enc_packet.getPlain(),
        ) catch |err| {
            std.log.debug("invalid stream packet: {}", .{err});
            return;
        };

        while (true) {
            const packet_data = switch (res) {
                .relyable => conn.stream.next() orelse break,
                .unrelyable => enc_packet.getPlain().data,
                .handled => break,
            };

            const packet = gam.proto.unbufferPacket(packet_data) catch |err| {
                std.log.debug("failed to decode packet: {}", .{err});
                return;
            };

            switch (packet) {
                .ping => |ping| {
                    self.send(conn, .unrelyable, .{ .pong = ping }) catch {};
                },
                .pong => |pong| {
                    _ = pong;
                },
                .chat_message => self.broadcast(.relyable, packet),
                .player_input => |inp| {
                    if (inp.seq > conn.input.seq) {
                        conn.input = inp;
                    }
                },

                .player_states => {
                    std.log.warn("server only packet {}", .{packet});
                    return;
                },
            }

            if (res == .unrelyable) break;
        }

        killed = false;
    }

    pub fn handlePackets(self: *Server) !void {
        var packets = self.reader.packets();
        while (packets.next()) |p| {
            self.packet_counter += 1;

            if (self.conns.getContext(p.from.toStd(), &self.hash_ctx)) |conn| {
                try self.handleConnPacket(conn, p);
                continue;
            }

            if (self.conns.entries.len == self.conns.entries.capacity) {
                self.sendRaw(p.from.toStd(), .constant, gam.auth.max_conns_reached);
                continue;
            }

            const conn = self.free_conns.pop() orelse b: {
                const slot = self.pool.arena.create(Connection);

                slot.stream = .init(
                    &self.pool.arena,
                    self.sock,
                    self.rng,
                    gam.proto.message_queue_size,
                );

                break :b slot;
            };

            conn.* = .{
                .handshake = ServerHandshake{ .kp = &self.kp },
                .last_packet = try .now(),
                .stream = conn.stream,
                .state = .{ .pos = .{ 100, 100 } },
                .input = .{},
            };

            if (conn.handshake.init(&self.loop, self.sock, self.rng, p)) |_| {
                const slot = self.conns
                    .getOrPutAssumeCapacityContext(p.from.toStd(), &self.hash_ctx);

                if (slot.found_existing) {
                    unreachable;
                }

                self.q.queue(.{ .sh = &conn.handshake });

                slot.value_ptr.* = conn;

                continue;
            } else |_| {
                self.free_conns.push(conn);
                self.sendRaw(p.from.toStd(), .constant, "garbou");
            }
        }
    }
};

pub fn main() !void {
    utils.Arena.initScratch(1024 * 1024 * 16);

    const port = 8080;

    var hash_key: [16]u8 = undefined;
    std.crypto.random.bytes(&hash_key);

    var self = Server{
        .pool = .{ .arena = utils.Arena.init(1024 * 1024 * 32) },
        .loop = try xev.Loop.init(.{}),
        .reader = undefined,
        .hash_ctx = .{ .key = hash_key },
        .rng = std.crypto.random,
        .sock = b: {
            const addr = std.net.Address.parseIp4("0.0.0.0", port) catch unreachable;

            const sock = try xev.UDP.init(addr);
            try sock.bind(addr);

            std.log.info("listening on port: {d}", .{addr.getPort()});

            break :b sock;
        },
        .kp = gam.auth.KeyPair.generate(),
    };

    self.reader = .{ .listen_buf = self.pool.arena.alloc(u8, 1 << 16) };
    try self.conns.ensureTotalCapacityContext(
        utils.Arena.scrath(null).arena.allocator(),
        max_conns,
        &self.hash_ctx,
    );
    self.schedule(&self.loop, self.sock);

    var time: f64 = @floatFromInt(std.time.milliTimestamp());

    var tps_counter: usize = 0;
    var last_tps_snapshot = try std.time.Instant.now();
    var state_seq: u32 = 1;
    var delta: f32 = 0;

    while (true) {
        if (self.tick.state() == .dead) {
            const now_time: f64 = @floatFromInt(std.time.milliTimestamp());
            delta = @floatCast(now_time - time);
            time += 1000.0 / @as(f64, tps);
            const sleep_duration = @max(time - now_time, 1);

            self.tick_timer.run(
                &self.loop,
                &self.tick,
                @intFromFloat(sleep_duration),
                anyopaque,
                null,
                struct {
                    fn cb(
                        _: ?*anyopaque,
                        _: *xev.Loop,
                        _: *xev.Completion,
                        _: xev.Timer.RunError!void,
                    ) xev.CallbackAction {
                        return .disarm;
                    }
                }.cb,
            );
        }

        const now = try std.time.Instant.now();

        var tmp = utils.Arena.scrath(null);
        defer tmp.deinit();

        for (
            @as([]*Connection, self.conns.entries.items(.value)),
            0..,
        ) |val, i| {
            if (val.handshake.task.inProgress()) continue;
            if (now.since(val.last_packet) > stale_conn_trashold) {
                self.free_conns.push(val);
                val.stream.unschedule(&self.loop);
                self.conns.swapRemoveAtContext(i, &self.hash_ctx);
                break;
            }
        }

        { // state sync
            const player_states = tmp.arena.alloc(
                gam.proto.Packet.PlayerSync,
                self.conns.entries.len,
            );
            for (player_states, self.conns.entries.items(.value)) |*slt, conn| {
                slt.* = .{ .id = conn.id, .state = conn.state };
            }

            self.broadcast(.unrelyable, .{ .player_states = .{
                .seq = state_seq,
                .states = player_states,
            } });
            state_seq += 1;
        }

        { // input simulation
            for (@as([]*Connection, self.conns.entries.items(.value))) |conn| {
                var dir = gam.vec.zero;
                if (conn.input.key_mask.up) dir += .{ 0, -1 };
                if (conn.input.key_mask.down) dir += .{ 0, 1 };
                if (conn.input.key_mask.left) dir += .{ -1, 0 };
                if (conn.input.key_mask.right) dir += .{ 1, 0 };
                dir = gam.vec.norm(dir);

                conn.state.pos += dir * gam.vec.splat(100 * (16.667 / 1000.0));
            }
        }

        if (now.since(last_tps_snapshot) > std.time.ns_per_s) {
            self.tps = tps_counter;
            tps_counter = 0;
            last_tps_snapshot = now;
        }

        while (self.tick.state() != .dead) {
            try self.loop.run(.once);

            self.handleTask();
            try self.handlePackets();
        }

        tps_counter += 1;
    }
}
