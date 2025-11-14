const std = @import("std");
const gam = @import("gam");
const xev = @import("xev");
const utils = @import("utils");
const vec = gam.vec;
const Sim = gam.sim;
const Id = Sim.Id;

pub const max_conns = 30;
pub const stale_conn_trashold = 300 * std.time.ns_per_ms;
pub const pong_period = 500;
pub const Server = @This();

pub const std_options: std.Options = .{
    .log_level = .debug,
};

pub fn get_now() std.time.Instant {
    return std.time.Instant.now() catch unreachable;
}

pub const SendMode = enum { relyable, unrelyable };

pub const Connection = struct {
    handshake: ServerHandshake,
    id: gam.auth.Identity = undefined,
    stream: gam.proto.Stream = undefined,
    last_packet: std.time.Instant,
    negotiated: bool = false,

    input: Sim.InputState,
    ent: Id,
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

pub const Frame = struct {
    time: f64 = undefined,

    tps_counter: usize = 0,
    tps: usize = 0,
    last_tps_snapshot: std.time.Instant = undefined,
    delta: f32 = 0,
    prev_time: f64 = undefined,
    comptime target_tps: usize = 60,

    tick_timer: xev.Timer = .{},
    tick: xev.Completion = .{},

    pub fn update(self: *Frame) void {
        const client: *Server = @fieldParentPtr("frame", self);

        if (self.tick.state() == .dead) {
            const now_time: f64 = @floatFromInt(std.time.milliTimestamp());
            self.delta = @floatCast(now_time - self.prev_time);
            self.delta /= 1000;
            self.prev_time = now_time;
            self.time += 1000.0 / @as(f64, @floatFromInt(self.target_tps));
            const sleep_duration = @max(self.time - now_time, 1);

            self.tick_timer.run(
                &client.loop,
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

        const now = get_now();

        if (now.since(self.last_tps_snapshot) > std.time.ns_per_s) {
            self.tps = self.tps_counter;
            self.tps_counter = 0;
            self.last_tps_snapshot = now;
        }
        self.tps_counter += 1;
    }
};

pool: utils.SclassPool,
loop: xev.Loop,
reader: gam.UdpReader,

free_conns: gam.List(Connection) = .{},
free_oneoffs: gam.List(gam.OneOffPacket) = .{},

pong_tick: gam.Sleep = .{},
frame: Frame = .{},

q: gam.Queue(union(enum) {
    sh: *ServerHandshake,
    one_off: *gam.OneOffPacket,
    const_one_off: *gam.OneOffPacket,
    pong: *gam.Sleep,
}) = .{},

conns: std.ArrayHashMapUnmanaged(std.net.Address, *Connection, *AddrCtx, false) =
    .empty,

sim: Sim,

state_seq: u32 = 1,

rng: std.Random,
hash_ctx: AddrCtx,
sock: xev.UDP,
kp: gam.auth.KeyPair,

pub fn schedule(self: *Server) void {
    self.reader.schedule(&self.loop, self.sock);
    self.pong_tick.schedule(&self.loop, pong_period);
    self.q.queue(.{ .pong = &self.pong_tick });
}

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
            self.broadcast(.unrelyable, .{ .ping = .{ .tps = self.frame.tps } });
            p.schedule(&self.loop, pong_period);
            self.q.queue(.{ .pong = p });
        },
    };
}

pub fn killConnection(self: *Server, conn: *Connection) void {
    const idx = std.mem.indexOfScalar(
        *Connection,
        self.conns.entries.items(.value),
        conn,
    ).?;
    _ = self.conns.swapRemoveAtContext(idx, &self.hash_ctx);
    conn.stream.unschedule(&self.loop);
    _ = self.sim.ents.remove(conn.ent);
    self.free_conns.push(conn);
}

pub fn handleConnPacket(
    self: *Server,
    conn: *Connection,
    p: gam.UdpReader.Packet,
) void {
    conn.last_packet = get_now();

    var killed = true;
    defer if (killed) {
        self.killConnection(conn);
    };

    if (!conn.negotiated) {
        if (conn.handshake.poll(p)) |verified| {
            conn.id = verified.id;
            conn.stream.schedule(
                &self.loop,
                self.sock,
                verified.secret,
                p.from.toStd(),
            );
            conn.negotiated = true;

            std.log.debug("authenticated a connection", .{});
            killed = false;
        } else |_| {}

        return;
    }

    var enc_packet = gam.proto.Crypt.init(p.body, .to_decode) catch |err| {
        std.log.debug(
            "invalid encrypted packet: {}: {x}",
            .{ err, p.body },
        );
        return;
    };

    enc_packet.decrypt(conn.stream.key) catch |err| {
        std.log.debug(
            "failed to decrypt packet: {} {x} {}",
            .{ err, enc_packet.data, enc_packet.data.len },
        );
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

            .state => {
                std.log.warn("server only packet {}", .{packet});
                return;
            },
        }

        if (res == .unrelyable) break;
    }

    killed = false;
}

pub fn handlePackets(self: *Server) void {
    var packets = self.reader.packets();
    while (packets.next()) |p| {
        if (self.conns.getContext(p.from.toStd(), &self.hash_ctx)) |conn| {
            self.handleConnPacket(conn, p);
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
                self.rng,
                gam.proto.message_queue_size,
            );

            break :b slot;
        };

        const ent = self.sim.ents.add() catch {
            self.sendRaw(p.from.toStd(), .constant, gam.auth.max_conns_reached);
            continue;
        };

        ent.kind = .player;
        ent.pos = .{ 100, 100 };
        ent.friction = 1;
        ent.radius = 32;
        ent.health = 100;

        conn.* = .{
            .handshake = ServerHandshake{ .kp = &self.kp },
            .last_packet = get_now(),
            .stream = conn.stream,
            .input = .{},
            .ent = ent.id,
        };

        if (conn.handshake.init(&self.loop, self.sock, self.rng, p)) |_| {
            const slot = self.conns
                .getOrPutAssumeCapacityContext(p.from.toStd(), &self.hash_ctx);

            if (slot.found_existing) unreachable;

            self.q.queue(.{ .sh = &conn.handshake });
            slot.value_ptr.* = conn;

            continue;
        } else |_| {
            self.free_conns.push(conn);
            self.sendRaw(p.from.toStd(), .constant, "garbou");
        }
    }
}

pub fn init(port: u16) !Server {
    var hash_key: [16]u8 = undefined;
    std.crypto.random.bytes(&hash_key);

    const tmp_alloc = utils.Arena.scrath(null).arena;

    var self = Server{
        .pool = .{ .arena = utils.Arena.init(1024 * 1024 * 32) },
        .loop = try xev.Loop.init(.{}),

        .hash_ctx = .{ .key = hash_key },
        .rng = std.crypto.random,
        .sock = b: {
            const addr = std.net.Address.initIp4(@splat(0), port);

            const sock = try xev.UDP.init(addr);
            try sock.bind(addr);

            std.log.info("listening on port: {d}", .{addr.getPort()});

            break :b sock;
        },
        .kp = gam.auth.KeyPair.generate(),
        .reader = undefined,
        .sim = undefined,
    };

    self.sim = try .init(tmp_alloc, Sim.max_ents);
    self.reader = .{ .listen_buf = self.pool.arena.alloc(u8, 1 << 16) };
    try self.conns.ensureTotalCapacityContext(
        tmp_alloc.allocator(),
        max_conns,
        &self.hash_ctx,
    );

    self.frame.time = @floatFromInt(std.time.milliTimestamp());
    self.frame.last_tps_snapshot = get_now();
    self.frame.prev_time = self.frame.time;

    return self;
}

pub fn sync(self: *Server) void {
    errdefer unreachable;

    if (self.frame.tps_counter % (self.frame.target_tps / gam.proto.sps) != 0) return;

    var tmp = utils.Arena.scrath(null);
    defer tmp.deinit();

    const conns = tmp.arena.alloc(gam.proto.Packet.ConnSync, self.conns.entries.len);
    for (conns, self.conns.entries.items(.value)) |*slot, conn| {
        slot.* = .{ .id = conn.id, .ent = conn.ent, .input = conn.input };
    }

    self.broadcast(.unrelyable, .{ .state = .{
        .seq = self.state_seq,
        .conns = conns,
        .ents = self.sim.ents.slots.items,
    } });
    self.state_seq += 1;
}

pub fn handleInput(self: *Server) void {
    var tmp = utils.Arena.scrath(null);
    defer tmp.deinit();

    const conns: []*Connection = self.conns.entries.items(.value);

    for (conns) |conn| {
        self.sim.handleInput(.{ .delta = self.frame.delta }, conn.ent, conn.input);
    }
}

pub fn main() !void {
    utils.Arena.initScratch(1024 * 1024 * 16);

    var self = try init(8080);

    self.schedule();

    std.log.info("entering main loop", .{});

    while (true) {
        self.frame.update();

        self.sync();
        self.handleInput();
        self.sim.simulate(.{ .delta = self.frame.delta });

        const conns: []*Connection = self.conns.entries.items(.value);

        const now = get_now();

        var iter = std.mem.reverseIterator(conns);
        var i: usize = conns.len;
        while (@as(?*Connection, iter.next())) |conn| {
            i -= 1;
            if (conn.handshake.task.inProgress()) continue;
            if (now.since(conn.last_packet) > stale_conn_trashold) {
                self.killConnection(conn);
            }
        }

        while (self.frame.tick.state() != .dead) {
            try self.loop.run(.once);

            self.handleTask();
            self.handlePackets();
        }
    }
}
