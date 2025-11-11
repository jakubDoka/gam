const std = @import("std");
const gam = @import("gam");
const xev = @import("xev");
const utils = @import("utils");

pub const max_ents = 256;
pub const max_conns = 30;
pub const target_tps = 60;
pub const stale_conn_trashold = 300 * std.time.ns_per_ms;
pub const pong_period = 500;
pub const reload_period = 0.5;
pub const Server = @This();

pub const SendMode = enum { relyable, unrelyable };

pub const Connection = struct {
    handshake: ServerHandshake,
    id: gam.auth.Identity = undefined,
    stream: gam.proto.Stream = undefined,
    last_packet: std.time.Instant,
    negotiated: bool = false,

    input: gam.proto.PlayerInput,
    ent: SlotMap.Id,
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

pub const SlotMap = struct {
    pub const Id = packed struct(u64) {
        index: u32,
        gen: u32,

        pub fn get(self: Id, map: *SlotMap) ?*Ent {
            return map.get(self);
        }

        pub const invalid = Id{ .index = 0, .gen = std.math.maxInt(u32) };
    };

    slots: std.ArrayList(Ent),
    free: ?*Ent = null,

    pub fn init(scratch: *utils.Arena, cap: usize) !SlotMap {
        return .{
            .slots = try .initCapacity(scratch.allocator(), cap),
        };
    }

    pub fn add(self: *SlotMap) !*Ent {
        if (self.free) |fent| {
            const idx = (@intFromPtr(fent) - @intFromPtr(self.slots.items.ptr)) /
                @sizeOf(Ent);
            self.free = fent.next_free;

            fent.* = .{ .id = .{ .index = @intCast(idx), .gen = fent.id.gen + 1 } }; // eaven gen means we are alive

            return fent;
        }

        const slot = try self.slots.addOneBounded();
        slot.* = .{
            .id = .{ .index = @intCast(self.slots.items.len - 1), .gen = 0 },
        };

        return slot;
    }

    pub fn remove(self: *SlotMap, id: Id) bool {
        const slot = self.get(id) orelse return false;
        slot.id.gen += 1;
        slot.next_free = self.free;
        self.free = slot.next_free;
        return true;
    }

    pub fn get(self: *SlotMap, id: Id) ?*Ent {
        const slot = &self.slots.items[id.index];
        if (slot.id.gen != id.gen) return null;
        return slot;
    }
};

const Ent = struct {
    kind: enum { bullet, player } = undefined,

    reload: f32 = 0.0,
    lifetime: f32 = 0.0,
    friction: f32 = 0.0,
    radius: f32 = 0.0,
    mass_mult: f32 = 1.0,

    tmp_idx: u32 = undefined,

    owner: SlotMap.Id = .invalid,

    vel: gam.vec.T = gam.vec.zero,
    pos: gam.vec.T = gam.vec.zero,

    coll_id: u32 = std.math.maxInt(u32),

    next_free: ?*Ent = null,
    id: SlotMap.Id,

    pub fn isAlive(self: Ent) bool {
        return self.id.gen % 2 == 0;
    }
};

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

ents: SlotMap = undefined,

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

pub fn killConnection(self: *Server, conn: *Connection) void {
    const idx = std.mem.indexOfScalar(
        *Connection,
        self.conns.entries.items(.value),
        conn,
    ).?;
    _ = self.conns.swapRemoveAtContext(idx, &self.hash_ctx);
    conn.stream.unschedule(&self.loop);
    _ = self.ents.remove(conn.ent);
    self.free_conns.push(conn);
}

pub fn handleConnPacket(
    self: *Server,
    conn: *Connection,
    p: gam.UdpReader.Packet,
) !void {
    conn.last_packet = try .now();

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

            .state => {
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
                self.rng,
                gam.proto.message_queue_size,
            );

            break :b slot;
        };

        const ent = self.ents.add() catch unreachable;
        ent.kind = .player;
        ent.pos = .{ 100, 100 };
        ent.friction = 1;
        ent.radius = gam.proto.player_size / 2;

        conn.* = .{
            .handshake = ServerHandshake{ .kp = &self.kp },
            .last_packet = try .now(),
            .stream = conn.stream,
            .input = .{},
            .ent = ent.id,
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

pub fn main() !void {
    utils.Arena.initScratch(1024 * 1024 * 16);

    const port = 8080;

    var hash_key: [16]u8 = undefined;
    std.crypto.random.bytes(&hash_key);

    const tmp_alloc = utils.Arena.scrath(null).arena;

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

    self.ents = try .init(tmp_alloc, max_ents);
    self.reader = .{ .listen_buf = self.pool.arena.alloc(u8, 1 << 16) };
    try self.conns.ensureTotalCapacityContext(
        tmp_alloc.allocator(),
        max_conns,
        &self.hash_ctx,
    );
    self.schedule(&self.loop, self.sock);

    var time: f64 = @floatFromInt(std.time.milliTimestamp());

    var tps_counter: usize = 0;
    var last_tps_snapshot = try std.time.Instant.now();
    var state_seq: u32 = 1;
    var delta: f32 = 0;
    var prev_time = time;

    while (true) {
        if (self.tick.state() == .dead) {
            const now_time: f64 = @floatFromInt(std.time.milliTimestamp());
            delta = @floatCast(now_time - prev_time);
            delta /= 1000;
            prev_time = now_time;
            time += 1000.0 / @as(f64, target_tps);
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
        const conns: []*Connection = self.conns.entries.items(.value);

        var tmp = utils.Arena.scrath(null);
        defer tmp.deinit();

        { // state sync
            var player_states: std.ArrayList(gam.proto.Packet.PlayerSync) = .empty;
            var i: u32 = 0;
            for (conns) |conn| {
                const ent = self.ents.get(conn.ent) orelse continue;

                ent.tmp_idx = i;
                i += 1;

                (try player_states.addOne(tmp.arena.allocator())).* = .{
                    .id = conn.id,
                    .pos = ent.pos,
                    .mouse_pos = conn.input.mouse_pos,
                };
            }

            var bullet_states: std.ArrayList(gam.proto.Packet.BulletSync) = .empty;
            for (self.ents.slots.items) |ent| {
                if (!ent.isAlive()) continue;
                if (ent.kind != .bullet) continue;
                const owner = ent.owner.get(&self.ents) orelse continue;

                (try bullet_states.addOne(tmp.arena.allocator())).* = .{
                    .content_id = 0,
                    .pos = ent.pos,
                    .vel = ent.vel,
                    .owner = @intCast(owner.tmp_idx),
                    .lifetime = ent.lifetime,
                };
            }

            self.broadcast(.unrelyable, .{ .state = .{
                .seq = state_seq,
                .players = player_states.items,
                .bullets = bullet_states.items,
            } });
            state_seq += 1;
        }

        { // input simulation
            for (conns) |conn| {
                const ent = self.ents.get(conn.ent) orelse continue;

                var dir = gam.vec.zero;
                if (conn.input.key_mask.up) dir += .{ 0, -1 };
                if (conn.input.key_mask.down) dir += .{ 0, 1 };
                if (conn.input.key_mask.left) dir += .{ -1, 0 };
                if (conn.input.key_mask.right) dir += .{ 1, 0 };
                dir = gam.vec.norm(dir);

                const player_acc = 500;

                ent.vel += dir * gam.vec.splat(player_acc * delta);

                const look_dir = gam.vec.norm(conn.input.mouse_pos - ent.pos);
                const bullet_lifetime = 0.5;
                const bullet_speed = 1000;

                ent.reload -= delta;
                if (conn.input.key_mask.shoot) {
                    if (ent.reload <= 0) b: {
                        const slot = self.ents.add() catch break :b;
                        ent.reload = reload_period;

                        slot.kind = .bullet;
                        slot.pos = ent.pos;
                        slot.vel = look_dir * gam.vec.splat(bullet_speed);
                        slot.owner = conn.ent;
                        slot.lifetime = bullet_lifetime;
                        slot.radius = gam.proto.bullet_size / 2;
                    }
                }
            }
        }

        const Coll = struct { a: SlotMap.Id, b: SlotMap.Id, t: f32 };
        var collisions: std.ArrayList(Coll) = .empty;

        for (self.ents.slots.items) |*ent| {
            if (!ent.isAlive()) continue;

            ent.vel *= gam.vec.splat(1 - (ent.friction * delta));
            ent.pos += ent.vel * gam.vec.splat(delta);

            // physics sim
            collect_colls: for (self.ents.slots.items) |*oent| {
                if (!oent.isAlive() or oent == ent) continue;
                if (oent.owner == ent.id or ent.owner == oent.id) continue;

                const min_dist = ent.radius + oent.radius;
                const dist = gam.vec.dist2(ent.pos, oent.pos);

                // get rid of overlaps
                if (min_dist * min_dist > dist) {
                    if (ent.radius > oent.radius) {
                        oent.pos = ent.pos + gam.vec.norm(oent.pos - ent.pos) *
                            gam.vec.splat(min_dist);
                    } else {
                        ent.pos = oent.pos + gam.vec.norm(ent.pos - oent.pos) *
                            gam.vec.splat(min_dist);
                    }
                }

                // this is a formula I derived somehow
                const d = oent.pos - ent.pos;
                const dv = oent.vel - ent.vel;

                const a = gam.vec.dot(dv, dv);
                const b = 2 * gam.vec.dot(dv, d);
                const c = gam.vec.dot(d, d) - min_dist * min_dist;

                const disc = b * b - 4 * a * c;
                if (disc <= 0) continue;

                const t1 = (-b + std.math.sqrt(disc)) / (2 * a);
                const t2 = (-b - std.math.sqrt(disc)) / (2 * a);
                const t = @min(t1, t2);

                if (t < 0 or t > delta) continue;

                for ([_]*Ent{ ent, oent }) |e| {
                    if (e.coll_id != std.math.maxInt(u32)) {
                        if (collisions.items[e.coll_id].t > t) {
                            collisions.items[e.coll_id].t = delta;
                        } else continue :collect_colls;
                    }
                }

                oent.coll_id = @intCast(collisions.items.len);
                ent.coll_id = @intCast(collisions.items.len);

                collisions.append(
                    tmp.arena.allocator(),
                    .{ .a = ent.id, .b = oent.id, .t = t },
                ) catch unreachable;
            }

            switch (ent.kind) {
                .bullet => {
                    ent.lifetime -= delta;

                    if (ent.lifetime <= 0) {
                        _ = self.ents.remove(ent.id);
                        continue;
                    }

                    for (self.ents.slots.items) |*oent| {
                        if (!oent.isAlive()) continue;
                        if (oent == ent) continue;

                        if (gam.vec.dist(oent.pos, ent.pos) <
                            (gam.proto.bullet_size + gam.proto.player_size) / 2 and
                            oent.id != ent.owner)
                        {
                            _ = self.ents.remove(ent.id);
                        }
                    }
                },
                .player => {},
            }
        }

        for (collisions.items) |col| {
            const aent_o = col.a.get(&self.ents);
            const bent_o = col.b.get(&self.ents);

            if (aent_o) |aent| aent.coll_id = std.math.maxInt(u32);
            if (bent_o) |bent| bent.coll_id = std.math.maxInt(u32);

            if (col.t == delta) continue;

            const aent = aent_o orelse continue;
            const bent = bent_o orelse continue;

            aent.pos += aent.vel * gam.vec.splat(col.t);
            bent.pos += bent.vel * gam.vec.splat(col.t);

            const dist = gam.vec.dist(aent.pos, bent.pos);

            {
                const amult = aent.mass_mult;
                const bmult = bent.mass_mult;

                const amass = aent.radius * amult;
                const bmass = bent.radius * bmult;

                const norm = (bent.pos - aent.pos) / gam.vec.splat(dist);
                const p = 2 * (gam.vec.dot(aent.vel, norm) -
                    gam.vec.dot(bent.vel, norm)) / (amass + bmass);

                for ([_]*Ent{ aent, bent }, [_]f32{ -bmass, amass }) |c, m| {
                    c.vel += gam.vec.splat(p * m) * norm;
                    c.pos -= c.vel * gam.vec.splat(col.t);
                }
            }
        }

        for (self.ents.slots.items) |ent| {
            if (ent.isAlive()) {
                std.debug.assert(ent.coll_id == std.math.maxInt(u32));
            }
        }

        var iter = std.mem.reverseIterator(conns);
        var i: usize = conns.len;
        while (@as(?*Connection, iter.next())) |conn| {
            i -= 1;
            if (conn.handshake.task.inProgress()) continue;
            if (now.since(conn.last_packet) > stale_conn_trashold) {
                self.killConnection(conn);
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
