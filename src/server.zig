const std = @import("std");
const gam = @import("gam");
const xev = @import("xev");
const utils = @import("utils");
const vec = gam.vec;

pub const Id = gam.proto.Id;

pub const max_ents = 256;
pub const max_conns = 30;
pub const stale_conn_trashold = 300 * std.time.ns_per_ms;
pub const pong_period = 500;
pub const reload_period = 0.5;
pub const no_coll_id = std.math.maxInt(u32);
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

    input: gam.proto.PlayerInput,
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

pub const SlotMap = struct {
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

    // mostly static
    friction: f32 = 0.0,
    radius: f32 = 0.0,
    mass_mult: f32 = 1.0,
    damage: u32 = 0,

    reload: f32 = 0.0,
    lifetime: f32 = 0.0,
    health: u32 = 0,

    tmp_idx: u32 = undefined,

    owner: Id = .invalid,

    vel: vec.T = vec.zero,
    pos: vec.T = vec.zero,

    coll_id: u32 = no_coll_id,

    next_free: ?*Ent = null,
    id: Id,

    pub fn isAlive(self: Ent) bool {
        return self.id.gen % 2 == 0;
    }
};

pub const Frame = struct {
    time: f64 = undefined,

    tps_counter: usize = 0,
    tps: usize = 0,
    last_tps_snapshot: std.time.Instant = undefined,
    delta: f32 = 0,
    prev_time: f64 = undefined,
    comptime target_tps: f64 = 60,

    tick_timer: xev.Timer = .{},
    tick: xev.Completion = .{},

    pub fn update(self: *Frame) void {
        const client: *Server = @fieldParentPtr("frame", self);

        if (self.tick.state() == .dead) {
            const now_time: f64 = @floatFromInt(std.time.milliTimestamp());
            self.delta = @floatCast(now_time - self.prev_time);
            self.delta /= 1000;
            self.prev_time = now_time;
            self.time += 1000.0 / self.target_tps;
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

ents: SlotMap,

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
    _ = self.ents.remove(conn.ent);
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

        const ent = self.ents.add() catch {
            self.sendRaw(p.from.toStd(), .constant, gam.auth.max_conns_reached);
            continue;
        };

        ent.kind = .player;
        ent.pos = .{ 100, 100 };
        ent.friction = 1;
        ent.radius = gam.proto.player_size / 2;
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
        .ents = undefined,
    };

    self.ents = try .init(tmp_alloc, max_ents);
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

    var tmp = utils.Arena.scrath(null);
    defer tmp.deinit();

    const conns: []*Connection = self.conns.entries.items(.value);

    var player_states: std.ArrayList(gam.proto.Packet.PlayerSync) = .empty;
    var i: u32 = 0;
    for (conns) |conn| {
        const ent = self.ents.get(conn.ent) orelse continue;

        ent.tmp_idx = i;
        i += 1;

        try player_states.append(tmp.arena.allocator(), .{
            .identity = conn.id,
            .pos = ent.pos,
            .mouse_pos = conn.input.mouse_pos,
            .id = ent.id,
        });
    }

    var bullet_states: std.ArrayList(gam.proto.Packet.BulletSync) = .empty;
    for (self.ents.slots.items) |ent| {
        if (!ent.isAlive()) continue;
        if (ent.kind != .bullet) continue;
        const owner = self.ents.get(ent.owner) orelse continue;

        try bullet_states.append(tmp.arena.allocator(), .{
            .pos = ent.pos,
            .vel = ent.vel,
            .owner = owner.tmp_idx,
            .lifetime = ent.lifetime,
            .id = ent.id,
        });
    }

    self.broadcast(.unrelyable, .{ .state = .{
        .seq = self.state_seq,
        .players = player_states.items,
        .bullets = bullet_states.items,
    } });
    self.state_seq += 1;
}

pub fn handleInput(self: *Server) void {
    var tmp = utils.Arena.scrath(null);
    defer tmp.deinit();

    const conns: []*Connection = self.conns.entries.items(.value);

    for (conns) |conn| {
        const ent = self.ents.get(conn.ent) orelse continue;

        var dir = vec.zero;
        if (conn.input.key_mask.up) dir += .{ 0, -1 };
        if (conn.input.key_mask.down) dir += .{ 0, 1 };
        if (conn.input.key_mask.left) dir += .{ -1, 0 };
        if (conn.input.key_mask.right) dir += .{ 1, 0 };
        dir = vec.norm(dir);

        const player_acc = 500;

        ent.vel += dir * vec.splat(player_acc * self.frame.delta);

        const look_dir = vec.norm(conn.input.mouse_pos - ent.pos);
        const bullet_lifetime = 0.5;
        const bullet_speed = 1000;

        ent.reload -= self.frame.delta;
        if (conn.input.key_mask.shoot) {
            if (ent.reload <= 0) b: {
                const slot = self.ents.add() catch break :b;
                ent.reload = reload_period;

                slot.kind = .bullet;
                slot.pos = ent.pos;
                slot.vel = look_dir * vec.splat(bullet_speed);
                slot.owner = conn.ent;
                slot.lifetime = bullet_lifetime;
                slot.radius = gam.proto.bullet_size / 2;
                slot.damage = 25;
            }
        }
    }
}

pub fn simulate(self: *Server) void {
    errdefer unreachable;

    var tmp = utils.Arena.scrath(null);
    defer tmp.deinit();

    const Coll = struct { a: Id, b: Id, t: f32 };
    var collisions: std.ArrayList(Coll) = .empty;

    for (self.ents.slots.items) |*ent| {
        if (!ent.isAlive()) continue;

        ent.vel *= vec.splat(1 - (ent.friction * self.frame.delta));
        ent.pos += ent.vel * vec.splat(self.frame.delta);

        collect_colls: for (self.ents.slots.items) |*oent| {
            if (!oent.isAlive() or oent == ent) continue;
            if (oent.owner == ent.id or ent.owner == oent.id) continue;

            const min_dist = ent.radius + oent.radius;
            const dist = vec.dist2(ent.pos, oent.pos);

            // get rid of overlaps
            if (min_dist * min_dist > dist) {
                if (ent.radius > oent.radius) {
                    oent.pos = ent.pos + vec.norm(oent.pos - ent.pos) *
                        vec.splat(min_dist);
                } else {
                    ent.pos = oent.pos + vec.norm(ent.pos - oent.pos) *
                        vec.splat(min_dist);
                }
            }

            // this is a formula I derived somehow
            const d = oent.pos - ent.pos;
            const dv = oent.vel - ent.vel;

            const a = vec.dot(dv, dv);
            const b = 2 * vec.dot(dv, d);
            const c = vec.dot(d, d) - min_dist * min_dist;

            const disc = b * b - 4 * a * c;
            if (disc <= 0) continue;

            const t1 = (-b + std.math.sqrt(disc)) / (2 * a);
            const t2 = (-b - std.math.sqrt(disc)) / (2 * a);
            const t = @min(t1, t2);

            if (t < 0 or t > self.frame.delta) continue;

            for ([_]*Ent{ ent, oent }) |e| {
                if (e.coll_id != no_coll_id) {
                    if (collisions.items[e.coll_id].t > t) {
                        collisions.items[e.coll_id].t = -1;
                    } else continue :collect_colls;
                }
            }

            oent.coll_id = @intCast(collisions.items.len);
            ent.coll_id = @intCast(collisions.items.len);

            try collisions.append(
                tmp.arena.allocator(),
                .{ .a = ent.id, .b = oent.id, .t = t },
            );
        }

        const prev_lt = ent.lifetime;
        ent.lifetime -= self.frame.delta;
        if (ent.lifetime <= 0 and prev_lt > 0) {
            _ = self.ents.remove(ent.id);
            continue;
        }
    }

    for (collisions.items) |col| {
        const aent_o = self.ents.get(col.a);
        const bent_o = self.ents.get(col.b);

        if (aent_o) |aent| aent.coll_id = no_coll_id;
        if (bent_o) |bent| bent.coll_id = no_coll_id;

        if (col.t < 0) continue;

        const aent = aent_o orelse continue;
        const bent = bent_o orelse continue;

        aent.pos += aent.vel * vec.splat(col.t);
        bent.pos += bent.vel * vec.splat(col.t);

        const amass = aent.radius * aent.mass_mult;
        const bmass = bent.radius * bent.mass_mult;

        const dist = vec.dist(aent.pos, bent.pos);
        const norm = (bent.pos - aent.pos) / vec.splat(dist);
        const p = 2 * (vec.dot(aent.vel, norm) -
            vec.dot(bent.vel, norm)) / (amass + bmass);

        for ([_]*Ent{ aent, bent }, [_]f32{ -bmass, amass }) |c, m| {
            c.vel += vec.splat(p * m) * norm;
            c.pos -= c.vel * vec.splat(col.t);
        }

        for ([_]*Ent{ aent, bent }, [_]*Ent{ bent, aent }) |a, b| {
            // NOTE: we dont die twice, but also, invincible objects start with
            // health 0
            if (a.health == 0) continue;
            a.health -|= b.damage;
            if (a.health == 0) {
                _ = self.ents.remove(a.id);
            }
        }
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
        self.simulate();

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
