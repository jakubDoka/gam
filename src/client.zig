const std = @import("std");
const gam = @import("gam");
const xev = @import("xev");
const utils = @import("utils");
const ui = @import("client/ui.zig");
const proto = @import("client/proto.zig");
const PlayerSync = gam.proto.Packet.PlayerSync;
const BulletSync = gam.proto.Packet.BulletSync;
const vec = gam.vec;
const Sim = gam.sim;

pub const Client = @This();

pub const rl = @cImport({
    @cInclude("raylib.h");
    @cInclude("raymath.h");
    @cInclude("raygui.h");
});

pub const std_options: std.Options = .{
    .log_level = .debug,
};

const sheet_rects = @import("sheet_zig");

const ping_interval = 300;
const stale_connection_period = 2 * std.time.ns_per_s;
const max_retries = 4;
const max_particles = 256;

pub fn get_time_secs() f64 {
    return @as(f64, @floatFromInt(std.time.milliTimestamp())) / 1000;
}

pub fn InRect(r: rl.Rectangle, v: rl.Vector2) bool {
    return r.x <= v.x and v.x <= r.x + r.width and
        r.y <= v.y and v.y <= r.y + r.height;
}

pub fn SliceStr(buf: []u8) [:0]u8 {
    return buf[0..std.mem.indexOfScalar(u8, buf, 0).? :0];
}

pool: utils.SclassPool,

loop: xev.Loop,
q: gam.Queue(union(enum) {
    ch: *proto.ClientHandshake,
    one_off: *gam.OneOffPacket,
    retry_handshake: *gam.Sleep,
    ping_interval: *gam.Sleep,
    close: *gam.proto.Stream.Closer,
    some_sleep: *gam.Sleep,
}) = .{},

kp: gam.auth.KeyPair,
handshake: proto.ClientHandshake = undefined,
handshake_retry_sleep: gam.Sleep = .{},
handshake_retry_round: usize = 0,
server_id: gam.auth.Identity = undefined,

stream: gam.proto.Stream = undefined,
closer: gam.proto.Stream.Closer = .{},
reader: gam.UdpReader = undefined,
reader_canc: xev.Completion = .{},
connection_state: enum {
    disconnected,
    disconnecting,
    connecting,
    connected,
} = .disconnected,

free_oneoffs: gam.List(gam.OneOffPacket) = .{},

last_ping: std.time.Instant = undefined,
last_server_ping: std.time.Instant = undefined,
ping_sleep: gam.Sleep = .{},
ping_n: u32 = 0,
ping: u64 = 0,
average_ping_sum: u64 = 0,
ping_count: u64 = 0,
tps: usize = 0,
frame_counter: usize = 0,

prng: std.Random.DefaultPrng = .init(0),

chat: ui.Chat = .{},
connection_menu: ui.ConnectionMenu = .{},

state_seq: u32 = 0,
input_seq: u32 = 1,

conns: std.ArrayList(gam.proto.Packet.ConnSync) = undefined,
sim: Sim,

particles: std.ArrayList(Particle) = undefined,

sheet: rl.Texture2D = undefined,
camera: rl.Camera2D = .{ .zoom = 1 },

map: TileMap,

stats: []const Stats = &.{ .{
    .sprite = sheet_rects.player,
    .playable = true,
    .cbs = .init(opaque {
        pub const explode = common.explodeShip;
    }),
}, .{
    .sprite = sheet_rects.bullet,
    .cbs = .init(opaque {
        pub fn explode(self: *Client, a: Sim.Ent) void {
            for (0..10) |_| {
                const rng = self.prng.random();
                self.particles.appendBounded(.{
                    .pos = a.pos,
                    .vel = vec.unit(rng.float(f32) * 2 * rl.PI) *
                        vec.splat(rng.float(f32) * 100 + 10),
                    .lifetime = 0.3 + rng.float(f32) * 0.2,
                    .radius = 10 + rng.float(f32) * 10,
                    .color = rl.SKYBLUE,
                }) catch {};
            }
        }
        pub fn trail(self: *Client, ent: Sim.Ent) void {
            self.particles.appendBounded(.{
                .pos = ent.pos,
                .vel = vec.zero,
                .radius = 10,
                .lifetime = 0.5,
                .color = rl.SKYBLUE,
            }) catch {};
        }
    }),
}, .{
    .sprite = sheet_rects.player2,
    .playable = true,
    .cbs = .init(opaque {
        pub const explode = common.explodeShip;
    }),
}, .{
    .sprite = sheet_rects.bullet,
    .cbs = .init(opaque {
        pub fn explode(self: *Client, a: Sim.Ent) void {
            for (0..10) |_| {
                const rng = self.prng.random();
                self.particles.appendBounded(.{
                    .pos = a.pos,
                    .vel = vec.unit(rng.float(f32) * 2 * rl.PI) *
                        vec.splat(rng.float(f32) * 50 + 10),
                    .lifetime = 0.2 + rng.float(f32) * 0.1,
                    .radius = 5 + rng.float(f32) * 5,
                    .color = rl.SKYBLUE,
                }) catch {};
            }
        }
        pub fn trail(self: *Client, ent: Sim.Ent) void {
            self.particles.appendBounded(.{
                .pos = ent.pos,
                .vel = vec.zero,
                .radius = 8,
                .lifetime = 0.5,
                .color = rl.SKYBLUE,
            }) catch {};
        }
    }),
}, .{
    .sprite = sheet_rects.player3,
    .playable = true,
    .cbs = .init(opaque {
        pub const explode = common.explodeShip;
    }),
}, .{
    .sprite = sheet_rects.bullet,
    .cbs = .init(opaque {
        pub fn explode(self: *Client, a: Sim.Ent) void {
            for (0..10) |_| {
                const rng = self.prng.random();
                self.particles.appendBounded(.{
                    .pos = a.pos,
                    .vel = vec.unit(rng.float(f32) * 2 * rl.PI) *
                        vec.splat(rng.float(f32) * 50 + 10),
                    .lifetime = 0.2 + rng.float(f32) * 0.1,
                    .radius = 5 + rng.float(f32) * 5,
                    .color = rl.SKYBLUE,
                }) catch {};
            }
        }
        pub fn trail(self: *Client, ent: Sim.Ent) void {
            self.particles.appendBounded(.{
                .pos = ent.pos,
                .vel = vec.zero,
                .radius = 8,
                .lifetime = 0.5,
                .color = rl.SKYBLUE,
            }) catch {};
        }
    }),
} },

pub const common = opaque {
    pub fn explodeShip(self: *Client, a: Sim.Ent) void {
        for (0..30) |_| {
            const rng = self.prng.random();
            self.particles.appendBounded(.{
                .pos = a.pos,
                .vel = vec.unit(rng.float(f32) * 2 * rl.PI) *
                    vec.splat(rng.float(f32) * 200 + 30),
                .lifetime = 0.3 + rng.float(f32) * 0.2,
                .radius = 20 + rng.float(f32) * 10,
                .color = rl.SKYBLUE,
            }) catch {};
        }
    }
};

const Spec = struct {
    pub const tile_sheet = [_]rl.Rectangle{
        sheet_rects.tile_full,
    };

    pub const weng_tiles = [_]rl.Rectangle{
        sheet_rects.tile_corner,
        sheet_rects.tile_side,
    };

    pub const world_size_pow = 11;
};

pub const TileMap = struct {
    const Tile = std.math.IntFittingRange(0, Spec.tile_sheet.len);
    pub const no_tile = std.math.maxInt(Tile);
    pub const tile_size: u32 = @intFromFloat(Spec.tile_sheet[0].width * 2);
    pub const stride = (@as(u32, 1) << Spec.world_size_pow) / tile_size;
    const size = stride * stride;

    tiles: *[size]Tile,
    pub fn init(scratch: *utils.Arena) TileMap {
        const self = TileMap{ .tiles = scratch.create([size]Tile) };
        @memset(self.tiles, no_tile);
        return self;
    }

    inline fn project(v: f32) u32 {
        return @intCast(std.math.clamp(@as(i32, @intFromFloat(v / tile_size)), 0, @as(i32, @intCast(stride - 1))));
    }

    pub inline fn get(self: *@This(), x: usize, y: usize) Tile {
        return self.tiles[y * stride + x];
    }

    pub inline fn set(self: *@This(), x: usize, y: usize, tile: Tile) void {
        self.tiles[y * stride + x] = tile;
    }

    pub fn draw(self: *@This(), view_port: rl.Rectangle) void {
        const client: *Client = @fieldParentPtr("map", self);

        const minx = project(view_port.x);
        const miny = project(view_port.y);
        const maxx = project(view_port.x + view_port.width + tile_size);
        const maxy = project(view_port.y + view_port.height + tile_size);

        const color = rl.WHITE;
        for (miny..maxy) |y| for (minx..maxx) |x| {
            const tile = self.tiles[y * stride + x];
            const pos = vec.T{ vec.tof(x * tile_size), vec.tof(y * tile_size) } + vec.splat(tile_size / 2);

            if (tile != no_tile) {
                rl.DrawTexturePro(client.sheet, Spec.tile_sheet[tile], .{
                    .x = pos[0],
                    .y = pos[1],
                    .width = tile_size,
                    .height = tile_size,
                }, .{ .x = tile_size / 2, .y = tile_size / 2 }, 0, color);
                continue;
            }

            const utls = struct {
                pub inline fn sideMask(side: u2, value: bool) u8 {
                    return ([_]u8{ 0b111, 0b1_1_100, 0b111_0_000, 0b110_0_000_1 })[side] * @intFromBool(value);
                }

                pub inline fn cornerMask(side: u2, value: bool) u8 {
                    return ([_]u8{ 0b1, 0b100, 0b1_0_000, 0b0_100_0_000 })[side] * @intFromBool(value);
                }
            };

            const s = stride - 1;
            const bitset: u8 =
                utls.sideMask(0, y != 0 and self.get(x, y - 1) == 0) |
                utls.sideMask(1, x != s and self.get(x + 1, y) == 0) |
                utls.sideMask(2, y != s and self.get(x, y + 1) == 0) |
                utls.sideMask(3, x != 0 and self.get(x - 1, y) == 0) |
                utls.cornerMask(0, x != 0 and y != 0 and self.get(x - 1, y - 1) == 0) |
                utls.cornerMask(1, x != s and y != 0 and self.get(x + 1, y - 1) == 0) |
                utls.cornerMask(2, x != s and y != s and self.get(x + 1, y + 1) == 0) |
                utls.cornerMask(3, x != 0 and y != s and self.get(x - 1, y + 1) == 0);

            for (0..8) |i| {
                if (i % 2 == 0 and bitset & (@as(u8, 1) << @intCast(i)) != 0) {
                    rl.DrawTexturePro(
                        client.sheet,
                        Spec.weng_tiles[0],
                        .{
                            .x = pos[0],
                            .y = pos[1],
                            .width = tile_size,
                            .height = tile_size,
                        },
                        .{ .x = tile_size / 2, .y = tile_size / 2 },
                        (std.math.tau / 4.0) * vec.tof(i / 2) / std.math.tau * 360,
                        color,
                    );
                }
            }

            for (0..8) |i| {
                if (i % 2 == 1 and bitset & (@as(u8, 1) << @intCast(i)) != 0) {
                    rl.DrawTexturePro(
                        client.sheet,
                        Spec.weng_tiles[1],
                        .{
                            .x = pos[0],
                            .y = pos[1],
                            .width = tile_size,
                            .height = tile_size,
                        },
                        .{ .x = tile_size / 2, .y = tile_size / 2 },
                        (std.math.tau / 4.0) * vec.tof(i / 2) / std.math.tau * 360,
                        color,
                    );
                }
            }
        };
    }
};

pub const Particle = struct {
    pos: vec.T,
    vel: vec.T,
    radius: f32,
    lifetime: f32,
    age: f32 = 0.0,
    color: rl.Color,
};

pub const Stats = struct {
    playable: bool = false,
    sprite: rl.Rectangle,
    cbs: Callbacks = .{},
};

pub const Callbacks = struct {
    explode: *const fn (sim: *Client, ent: Sim.Ent) void = default.explode,
    trail: *const fn (sim: *Client, ent: Sim.Ent) void = default.trail,

    const default = opaque {
        fn explode(self: *Client, ent: Sim.Ent) void {
            _ = self;
            _ = ent;
        }

        fn trail(self: *Client, ent: Sim.Ent) void {
            _ = self;
            _ = ent;
        }
    };

    pub fn init(comptime cbs: type) Callbacks {
        var self = Callbacks{};

        for (std.meta.fields(Callbacks)) |f| {
            if (@hasDecl(cbs, f.name)) @field(self, f.name) = &@field(cbs, f.name);
        }

        return self;
    }
};

pub fn startHandshake(self: *Client, ip: std.net.Address) !void {
    self.connection_state = .connecting;
    self.handshake_retry_round = 0;
    self.handshake = .{
        .server = ip,
        .rng = self.stream.rng,
        .kp = &self.kp,
        .hello_timeout = .{ .deadline = 500 },
    };

    const addr = std.net.Address.initIp4(@splat(0), 0);
    const sock = xev.UDP.init(addr) catch |err| {
        std.log.err("udp connection failed: {}", .{err});
        return error.@"cant open the socket";
    };
    sock.bind(addr) catch |err| {
        std.log.err("udp binding failed: {}", .{err});
        return error.@"cant bind the socket";
    };

    self.stream.sock = sock; // HACK: we read this from there on retry

    try self.handshake.schedule(&self.loop, sock);
    self.q.queue(.{ .ch = &self.handshake });

    self.chat.messages.items.len = 0;
    self.chat.message_timeouts = @splat(0);
    self.sim.reset();
    self.conns.items.len = 0;
}

pub fn disconnect(self: *Client) void {
    self.connection_state = .disconnecting;
    self.reader.unschedule(&self.loop, &self.reader_canc);
    self.stream.unschedule(&self.loop);
    self.closer.schedule(&self.loop, self.stream.sock);
    self.q.queue(.{ .close = &self.closer });
}

pub fn send(
    self: *Client,
    comptime mode: enum { relyable, unrelyable },
    packet: gam.proto.Packet,
) !void {
    if (mode == .unrelyable) {
        const pack = gam.proto.bufferPacket(
            packet,
            self.pool.allocator(),
        ) catch unreachable;

        pack.encrypt(self.stream.rng, self.stream.key);
        const one_off = self.free_oneoffs.pop() orelse
            self.pool.arena.create(gam.OneOffPacket);
        one_off.* = .{};
        one_off.schedule(
            &self.loop,
            self.stream.sock,
            self.handshake.server,
            pack.asBytes(),
        );
        self.q.queue(.{ .one_off = one_off });
    } else {
        gam.proto.bufferPacketRelyable(
            packet,
            &self.loop,
            &self.stream,
        ) catch return error.ServerOverload;
    }
}

pub fn handlePackets(self: *Client) !void {
    if (self.connection_state != .connected) return;

    var packets = self.reader.packets();
    stream: while (packets.next()) |p| {
        var killed = true;

        defer if (killed) self.disconnect();

        const crypt = gam.proto.Crypt.init(p.body, .to_decode) catch |err| {
            std.log.warn(
                "malformed packet from the server: {} {s}",
                .{ err, p.body },
            );
            break;
        };

        crypt.decrypt(self.stream.key) catch |err| {
            std.log.warn("failed to decrypt packet: {}", .{err});
            break;
        };

        const res = self.stream.handlePacket(
            &self.loop,
            crypt.getPlain(),
        ) catch |err| {
            std.log.warn("failed to handle stream packet: {}", .{err});
            break;
        };

        while (true) {
            const data = switch (res) {
                .handled => break,
                .unrelyable => crypt.getPlain().data,
                .relyable => self.stream.next() orelse break,
            };

            const packet = gam.proto.unbufferPacket(data) catch |err| {
                std.log.warn("unparsable packet from the server: {}", .{err});
                continue :stream;
            };

            try self.handlePacket(packet);

            if (res == .unrelyable) break;
        }

        killed = false;
    }
}

pub fn handlePacket(self: *Client, packet: gam.proto.Packet) !void {
    switch (packet) {
        .ping => |ping| {
            self.tps = ping.tps;
            self.send(.unrelyable, .{ .pong = ping }) catch {};
            self.last_server_ping = try .now();
        },
        .pong => |pong| {
            if (pong.tps == self.ping_n - 1) {
                self.ping = (try std.time.Instant.now())
                    .since(self.last_ping);
                self.average_ping_sum += self.ping;
                self.ping_count += 1;
            }
        },
        .chat_message => |msg| {
            self.chat.addMessage(msg);
        },
        .state => |s| {
            if (s.seq > self.state_seq) {
                self.state_seq = s.seq;

                self.conns.items.len = s.conns.len;
                @memcpy(self.conns.items, s.conns);

                var tmp = utils.Arena.scrath(null);
                defer tmp.deinit();

                const dupe_present = tmp.arena.alloc(u64, s.present.len);
                @memcpy(dupe_present, s.present);

                var present = std.DynamicBitSetUnmanaged{
                    .bit_length = s.present.len * 64,
                    .masks = dupe_present.ptr,
                };

                const prev_len = self.sim.ents.slots.items.len;
                self.sim.ents.slots.items.len = present.bit_length;

                for (self.sim.ents.slots.items[prev_len..], prev_len..) |*ent, i| {
                    ent.* = .{ .id = .{ .index = @intCast(i), .gen = 1 } };
                }

                var cursor: usize = 0;
                for (self.sim.ents.slots.items, 0..) |*ent, i| {
                    const prev_id = ent.id;
                    const prev_alive = ent.isAlive();
                    if (present.isSet(i)) {
                        ent.* = s.ents[cursor].expand(&self.sim, i);
                        cursor += 1;
                    } else {
                        ent.id = .{ .index = @intCast(i), .gen = 1 };
                    }

                    if (prev_alive) {
                        if (ent.id != prev_id) {
                            self.stats[ent.stats.id(&self.sim)]
                                .cbs.explode(self, ent.*);
                        }
                    }
                }
            }
        },
        .player_input, .spawn => unreachable,
    }
}

pub fn rtt(self: *Client) f64 {
    return @as(f64, @floatFromInt(self.average_ping_sum)) /
        @as(f64, @floatFromInt(self.average_ping_sum)) / 2000.0;
}

pub fn handleTasks(self: *Client) !void {
    while (self.q.next()) |task| switch (task) {
        .ch => |ch| {
            std.debug.assert(self.connection_state == .connecting);
            const verified, const sock = ch.task.res catch |err| {
                std.log.warn("handshake failed: {}", .{err});
                if (self.handshake_retry_round < max_retries) {
                    self.handshake_retry_sleep.schedule(&self.loop, 250);
                    self.q.queue(.{
                        .retry_handshake = &self.handshake_retry_sleep,
                    });
                    self.handshake_retry_round += 1;
                } else {
                    std.log.warn("server is not reachable", .{});
                    self.connection_state = .disconnected;
                    self.handshake_retry_round = 0;
                    self.connection_menu.ip_error = error.@"server unreachable";
                }
                continue;
            };

            std.log.debug("handshake succrsfull", .{});

            self.stream.schedule(&self.loop, sock, verified.secret, ch.server);
            self.reader.schedule(&self.loop, sock);

            if (!self.ping_sleep.task.inProgress()) {
                self.ping_sleep.schedule(&self.loop, ping_interval);
                self.q.queue(.{ .ping_interval = &self.ping_sleep });
            }

            self.last_server_ping = try .now();
            self.connection_state = .connected;
            self.state_seq = 0;
        },
        .one_off => |oo| {
            if (oo.task.res[0]) |err| {
                std.log.err("failed to send one off packet: {}", .{err});
            }
            self.pool.allocator().free(oo.task.res[1]);
            self.free_oneoffs.push(oo);
        },
        .retry_handshake => {
            std.debug.assert(self.connection_state == .connecting);
            try self.handshake.schedule(&self.loop, self.stream.sock);
            self.q.queue(.{ .ch = &self.handshake });
        },
        .ping_interval => ping: {
            if (self.connection_state != .connected) break :ping;

            self.send(.unrelyable, .{
                .ping = .{ .tps = self.ping_n },
            }) catch |err| {
                self.ip_error = err;
                self.disconnect();
            };

            self.last_ping = try .now();
            self.ping_sleep.schedule(&self.loop, ping_interval);
            self.q.queue(.{ .ping_interval = &self.ping_sleep });
            self.ping_n += 1;
        },
        .close => {
            self.connection_state = .disconnected;
        },
        .some_sleep => {},
    };
}

pub fn update(self: *Client) void {
    const delta = rl.GetFrameTime();
    const friction = 1;

    var keep: usize = 0;
    for (self.particles.items) |*p| {
        p.age += delta;
        if (p.lifetime <= p.age) continue;

        p.pos += p.vel * vec.splat(delta);
        p.vel *= vec.splat(1 - (friction * delta));

        self.particles.items[keep] = p.*;
        keep += 1;
    }
    self.particles.items.len = keep;

    for (self.conns.items) |conn| {
        const ent = self.sim.ents.get(conn.ent) orelse continue;

        var boost_dir = vec.zero;
        for (vec.dirs, [_]bool{
            conn.input.key_mask.down,
            conn.input.key_mask.right,
            conn.input.key_mask.up,
            conn.input.key_mask.left,
        }) |d, k| {
            if (k) boost_dir -= d;
        }

        const ang = ent.rot;

        if (boost_dir[0] != 0 or boost_dir[1] != 0) for (vec.dirs) |d| {
            const rotated_dir = vec.unit(vec.ang(d) + ang);
            const offset = vec.angBetween(boost_dir, rotated_dir);
            if (offset >= std.math.pi / 2.5) continue;

            const emit_pos = ent.pos + rotated_dir * vec.splat(-ent.stats.radius * 0.8);
            const intensity = 15 * (1 - std.math.pow(f32, offset / (std.math.pi / 2.0), 2));

            for (0..3) |_| {
                const rng = self.prng.random();
                _ = self.particles.appendBounded(Particle{
                    .pos = emit_pos + ent.vel * vec.splat(rl.GetFrameTime()),
                    .vel = vec.unit(rng.float(f32) * std.math.tau) *
                        vec.splat(100) + rotated_dir * -vec.splat(150),
                    .lifetime = 0.1 - rng.float(f32) * 0.04,
                    .radius = intensity,
                    .color = rl.SKYBLUE,
                }) catch {};
            }
        };
    }

    for (self.sim.ents.slots.items) |ent| {
        if (!ent.isAlive()) continue;
        self.stats[ent.stats.id(&self.sim)].cbs.trail(self, ent);
    }
}

pub fn draw(self: *Client) void {
    var tmp = utils.Arena.scrath(null);
    defer tmp.deinit();

    const no_conn = std.math.maxInt(u16);

    const ent_to_conn_table = tmp.arena.alloc(u16, self.sim.ents.slots.items.len);
    @memset(ent_to_conn_table, no_conn);

    for (self.conns.items, 0..) |c, i| {
        if (self.sim.ents.get(c.ent) == null) continue;
        ent_to_conn_table[c.ent.index] = @intCast(i);
    }

    for (self.particles.items) |p| {
        const coff = p.age / p.lifetime;
        rl.DrawCircleV(
            @bitCast(p.pos),
            p.radius * (1 - coff),
            rl.ColorAlpha(p.color, 1 - coff * coff),
        );
    }

    for (self.sim.ents.slots.items, ent_to_conn_table) |ent, _| {
        if (!ent.isAlive()) continue;

        const stats = &self.stats[ent.stats.id(&self.sim)];

        const rot = switch (stats.playable) {
            false => vec.ang(ent.vel),
            true => ent.rot,
        };

        rl.DrawTexturePro(
            self.sheet,
            stats.sprite,
            .{
                .x = ent.pos[0],
                .y = ent.pos[1],
                .width = ent.stats.radius * 2,
                .height = ent.stats.radius * 2,
            },
            .{
                .x = ent.stats.radius,
                .y = ent.stats.radius,
            },
            rot / rl.PI / 2 * 360,
            rl.WHITE,
        );

        if (ent.stats.max_health > 0) {
            const perc = 1 - @as(f32, @floatFromInt(ent.missing_health)) /
                @as(f32, @floatFromInt(ent.stats.max_health));

            const start = rot - rl.PI * perc;
            const end = rot + rl.PI * perc;

            rl.DrawRing(
                @bitCast(ent.pos),
                ent.stats.radius + 10,
                ent.stats.radius + 15,
                start / rl.PI / 2 * 360,
                end / rl.PI / 2 * 360,
                @intFromFloat(100 * perc),
                rl.GREEN,
            );
        }
    }
}

pub fn input(self: *Client, ent: Sim.Ent) void {
    if (self.frame_counter % 3 != 0) return;

    const mouse_pos: vec.T = @bitCast(rl.GetScreenToWorld2D(rl.GetMousePosition(), self.camera));

    self.send(.unrelyable, .{ .player_input = .{
        .seq = self.input_seq,
        .key_mask = .{
            .up = rl.IsKeyDown(rl.KEY_W),
            .down = rl.IsKeyDown(rl.KEY_S),
            .left = rl.IsKeyDown(rl.KEY_A),
            .right = rl.IsKeyDown(rl.KEY_D),
            .shoot = rl.IsMouseButtonDown(rl.MOUSE_BUTTON_LEFT),
        },
        .look_dir = vec.ang(mouse_pos - ent.pos),
    } }) catch {};
    self.input_seq += 1;
}

pub fn init() !Client {
    var self = Client{
        .pool = utils.SclassPool{ .arena = utils.Arena.init(1024 * 1024 * 32) },
        .kp = gam.auth.KeyPair.generate(),
        .loop = try xev.Loop.init(.{}),
        .sim = undefined,
        .map = undefined,
    };

    self.sim = try .init(&self.pool.arena, Sim.max_ents);
    self.sim.ents.dont_modify = true;

    self.map = .init(&self.pool.arena);
    const s = TileMap.stride;
    for (1..s - 1) |y| for (1..s - 1) |x| {
        const coff = 1 - vec.dist(.{ vec.tof(x), vec.tof(y) }, .{ s / 2, s / 2 }) / (s / 2);
        if (self.prng.random().float(f32) < coff) self.map.set(x, y, 0);
    };

    self.chat.messages = self.pool.arena.makeArrayList(u8, 1 << 16);
    self.stream = .init(
        &self.pool.arena,
        std.crypto.random,
        gam.proto.message_queue_size,
    );
    self.reader = .{ .listen_buf = self.pool.arena.alloc(u8, 1 << 16) };
    self.particles = self.pool.arena.makeArrayList(Particle, max_particles);
    self.conns = self.pool.arena.makeArrayList(
        gam.proto.Packet.ConnSync,
        gam.proto.max_conns,
    );

    std.debug.assert(self.sim.stats.len == self.stats.len);

    return self;
}

pub fn shipSelection(self: *Client) void {
    if (self.connection_state != .connected) return;

    const display_size = 100.0;
    const padding = 10.0;
    const hover_scale_up = padding / 2;

    var count: usize = 0;
    for (self.stats) |s| {
        count += @intFromBool(s.playable);
    }

    const choice_count: f32 = @floatFromInt(count);
    const width = display_size * choice_count + (padding * (choice_count - 1));

    const size = vec.T{
        @floatFromInt(rl.GetScreenWidth()),
        @floatFromInt(rl.GetScreenHeight()),
    };

    var cursor = (size - vec.T{ width, display_size }) / vec.splat(2);

    const pressed = rl.IsMouseButtonDown(rl.MOUSE_BUTTON_LEFT);

    for (self.stats, 0..) |s, i| {
        if (!s.playable) continue;

        const hovered = InRect(
            .{
                .x = cursor[0],
                .y = cursor[1],
                .height = display_size,
                .width = display_size,
            },
            rl.GetMousePosition(),
        );

        const scale_up: f32 = if (hovered and !pressed)
            hover_scale_up
        else
            0;

        // TODO: rotate this
        rl.DrawTexturePro(self.sheet, s.sprite, .{
            .x = cursor[0] - scale_up,
            .y = cursor[1] - scale_up,
            .width = display_size + scale_up * 2,
            .height = display_size + scale_up * 2,
        }, .{}, 0, rl.WHITE);

        cursor[0] += display_size + padding;

        if (hovered and pressed) {
            self.send(
                .relyable,
                .{ .spawn = .{ .content_id = i } },
            ) catch |err| {
                std.log.err("server is overloaded: {}", .{err});
            };
        }
    }
}

pub fn main() !void {
    utils.Arena.initScratch(1024 * 1024 * 16);

    var self = try init();

    rl.SetConfigFlags(rl.FLAG_WINDOW_RESIZABLE);
    rl.InitWindow(800, 600, "gam");
    rl.SetTargetFPS(60);
    rl.GuiSetStyle(rl.DEFAULT, rl.TEXT_SIZE, ui.font_size);

    const sheet = @embedFile("sheet_png");
    self.sheet = rl.LoadTextureFromImage(rl.LoadImageFromMemory(".png", sheet.ptr, sheet.len));

    var some_sleep = gam.Sleep{};

    some_sleep.schedule(&self.loop, 100);
    self.q.queue(.{ .some_sleep = &some_sleep });

    while (!rl.WindowShouldClose()) {
        rl.BeginDrawing();
        defer rl.EndDrawing();

        rl.ClearBackground(rl.RAYWHITE);

        const now = try std.time.Instant.now();

        const our_ent = for (self.conns.items) |conn| {
            if (std.mem.eql(u8, &conn.id.bytes, &self.kp.public_key.bytes) and
                self.sim.ents.get(conn.ent) != null)
            {
                break self.sim.ents.get(conn.ent).?;
            }
        } else null;

        if (our_ent) |o| {
            self.camera.target = @bitCast(o.pos);
        }

        rl.BeginMode2D(self.camera);

        if (self.connection_state == .connected) {
            if (now.since(self.last_server_ping) > stale_connection_period) {
                self.connection_menu.ip_error = error.@"server is unresponsive";
                self.disconnect();
            }

            {
                const tl = rl.GetScreenToWorld2D(.{}, self.camera);
                const r = vec.tof(rl.GetScreenWidth());
                const b = vec.tof(rl.GetScreenHeight());

                self.camera.offset = .{ .x = r / 2, .y = b / 2 };

                const size = rl.Vector2Subtract(rl.GetScreenToWorld2D(
                    .{ .x = r, .y = b },
                    self.camera,
                ), tl);

                self.map.draw(.{
                    .x = tl.x,
                    .y = tl.y,
                    .width = size.x,
                    .height = size.y,
                });
            }

            if (our_ent) |e| self.input(e.*);

            self.update();
            self.sim.simulate(.{ .delta = rl.GetFrameTime() });

            for (self.conns.items) |conn| {
                self.sim.handleInput(
                    .{ .delta = rl.GetFrameTime() },
                    conn.ent,
                    conn.input,
                );
            }

            self.draw();
        }

        rl.EndMode2D();

        if (our_ent == null) {
            self.shipSelection();
        }

        self.connection_menu.render();
        self.chat.render();

        for (0..10) |_| {
            try self.loop.run(.no_wait);
            try self.handlePackets();
            try self.handleTasks();
        }

        self.frame_counter += 1;
    }
}
