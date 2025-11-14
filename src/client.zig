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

const sheet_rects = @import("sheet_zig");

pub const Particle = struct {
    pos: vec.T,
    vel: vec.T,
    lifetime: f32,
};

const ping_interval = 300;
const stale_connection_period = 2 * std.time.ns_per_s;
const max_retries = 4;

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

    self.stream.sock = sock; // HACK: we read this from ther on retry

    try self.handshake.schedule(&self.loop, sock);
    self.q.queue(.{ .ch = &self.handshake });

    self.chat.messages.items.len = 0;
    self.chat.message_timeouts = @splat(0);
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

                const ents = self.sim.ents.slots.items;

                for (ents, s.ents[0..ents.len]) |a, b| {
                    if (a.isAlive() and !b.isAlive()) {
                        for (0..10) |_| {
                            const rng = self.prng.random();
                            self.particles.appendBounded(.{
                                .pos = a.pos,
                                .vel = vec.unit(rng.float(f32) * 2 * rl.PI) *
                                    vec.splat(rng.float(f32) * 100 + 10),
                                .lifetime = 0.3 + rng.float(f32) * 0.2,
                            }) catch {};
                        }
                    }
                }

                self.conns.items.len = s.conns.len;
                @memcpy(self.conns.items, s.conns);

                self.sim.ents.slots.items.len = s.ents.len;
                @memcpy(self.sim.ents.slots.items, s.ents);
            }
        },
        .player_input => unreachable,
    }
}

pub fn rtt(self: *Client) f64 {
    return @as(f64, @floatFromInt(self.average_ping_sum)) /
        @as(f64, @floatFromInt(self.average_ping_sum)) / 2000.0;
}

pub fn handleTask(self: *Client) !void {
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
    };
}

pub fn update(self: *Client) void {
    const delta = rl.GetFrameTime();
    const friction = 1;

    var keep: usize = 0;
    for (self.particles.items) |*p| {
        p.lifetime -= delta;
        if (p.lifetime <= 0) continue;

        p.pos += p.vel * vec.splat(delta);
        p.vel *= vec.splat(1 - (friction * delta));

        self.particles.items[keep] = p.*;
        keep += 1;
    }
    self.particles.items.len = keep;
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

    for (self.sim.ents.slots.items, ent_to_conn_table) |ent, _| {
        if (!ent.isAlive()) continue;

        const rot = switch (ent.kind) {
            .bullet => vec.ang(ent.vel),
            .player => ent.rot,
        };

        const region = switch (ent.kind) {
            .bullet => sheet_rects.bullet,
            .player => sheet_rects.player,
        };

        rl.DrawTexturePro(
            self.sheet,
            region,
            .{
                .x = ent.pos[0],
                .y = ent.pos[1],
                .width = ent.radius * 2,
                .height = ent.radius * 2,
            },
            .{
                .x = ent.radius,
                .y = ent.radius,
            },
            rot / rl.PI / 2 * 360,
            rl.WHITE,
        );
    }

    for (self.particles.items) |p| {
        rl.DrawRectangleRec(.{
            .x = p.pos[0],
            .y = p.pos[1],
            .width = 15,
            .height = 15,
        }, rl.RED);
    }
}

pub fn input(self: *Client) void {
    if (self.frame_counter % 3 != 0) return;

    self.send(.unrelyable, .{ .player_input = .{
        .seq = self.input_seq,
        .key_mask = .{
            .up = rl.IsKeyDown(rl.KEY_W),
            .down = rl.IsKeyDown(rl.KEY_S),
            .left = rl.IsKeyDown(rl.KEY_A),
            .right = rl.IsKeyDown(rl.KEY_D),
            .shoot = rl.IsMouseButtonDown(rl.MOUSE_BUTTON_LEFT),
        },
        .mouse_pos = @bitCast(rl.GetMousePosition()),
    } }) catch {};
    self.input_seq += 1;
}

pub fn init() !Client {
    var self = Client{
        .pool = utils.SclassPool{ .arena = utils.Arena.init(1024 * 1024 * 32) },
        .kp = gam.auth.KeyPair.generate(),
        .loop = try xev.Loop.init(.{}),
        .sim = undefined,
    };

    self.sim = try .init(&self.pool.arena, Sim.max_ents);
    self.sim.ents.dont_modify = true;

    self.chat.messages = self.pool.arena.makeArrayList(u8, 1 << 16);
    self.stream = .init(
        &self.pool.arena,
        std.crypto.random,
        gam.proto.message_queue_size,
    );
    self.reader = .{ .listen_buf = self.pool.arena.alloc(u8, 1 << 16) };
    self.particles = self.pool.arena.makeArrayList(Particle, 256);
    self.conns = self.pool.arena.makeArrayList(gam.proto.Packet.ConnSync, 32);

    return self;
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

    while (!rl.WindowShouldClose()) {
        rl.BeginDrawing();
        defer rl.EndDrawing();

        rl.ClearBackground(rl.RAYWHITE);

        const now = try std.time.Instant.now();

        if (self.connection_state == .connected) {
            if (now.since(self.last_server_ping) > stale_connection_period) {
                self.connection_menu.ip_error = error.@"server is unresponsive";
                self.disconnect();
            }

            self.input();

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

        self.connection_menu.render();
        self.chat.render();

        for (0..10) |_| {
            try self.loop.run(.no_wait);
            try self.handlePackets();
            try self.handleTask();
        }

        self.frame_counter += 1;
    }
}

pub fn smoothAngle(current: f32, target: f32, dt: f32, speed: f32) f32 {
    const tau = 2.0 * std.math.pi;

    const a = @mod(current, tau);
    const b = @mod(target, tau);

    const diff = @mod(b - a + std.math.pi, tau) - std.math.pi;
    const factor = 1.0 - std.math.exp(-speed * dt);
    const new_angle = a + diff * factor;

    return @mod(new_angle, tau);
}
