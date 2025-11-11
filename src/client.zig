const std = @import("std");
const gam = @import("gam");
const xev = @import("xev");
const utils = @import("utils");
const ui = @import("client/ui.zig");
const proto = @import("client/proto.zig");
const PlayerSync = gam.proto.Packet.PlayerSync;
const BulletSync = gam.proto.Packet.BulletSync;

pub const Client = @This();

pub const rl = @cImport({
    @cInclude("raylib.h");
    @cInclude("raymath.h");
    @cInclude("raygui.h");
});

const ping_interval = 300;
const stale_connection_period = 2 * std.time.ns_per_s;
const max_retries = 4;

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
tps: usize = 0,

chat: ui.Chat = .{},
connection_menu: ui.ConnectionMenu = .{},

state_seq: u32 = 0,
input_seq: u32 = 1,
player_states: std.ArrayList(PlayerSync) = undefined,
bullet_states: std.ArrayList(BulletSync) = undefined,

player_sprites: []const rl.Texture2D = undefined,

pub fn startHandshake(self: *Client, ip: std.net.Address) !void {
    self.connection_state = .connecting;
    self.handshake_retry_round = 0;
    self.handshake = proto.ClientHandshake{
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
            }
        },
        .chat_message => |msg| {
            self.chat.addMessage(msg);
        },
        .state => |ps| {
            if (ps.seq > self.state_seq) {
                self.state_seq = ps.seq;

                self.player_states.items.len = ps.players.len;
                @memcpy(self.player_states.items, ps.players);

                self.bullet_states.items.len = ps.bullets.len;
                @memcpy(self.bullet_states.items, ps.bullets);
            }
        },
        .player_input => unreachable,
    }
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

pub fn draw(self: *Client) void {
    for (self.bullet_states.items) |bl| {
        const color: rl.Color = @bitCast(self.player_states.items[bl.owner]
            .id.bytes[0..3].* ++ .{0xff});
        rl.DrawRectanglePro(
            .{
                .x = bl.pos[0],
                .y = bl.pos[1],
                .width = gam.proto.bullet_size,
                .height = gam.proto.bullet_size,
            },
            .{
                .x = gam.proto.bullet_size / 2,
                .y = gam.proto.bullet_size / 2,
            },
            gam.vec.ang(bl.vel) / rl.PI / 2 * 360,
            color,
        );
    }

    for (self.player_states.items) |pl| {
        rl.DrawLineV(@bitCast(pl.pos), @bitCast(pl.mouse_pos), rl.RED);

        for (self.player_sprites, 0..) |tex, i| {
            const color: rl.Color = @bitCast(pl.id.bytes[i * 3 ..][0..3].* ++
                .{0xff});
            rl.DrawTexturePro(
                tex,
                .{
                    .x = 0,
                    .y = 0,
                    .width = @floatFromInt(tex.width),
                    .height = @floatFromInt(tex.height),
                },
                .{
                    .x = pl.pos[0],
                    .y = pl.pos[1],
                    .width = gam.proto.player_size,
                    .height = @as(f32, @floatFromInt(gam.proto.player_size)) /
                        @as(f32, @floatFromInt(tex.width)) *
                        @as(f32, @floatFromInt(tex.height)),
                },
                .{
                    .x = gam.proto.player_size / 2,
                    .y = gam.proto.player_size / 2,
                },
                gam.vec.ang(pl.mouse_pos - pl.pos) / rl.PI / 2 * 360 + 90,
                color,
            );
        }
    }
}

pub fn input(self: *Client) void {
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

pub fn main() !void {
    utils.Arena.initScratch(1024 * 1024 * 16);

    var self = Client{
        .pool = utils.SclassPool{ .arena = utils.Arena.init(1024 * 1024 * 32) },
        .kp = gam.auth.KeyPair.generate(),
        .loop = try xev.Loop.init(.{}),
    };

    self.chat.messages = self.pool.arena.makeArrayList(u8, 1 << 16);
    self.stream = .init(
        &self.pool.arena,
        std.crypto.random,
        gam.proto.message_queue_size,
    );
    self.reader = .{ .listen_buf = self.pool.arena.alloc(u8, 1 << 16) };
    self.player_states = self.pool.arena.makeArrayList(PlayerSync, 32);
    self.bullet_states = self.pool.arena.makeArrayList(BulletSync, 128);

    rl.SetConfigFlags(rl.FLAG_WINDOW_RESIZABLE);
    rl.InitWindow(800, 600, "gam");
    rl.SetTargetFPS(60);
    rl.GuiSetStyle(rl.DEFAULT, rl.TEXT_SIZE, ui.font_size);

    const player_sprites = [_]rl.Texture2D{
        rl.LoadTexture("./assets/player/wings.png"),
        rl.LoadTexture("./assets/player/shield.png"),
        rl.LoadTexture("./assets/player/core.png"),
        rl.LoadTexture("./assets/player/outline.png"),
    };
    self.player_sprites = &player_sprites;

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

            self.draw();
            self.input();
        }

        self.connection_menu.render();
        self.chat.render();

        for (0..10) |_| {
            try self.loop.run(.no_wait);
            try self.handlePackets();
            try self.handleTask();
        }
    }
}
