const std = @import("std");
const gam = @import("gam");
const xev = @import("xev");
const utils = @import("utils");
const PlayerSync = gam.proto.Packet.PlayerSync;
const rl = @cImport({
    @cInclude("raylib.h");
    @cInclude("raymath.h");
    @cInclude("raygui.h");
});

pub fn InRect(r: rl.Rectangle, v: rl.Vector2) bool {
    return r.x <= v.x and v.x <= r.x + r.width and
        r.y <= v.y and v.y <= r.y + r.height;
}

pub fn SliceStr(buf: []u8) [:0]u8 {
    return buf[0..std.mem.indexOfScalar(u8, buf, 0).? :0];
}

pub const ClientHandshake = struct {
    rng: std.Random,
    kp: *const gam.auth.KeyPair,
    server: std.net.Address,
    hello_timeout: gam.Timeout,
    interop: gam.UdpInterop = .{},
    task: gam.Task(Error!gam.auth.Verified) = .{},
    ch: gam.auth.ClientHello = undefined,
    sh: gam.auth.ServerHello = undefined,
    finished: gam.auth.Finished = undefined,

    pub const resolve_refcount = 2;

    pub const Error = xev.WriteError || xev.ReadError ||
        error{ MalformedHello, ServerFull, InvalidHello, Timeout };

    pub fn schedule(
        self: *ClientHandshake,
        loop: *xev.Loop,
        sock: xev.UDP,
    ) !void {
        self.ch = gam.auth.ClientHello.init(self.rng, self.kp.public_key);

        self.interop.send(
            loop,
            sock,
            self.server,
            std.mem.asBytes(&self.ch),
            sentHello,
        );
    }

    fn sentHello(
        ud: *gam.UdpInterop,
        loop: *xev.Loop,
        sock: xev.UDP,
        _: []const u8,
        r: xev.WriteError!usize,
    ) xev.CallbackAction {
        const self: *ClientHandshake = @fieldParentPtr("interop", ud);
        const written = r catch |err| return self.task.ret(err);

        std.debug.assert(written == @sizeOf(gam.auth.ClientHello));
        self.interop.recv(loop, sock, std.mem.asBytes(&self.sh), recvdHello);
        self.hello_timeout.run(loop, &self.interop.comp, recvHelloTimeout);

        return .disarm;
    }

    pub fn recvHelloTimeout(
        ud: *gam.Timeout,
        _: *xev.Loop,
        r: xev.CancelError!void,
    ) xev.CallbackAction {
        _ = r catch {};
        const self: *ClientHandshake = @fieldParentPtr("hello_timeout", ud);
        return self.task.ret(error.Timeout);
    }

    pub fn recvdHello(
        ud: *gam.UdpInterop,
        loop: *xev.Loop,
        sock: xev.UDP,
        addr: std.net.Address,
        r: xev.ReadError!usize,
    ) xev.CallbackAction {
        const self: *ClientHandshake = @fieldParentPtr("interop", ud);

        const read = r catch |err| switch (err) {
            error.Canceled => return self.task.end(),
            else => return self.task.ret(err),
        };

        if (addr.any.family == 0xaaaa) unreachable;

        self.hello_timeout.cancel(loop, helloTimeoutCancel);

        if (read != @sizeOf(gam.auth.ServerHello)) {
            if (std.mem.eql(
                u8,
                std.mem.asBytes(&self.sh)[0..read],
                gam.auth.max_conns_reached,
            )) {
                return self.task.ret(error.ServerFull);
            }

            return self.task.ret(error.MalformedHello);
        }

        const finished, const verified =
            gam.auth.Finished.init(self.rng, self.kp.*, self.ch, self.sh) catch |err| {
                std.log.debug("invalid server hello: {}", .{err});
                return self.task.ret(error.InvalidHello);
            };

        self.task.res = verified;
        self.finished = finished;

        self.interop.send(
            loop,
            sock,
            self.server,
            std.mem.asBytes(&self.finished),
            finish,
        );

        return .disarm;
    }

    fn helloTimeoutCancel(
        ud: *gam.Timeout,
        _: *xev.Loop,
        r: xev.Timer.CancelError!void,
    ) xev.CallbackAction {
        _ = r catch {}; // autofix
        const self: *ClientHandshake = @fieldParentPtr("hello_timeout", ud);
        return self.task.end();
    }

    fn finish(
        ud: *gam.UdpInterop,
        _: *xev.Loop,
        _: xev.UDP,
        _: []const u8,
        r: xev.WriteError!usize,
    ) xev.CallbackAction {
        const self: *ClientHandshake = @fieldParentPtr("interop", ud);

        const written = r catch |err| return self.task.ret(err);
        std.debug.assert(written == @sizeOf(gam.auth.Finished));

        return self.task.end();
    }
};

const ping_interval = 300;
const stale_connection_period = 2 * std.time.ns_per_s;
const max_retries = 4;

pub const Client = struct {
    pool: utils.SclassPool,
    kp: gam.auth.KeyPair,
    loop: xev.Loop,
    q: gam.Queue(union(enum) {
        ch: *ClientHandshake,
        one_off: *gam.OneOffPacket,
        retry_handshake: *gam.Sleep,
        ping_interval: *gam.Sleep,
    }) = .{},

    stream: gam.proto.Stream,

    reader: gam.UdpReader,
    reader_canc: xev.Completion = .{},

    free_oneoffs: gam.List(gam.OneOffPacket) = .{},

    handshake: ClientHandshake = undefined,
    handshake_retry_sleep: gam.Sleep = .{},
    handshake_retry_round: usize = 0,
    server_id: gam.auth.Identity = undefined,

    last_ping: std.time.Instant = undefined,
    last_server_ping: std.time.Instant = undefined,
    ping_sleep: gam.Sleep = .{},
    ping_n: u32 = 0,
    ping: u64 = 0,
    tps: usize = 0,

    chat: Chat = .{},
    connection_menu: ConnectionMenu = .{},

    state_seq: u32 = 0,
    player_states: std.ArrayList(gam.proto.Packet.PlayerSync) = .empty,

    connection_state: enum {
        disconnected,
        connecting,
        connected,
    } = .disconnected,

    ip_error: ?error{
        InvalidAddress,
        InvalidPort,
        ServerUnreachable,
        ServerOverload,
        ServerUnresponsive,
    } = null,

    pub fn startHandshake(self: *Client, ip: std.net.Address) void {
        self.connection_state = .connecting;
        self.handshake_retry_round = 0;
        self.handshake = ClientHandshake{
            .server = ip,
            .rng = self.stream.rng,
            .kp = &self.kp,
            .hello_timeout = .{ .deadline = 500 },
        };
        try self.handshake.schedule(&self.loop, self.stream.sock);
        self.q.queue(.{ .ch = &self.handshake });

        self.stream.rebind() catch unreachable;
        self.chat.messages.items.len = 0;
        self.chat.message_timeouts = @splat(0);
    }

    pub fn disconnect(self: *Client) void {
        self.connection_state = .disconnected;
        self.reader.unschedule(&self.loop, &self.reader_canc);
        self.stream.unschedule(&self.loop);
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
                    .player_states => |ps| {
                        if (ps.seq > self.state_seq) {
                            self.state_seq = ps.seq;
                            self.player_states.items.len = ps.states.len;
                            @memcpy(self.player_states.items, ps.states);
                        }
                    },
                    .player_input => unreachable,
                }

                if (res == .unrelyable) break;
            }

            killed = false;
        }
    }

    pub fn handleTask(self: *Client) !void {
        while (self.q.next()) |task| switch (task) {
            .ch => |ch| {
                std.debug.assert(self.connection_state == .connecting);
                const verified = ch.task.res catch |err| {
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
                        self.ip_error = error.ServerUnreachable;
                    }
                    continue;
                };

                std.log.debug("handshake succrsfull", .{});

                self.stream.schedule(&self.loop, verified.secret, ch.server);
                self.reader.schedule(&self.loop, self.stream.sock);

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
        };
    }
};

pub const layout = opaque {
    const font_size = 20;
    const default_font_size = 10;
    const font_spacing = font_size / default_font_size;

    const screen_padding = 10;

    const server_box_bounds = rl.Rectangle{
        .x = screen_padding,
        .y = screen_padding,
        .width = 150,
        .height = 25,
    };

    const font = rl.GetFontDefault;
};

pub const ConnectionMenu = struct {
    ip_text: [64]u8 = default_ip.* ++ [_]u8{0} ** (64 - default_ip.len),
    ip_text_selected: bool = true,
    spinner_angle: f32 = 0.0,

    const default_ip = "127.0.0.1:8080";

    pub fn render(self: *ConnectionMenu) void {
        const client: *Client = @alignCast(@fieldParentPtr("connection_menu", self));
        const mouse = rl.GetMousePosition();

        if (client.connection_state != .connected) {
            const confirmed = rl.GuiTextBox(
                layout.server_box_bounds,
                &self.ip_text,
                self.ip_text.len - 1,
                client.connection_state == .disconnected and self.ip_text_selected,
            );

            const ip = SliceStr(&self.ip_text);

            if (confirmed != 0) b: {
                if (rl.IsMouseButtonPressed(rl.MOUSE_BUTTON_LEFT)) {
                    self.ip_text_selected = InRect(layout.server_box_bounds, mouse);
                    break :b;
                }

                const server_ip = std.net.Address.parseIpAndPort(ip) catch |err| {
                    client.ip_error = err;
                    break :b;
                };

                client.ip_error = null;

                client.startHandshake(server_ip);
            }
        } else {
            if (rl.GuiButton(layout.server_box_bounds, "disconnect") != 0 or
                (rl.IsKeyPressed(rl.KEY_K) and !client.chat.enabled))
            {
                client.disconnect();
            }

            {
                var tmp = utils.Arena.scrath(null);
                defer tmp.deinit();

                const x: c_int = @intFromFloat(layout.server_box_bounds.x +
                    layout.server_box_bounds.width + 5);
                var cursor: c_int = @intFromFloat(layout.server_box_bounds.y);

                rl.DrawText(
                    (std.fmt.allocPrintSentinel(
                        tmp.arena.allocator(),
                        "ping: {d:.2}ms",
                        .{@as(f32, @floatFromInt(client.ping)) / std.time.ns_per_ms},
                        0,
                    ) catch unreachable).ptr,
                    x,
                    cursor,
                    layout.font_size,
                    rl.GREEN,
                );

                cursor += layout.font_size;
                rl.DrawText(
                    (std.fmt.allocPrintSentinel(
                        tmp.arena.allocator(),
                        "tps: {d}",
                        .{client.tps},
                        0,
                    ) catch unreachable).ptr,
                    x,
                    cursor,
                    layout.font_size,
                    rl.GREEN,
                );
            }
        }

        if (client.ip_error) |err| {
            const message = switch (err) {
                error.InvalidAddress => "invalid address",
                error.InvalidPort => "invalid port",
                error.ServerUnreachable => "server unreachable",
                error.ServerOverload => "server is overloaded",
                error.ServerUnresponsive => "server ignored us",
            };

            rl.DrawText(
                message.ptr,
                @intFromFloat(layout.server_box_bounds.x),
                @intFromFloat(layout.server_box_bounds.y +
                    layout.server_box_bounds.height + 5),
                layout.font_size,
                rl.RED,
            );
        }

        if (client.connection_state == .connecting) {
            self.spinner_angle += rl.PI * rl.GetFrameTime();

            const radius = 10;
            const pos = rl.Vector2{
                .x = layout.server_box_bounds.x + layout.server_box_bounds.width +
                    radius + 5,
                .y = layout.screen_padding + layout.server_box_bounds.height / 2,
            };

            var left = rl.Vector2{
                .x = @cos(self.spinner_angle),
                .y = @sin(self.spinner_angle),
            };
            var right = rl.Vector2Negate(left);

            left = rl.Vector2Scale(left, radius);
            right = rl.Vector2Scale(right, radius);
            left = rl.Vector2Add(left, pos);
            right = rl.Vector2Add(right, pos);

            const color = rl.GetColor(@bitCast(rl.GuiGetStyle(rl.TEXTBOX, rl.BASE_COLOR_NORMAL)));
            rl.DrawLineEx(left, right, 4, color);
        }
    }
};

pub const Chat = struct {
    prompt_text: [1024]u8 = @splat(0),
    enabled: bool = false,
    messages: std.ArrayList(u8) = undefined,
    message_timeouts: [32]f32 = @splat(0),
    scroll_pos: usize = 0,

    pub fn addMessage(self: *Chat, msg: gam.proto.Packet.ChatMessage) void {
        const min_cut_off = (msg.content.len + 1) -|
            (self.messages.capacity -
                self.messages.items.len);

        const cut_off = std.mem.indexOfScalarPos(
            u8,
            self.messages.items,
            min_cut_off,
            '\n',
        ) orelse self.messages.items.len;

        @memmove(
            self.messages.items.ptr,
            self.messages.items[cut_off..],
        );
        self.messages.items.len -= cut_off;

        self.messages.appendAssumeCapacity('\n');
        self.messages.appendSliceAssumeCapacity(msg.content);

        std.mem.rotate(
            f32,
            &self.message_timeouts,
            self.message_timeouts.len - 1,
        );

        const chat_message_timeout = 15.0;
        self.message_timeouts[0] = chat_message_timeout;
    }

    pub fn render(self: *Chat) void {
        const client: *Client = @fieldParentPtr("chat", self);

        if (client.connection_state != .connected) {
            return;
        }

        var chat_prompt_rect = rl.Rectangle{
            .x = 0,
            .y = @floatFromInt(rl.GetScreenHeight()),
            .width = @floatFromInt(rl.GetScreenWidth()),
            .height = 25,
        };
        chat_prompt_rect.y -= chat_prompt_rect.height;

        var sent = false;

        if (self.enabled) {
            const confirmed = rl.GuiTextBox(
                chat_prompt_rect,
                &self.prompt_text,
                self.prompt_text.len - 1,
                true,
            );

            const message = SliceStr(&self.prompt_text);

            if (confirmed != 0 and message.len != 0) {
                client.send(.relyable, .{ .chat_message = .{
                    .id = client.kp.public_key,
                    .content = message,
                } }) catch |err| {
                    std.log.err("failed to send the chat message: {}", .{err});
                };

                sent = true;
                @memset(&self.prompt_text, 0);
                self.scroll_pos = 0;
            }
        }

        const scroll = rl.GetMouseWheelMove();
        if (self.enabled and scroll != 0) {
            self.scroll_pos = self.messages.items.len - self.scroll_pos;
            if (scroll == -1) {
                self.scroll_pos = if (std.mem.indexOfScalarPos(
                    u8,
                    self.messages.items,
                    self.scroll_pos,
                    '\n',
                )) |i| i + 1 else self.messages.items.len;
            } else {
                std.debug.assert(scroll == 1);
                self.scroll_pos = if (std.mem.lastIndexOfScalar(
                    u8,
                    self.messages.items[0..self.scroll_pos -| 1],
                    '\n',
                )) |i| i + 1 else 0;
            }
            self.scroll_pos = self.messages.items.len - self.scroll_pos;
        }

        for (&self.message_timeouts) |*flt| {
            if (flt.* < 0) break;
            flt.* -= rl.GetFrameTime();
        }

        var iter = std.mem.splitBackwardsScalar(
            u8,
            self.messages.items[0 .. self.messages.items.len - self.scroll_pos],
            '\n',
        );

        var cursor = chat_prompt_rect.y;
        const until = layout.server_box_bounds.y + layout.server_box_bounds.height +
            layout.screen_padding;
        var i: usize = 0;
        while (iter.next()) |message| : (i += 1) {
            if (message.len == 0) continue;

            const opacity = if (self.enabled)
                1.0
            else if (i < self.message_timeouts.len)
                @min(1.0, self.message_timeouts[i])
            else
                0.0;

            if (opacity <= 0) break;

            if (cursor < until) break;

            var tmp = utils.Arena.scrath(null);
            defer tmp.deinit();

            const msg = tmp.arena.dupeZ(u8, message);

            const message_padding = 2;
            const size = rl.MeasureTextEx(
                layout.font(),
                msg.ptr,
                layout.font_size,
                layout.font_spacing,
            );
            cursor -= size.y + message_padding * 2;

            const pos = rl.Vector2{
                .x = message_padding,
                .y = cursor + message_padding,
            };

            rl.DrawRectangleRec(
                .{
                    .x = pos.x - message_padding,
                    .y = pos.y - message_padding,
                    .width = size.x + message_padding * 2,
                    .height = size.y + message_padding * 2,
                },
                rl.ColorAlpha(rl.BLACK, opacity * 0.5),
            );

            rl.DrawTextEx(
                layout.font(),
                msg.ptr,
                pos,
                layout.font_size,
                layout.font_spacing,
                rl.ColorAlpha(rl.WHITE, opacity),
            );
        }

        if (rl.IsKeyPressed(rl.KEY_ENTER) and !sent) self.enabled = !self.enabled;
    }
};

pub fn main() !void {
    utils.Arena.initScratch(1024 * 1024 * 16);

    var self = Client{
        .pool = utils.SclassPool{ .arena = utils.Arena.init(1024 * 1024 * 32) },
        .kp = gam.auth.KeyPair.generate(),
        .loop = try xev.Loop.init(.{}),
        .stream = undefined,
        .reader = undefined,
    };

    const addr = try std.net.Address.parseIp4("0.0.0.0", 0);
    const sock = try xev.UDP.init(addr);
    try sock.bind(addr);

    self.chat.messages = self.pool.arena.makeArrayList(u8, 1 << 16);
    self.stream = .init(
        &self.pool.arena,
        sock,
        std.crypto.random,
        gam.proto.message_queue_size,
    );
    self.reader = .{ .listen_buf = self.pool.arena.alloc(u8, 1 << 16) };
    self.player_states = self.pool.arena.makeArrayList(PlayerSync, 32);

    rl.SetConfigFlags(rl.FLAG_WINDOW_RESIZABLE);
    rl.InitWindow(800, 600, "gam");
    rl.SetTargetFPS(60);
    rl.GuiSetStyle(rl.DEFAULT, rl.TEXT_SIZE, layout.font_size);

    var input_seq: u32 = 1;

    while (!rl.WindowShouldClose()) {
        rl.BeginDrawing();
        defer rl.EndDrawing();

        rl.ClearBackground(rl.RAYWHITE);

        const now = try std.time.Instant.now();

        if (self.connection_state == .connected) {
            if (now.since(self.last_server_ping) > stale_connection_period) {
                self.ip_error = error.ServerUnresponsive;
                self.disconnect();
            }

            const player_size = 32;

            for (self.player_states.items) |pl| {
                rl.DrawRectangleRec(.{
                    .x = pl.state.pos[0] - player_size / 2,
                    .y = pl.state.pos[1] - player_size / 2,
                    .width = player_size,
                    .height = player_size,
                }, @bitCast(pl.id.bytes[0..3].* ++ .{0xff}));
            }

            self.send(.unrelyable, .{ .player_input = .{
                .seq = input_seq,
                .key_mask = .{
                    .up = rl.IsKeyDown(rl.KEY_W),
                    .down = rl.IsKeyDown(rl.KEY_S),
                    .left = rl.IsKeyDown(rl.KEY_A),
                    .right = rl.IsKeyDown(rl.KEY_D),
                },
            } }) catch {};
            input_seq += 1;
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
