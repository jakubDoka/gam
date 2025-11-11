const std = @import("std");
const gam = @import("gam");
const utils = @import("utils");
const root = @import("../client.zig");
const rl = root.rl;
const Client = root.Client;
const SliceStr = root.SliceStr;
const InRect = root.InRect;

pub const font_size = 20;
pub const default_font_size = 10;
pub const font_spacing = font_size / default_font_size;

pub const screen_padding = 10;

pub const server_box_bounds = rl.Rectangle{
    .x = screen_padding,
    .y = screen_padding,
    .width = 150,
    .height = 25,
};

pub const font = rl.GetFontDefault;

pub const ConnectionMenu = struct {
    ip_text: [64]u8 = default_ip.* ++ [_]u8{0} ** (64 - default_ip.len),
    ip_text_selected: bool = true,
    spinner_angle: f32 = 0.0,
    ip_error: ?error{
        @"invalid address",
        @"invalid port",
        @"server unreachable",
        @"server is overloaded",
        @"server is unresponsive",
        @"cant open the socket",
        @"cant bind the socket",
    } = null,

    const default_ip = "127.0.0.1:8080";

    pub fn render(self: *ConnectionMenu) void {
        const client: *Client = @alignCast(@fieldParentPtr("connection_menu", self));
        const mouse = rl.GetMousePosition();

        if (client.connection_state != .connected) {
            const confirmed = rl.GuiTextBox(
                server_box_bounds,
                &self.ip_text,
                self.ip_text.len - 1,
                client.connection_state == .disconnected and self.ip_text_selected,
            );

            const ip = SliceStr(&self.ip_text);

            if (confirmed != 0) b: {
                if (rl.IsMouseButtonPressed(rl.MOUSE_BUTTON_LEFT)) {
                    self.ip_text_selected = InRect(server_box_bounds, mouse);
                    break :b;
                }

                const server_ip = std.net.Address.parseIpAndPort(ip) catch |err| {
                    self.ip_error = switch (err) {
                        error.InvalidAddress => error.@"invalid address",
                        error.InvalidPort => error.@"invalid port",
                    };
                    break :b;
                };

                self.ip_error = null;

                client.startHandshake(server_ip) catch |err| {
                    self.ip_error = err;
                };
            }
        } else {
            if (rl.GuiButton(server_box_bounds, "disconnect") != 0 or
                (rl.IsKeyPressed(rl.KEY_K) and !client.chat.enabled))
            {
                client.disconnect();
            }

            {
                var tmp = utils.Arena.scrath(null);
                defer tmp.deinit();

                const x: c_int = @intFromFloat(server_box_bounds.x +
                    server_box_bounds.width + 5);
                var cursor: c_int = @intFromFloat(server_box_bounds.y);

                rl.DrawText(
                    (std.fmt.allocPrintSentinel(
                        tmp.arena.allocator(),
                        "ping: {d:.2}ms",
                        .{@as(f32, @floatFromInt(client.ping)) / std.time.ns_per_ms},
                        0,
                    ) catch unreachable).ptr,
                    x,
                    cursor,
                    font_size,
                    rl.GREEN,
                );

                cursor += font_size;
                rl.DrawText(
                    (std.fmt.allocPrintSentinel(
                        tmp.arena.allocator(),
                        "tps: {d}",
                        .{client.tps},
                        0,
                    ) catch unreachable).ptr,
                    x,
                    cursor,
                    font_size,
                    rl.GREEN,
                );
            }
        }

        if (self.ip_error) |err| {
            const message = @errorName(err);

            rl.DrawText(
                message.ptr,
                @intFromFloat(server_box_bounds.x),
                @intFromFloat(server_box_bounds.y +
                    server_box_bounds.height + 5),
                font_size,
                rl.RED,
            );
        }

        if (client.connection_state == .connecting or
            client.connection_state == .disconnecting)
        {
            self.spinner_angle += rl.PI * rl.GetFrameTime();

            const radius = 10;
            const pos = rl.Vector2{
                .x = server_box_bounds.x + server_box_bounds.width +
                    radius + 5,
                .y = screen_padding + server_box_bounds.height / 2,
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
        const until = server_box_bounds.y + server_box_bounds.height +
            screen_padding;
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
                font(),
                msg.ptr,
                font_size,
                font_spacing,
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
                font(),
                msg.ptr,
                pos,
                font_size,
                font_spacing,
                rl.ColorAlpha(rl.WHITE, opacity),
            );
        }

        if (rl.IsKeyPressed(rl.KEY_ENTER) and !sent) self.enabled = !self.enabled;
    }
};
