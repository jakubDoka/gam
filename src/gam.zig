const std = @import("std");

const utils = @import("utils");
const xev = @import("xev");

pub const proto = @import("gam/proto.zig");
pub const auth = @import("gam/auth.zig");
pub const vec = @import("gam/vec.zig");
pub const sim = @import("gam/sim.zig");

pub const Addr = extern struct {
    bytes: [16]u8,
    port: u16,

    pub fn fromStd(self: std.net.Address) ?Addr {
        switch (self.any.family) {
            std.posix.AF.INET => {
                return .{
                    .bytes = std.mem.toBytes(self.in.sa.addr) ++ [_]u8{0} ** 12,
                    .port = self.in.getPort(),
                };
            },
            std.posix.AF.INET6 => {
                return .{
                    .bytes = self.in6.sa.addr,
                    .port = self.in6.getPort(),
                };
            },
            else => return null,
        }
    }

    pub fn toStd(self: Addr) std.net.Address {
        if (std.mem.allEqual(u8, self.bytes[4..], 0)) {
            return .initIp4(self.bytes[0..4].*, self.port);
        } else {
            return .initIp6(self.bytes, self.port, 0, 0);
        }
    }
};

pub const OneOffPacket = struct {
    interop: UdpInterop = .{},
    task: Task(struct { ?xev.WriteError, []const u8 }) = .{},

    pub fn schedule(self: *@This(), lop: *xev.Loop, sck: xev.UDP, to: std.net.Address, message: []const u8) void {
        self.interop.send(lop, sck, to, message, endDriver);
    }

    pub fn endDriver(
        ud: *UdpInterop,
        _: *xev.Loop,
        _: xev.UDP,
        b: []const u8,
        r: xev.WriteError!usize,
    ) xev.CallbackAction {
        const self: *@This() = @fieldParentPtr("interop", ud);
        _ = r catch |err| return self.task.ret(.{ err, b });
        return self.task.ret(.{ null, b });
    }
};

pub const UdpReader = struct {
    listen_completion: xev.Completion = .{},
    listen_state: xev.UDP.State = undefined,
    listen_buf: []u8,
    listen_red: usize = undefined,
    cleared: bool = undefined,
    schedule_lock: std.debug.SafetyLock = .{},
    cancel_task: Task(void) = .{},

    pub fn schedule(self: *UdpReader, loop: *xev.Loop, sock: xev.UDP) void {
        self.schedule_lock.lock();
        self.listen_red = @sizeOf(PacketHeader);
        self.cleared = false;
        sock.read(
            loop,
            &self.listen_completion,
            &self.listen_state,
            .{ .slice = self.listen_buf[self.listen_red..] },
            UdpReader,
            self,
            listenDriver,
        );
    }

    pub fn unschedule(self: *UdpReader, loop: *xev.Loop, comp: *xev.Completion) void {
        comp.* = .{
            .op = .{ .cancel = .{
                .c = &self.listen_completion,
            } },
            .userdata = self,
            .callback = cancelDriver,
        };
        loop.add(comp);
    }

    pub fn cancelDriver(
        ud: ?*anyopaque,
        _: *xev.Loop,
        _: *xev.Completion,
        _: xev.Result,
    ) xev.CallbackAction {
        const self: *UdpReader = @ptrCast(@alignCast(ud.?));
        self.schedule_lock.unlock();
        return .disarm;
    }

    pub fn packets(self: *UdpReader) PacketIter {
        defer self.cleared = true;
        return .{
            .server = self,
            .remining = if (self.cleared)
                self.listen_buf[0..@sizeOf(PacketHeader)]
            else
                self.listen_buf[0..self.listen_red],
        };
    }

    pub const PacketHeader = extern struct {
        addr: Addr,
        len: u16,

        pub fn format(
            self: @This(),
            writer: *std.Io.Writer,
        ) std.Io.Writer.Error!void {
            try writer.print("{f}[{d}]", .{ self.addr.toStd(), self.len });
        }
    };

    pub const Packet = struct {
        from: Addr,
        body: []u8,

        pub fn format(
            self: @This(),
            writer: *std.Io.Writer,
        ) std.Io.Writer.Error!void {
            try writer.print("{f}[{x}]", .{ self.from.toStd(), self.body });
        }
    };

    pub const PacketIter = struct {
        server: *UdpReader,
        remining: []u8,

        pub fn next(self: *PacketIter) ?Packet {
            const ph_size = @sizeOf(PacketHeader);

            if (self.remining.len == ph_size) return null;

            const head: PacketHeader = @bitCast(self.remining[0..ph_size].*);
            defer self.remining = self.remining[ph_size + head.len ..];
            return .{
                .from = head.addr,
                .body = self.remining[ph_size..][0..head.len],
            };
        }
    };

    pub fn listenDriver(
        ud: ?*UdpReader,
        loop: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        adr: std.net.Address,
        sock: xev.UDP,
        rbuff: xev.ReadBuffer,
        r: xev.ReadError!usize,
    ) xev.CallbackAction {
        const self = ud.?;

        const len_wide = r catch |err| {
            if (err == error.Canceled) return .disarm;
            std.log.err("error listening: {}", .{err});
            return .disarm;
        };

        if (!std.debug.runtime_safety or true or std.crypto.random.float(f32) < 0.85) {
            const header = PacketHeader{
                .addr = Addr.fromStd(adr) orelse {
                    // Whatever this is we dont care
                    return .rearm;
                },
                .len = @intCast(len_wide),
            };

            const ph_size = @sizeOf(PacketHeader);

            std.debug.assert(rbuff.slice.ptr == self.listen_buf[self.listen_red..].ptr);

            if (self.cleared) {
                @memmove(
                    self.listen_buf[ph_size..][0..header.len],
                    self.listen_buf[self.listen_red..][0..header.len],
                );

                self.listen_red = ph_size;
                self.cleared = false;
            }

            self.listen_buf[self.listen_red - ph_size ..][0..ph_size].* =
                std.mem.toBytes(header);
            self.listen_red += header.len + ph_size;

            if (self.listen_red >= self.listen_buf.len) {
                @panic("OOM: the packet buffer overflowed," ++
                    " this should not happen in practice");
            }
        }

        sock.read(
            loop,
            &self.listen_completion,
            &self.listen_state,
            .{ .slice = self.listen_buf[self.listen_red..] },
            UdpReader,
            self,
            listenDriver,
        );

        return .disarm;
    }
};

pub const UdpInterop = struct {
    comp: xev.Completion = .{},
    state: xev.UDP.State = undefined,

    pub fn recv(
        self: *UdpInterop,
        loop: *xev.Loop,
        trough: xev.UDP,
        buffer: []u8,
        comptime cb: *const fn (
            ud: *UdpInterop,
            l: *xev.Loop,
            s: xev.UDP,
            adr: std.net.Address,
            r: xev.ReadError!usize,
        ) xev.CallbackAction,
    ) void {
        trough.read(
            loop,
            &self.comp,
            &self.state,
            .{ .slice = buffer },
            UdpInterop,
            self,
            struct {
                fn cbm(
                    ud: ?*UdpInterop,
                    l: *xev.Loop,
                    _: *xev.Completion,
                    _: *xev.UDP.State,
                    adr: std.net.Address,
                    s: xev.UDP,
                    _: xev.ReadBuffer,
                    r: xev.ReadError!usize,
                ) xev.CallbackAction {
                    return @call(.always_inline, cb, .{ ud.?, l, s, adr, r });
                }
            }.cbm,
        );
    }

    pub fn send(
        self: *UdpInterop,
        loop: *xev.Loop,
        trough: xev.UDP,
        to: std.net.Address,
        message: []const u8,
        comptime cb: ?*const fn (
            ud: *UdpInterop,
            l: *xev.Loop,
            s: xev.UDP,
            buf: []const u8,
            r: xev.WriteError!usize,
        ) xev.CallbackAction,
    ) void {
        trough.write(
            loop,
            &self.comp,
            &self.state,
            to,
            .{ .slice = message },
            UdpInterop,
            self,
            struct {
                fn cbm(
                    ud: ?*UdpInterop,
                    l: *xev.Loop,
                    _: *xev.Completion,
                    _: *xev.UDP.State,
                    s: xev.UDP,
                    b: xev.WriteBuffer,
                    r: xev.WriteError!usize,
                ) xev.CallbackAction {
                    return @call(.always_inline, cb orelse return .disarm, .{
                        ud.?,
                        l,
                        s,
                        b.slice,
                        r,
                    });
                }
            }.cbm,
        );
    }
};

pub fn Queue(comptime T: type) type {
    return struct {
        inner: AnyQueue = .{},
        pending: usize = 0,

        const Self = @This();

        pub fn queue(self: *Self, task: T) void {
            self.pending += 1;
            switch (task) {
                inline else => |v, t| {
                    const res = &@field(v, "task");
                    res.base.queued_lock.lock();
                    res.base.id = @intFromEnum(t);
                    res.base.q = .{ .unqueued = &self.inner };
                    res.base.ref_count = if (@hasDecl(@TypeOf(v.*), "resolve_refcount"))
                        @TypeOf(v.*).resolve_refcount
                    else
                        1;
                },
            }
        }

        pub fn isEmpty(self: Self) bool {
            return self.pending == 0;
        }

        pub fn next(self: *Self) ?T {
            const finished = self.inner.ready orelse return null;
            finished.queued_lock.unlock();
            finished.ref_count = AnyTask.suspended_ref;
            self.inner.ready = finished.q.queued;
            self.pending -= 1;

            const tag: std.meta.Tag(T) = @enumFromInt(finished.id);
            switch (tag) {
                inline else => |t| {
                    const Payload = std.meta.TagPayload(T, t);
                    const ResTy = std.meta.fieldInfo(std.meta.Child(Payload), .task)
                        .type;
                    const ptr: Payload = @fieldParentPtr(
                        "task",
                        @as(*ResTy, @ptrCast(finished)),
                    );

                    return @unionInit(T, @tagName(t), ptr);
                },
            }
        }
    };
}

pub const AnyQueue = struct {
    ready: ?*AnyTask = null,
};

pub const AnyTask = struct {
    q: union { unqueued: *AnyQueue, queued: ?*AnyTask } = undefined,
    id: u32 = undefined,
    ref_count: u32 = suspended_ref,
    queued_lock: std.debug.SafetyLock = .{},

    const suspended_ref = std.math.maxInt(u32);

    pub fn wake(self: *AnyTask) void {
        self.ref_count -= 1;
        if (self.ref_count > 0) return;

        self.queued_lock.assertLocked();
        const q = self.q.unqueued;
        self.q = .{ .queued = q.ready };
        q.ready = self;
    }
};

pub fn Task(comptime T: type) type {
    return struct {
        pub const Res = T;

        base: AnyTask = .{},
        res: Res = undefined,

        pub fn inProgress(self: @This()) bool {
            return self.base.ref_count != AnyTask.suspended_ref;
        }

        pub fn end(self: *@This()) xev.CallbackAction {
            self.base.wake();
            return .disarm;
        }

        pub fn ret(self: *@This(), val: Res) xev.CallbackAction {
            self.res = val;
            return self.end();
        }
    };
}

pub const Timeout = struct {
    deadline: u64,
    comp: xev.Completion = .{},
    cancel_comp: xev.Completion = .{},
    timer: xev.Timer = undefined,
    to_cancel: ?*xev.Completion = undefined,

    pub fn cancel(
        self: *Timeout,
        loop: *xev.Loop,
        comptime cb: ?*const fn (
            *Timeout,
            *xev.Loop,
            xev.Timer.CancelError!void,
        ) xev.CallbackAction,
    ) void {
        self.timer.cancel(
            loop,
            &self.comp,
            &self.cancel_comp,
            Timeout,
            self,
            struct {
                pub fn cancelDriver(
                    ud: ?*Timeout,
                    l: *xev.Loop,
                    _: *xev.Completion,
                    r: xev.Timer.CancelError!void,
                ) xev.CallbackAction {
                    return @call(
                        .always_inline,
                        cb orelse return .disarm,
                        .{ ud.?, l, r },
                    );
                }
            }.cancelDriver,
        );
    }

    pub fn run(
        self: *Timeout,
        loop: *xev.Loop,
        to_cancel: ?*xev.Completion,
        comptime cb: *const fn (
            *Timeout,
            *xev.Loop,
            xev.CancelError!void,
        ) xev.CallbackAction,
    ) void {
        if (self.cancel_comp.state() != .dead) {
            return;
        }

        self.timer = try .init();
        self.to_cancel = to_cancel;
        self.timer.reset(
            loop,
            &self.comp,
            &self.cancel_comp,
            self.deadline,
            Timeout,
            self,
            struct {
                pub fn cbm(
                    d: ?*anyopaque,
                    l: *xev.Loop,
                    _: *xev.Completion,
                    r: xev.Result,
                ) xev.CallbackAction {
                    return @call(.always_inline, cb, .{
                        @as(*Timeout, @ptrCast(@alignCast(d.?))),
                        l,
                        r.cancel,
                    });
                }

                pub fn cancelDriver(
                    ud: ?*Timeout,
                    loo: *xev.Loop,
                    c: *xev.Completion,
                    rs: xev.Timer.RunError!void,
                ) xev.CallbackAction {
                    rs catch |err| if (err == error.Canceled) {
                        return .disarm;
                    };

                    const slf = ud.?;

                    slf.timer.deinit();

                    if (slf.to_cancel) |cc| {
                        slf.comp = .{
                            .op = .{ .cancel = .{
                                .c = cc,
                            } },
                            .callback = cbm,
                            .userdata = slf,
                        };
                    } else {
                        return cbm(ud, loo, c, .{ .cancel = {} });
                    }

                    loo.add(&slf.comp);

                    return .disarm;
                }
            }.cancelDriver,
        );
    }
};

pub const Sleep = struct {
    comp: xev.Completion = .{},
    timer: xev.Timer = undefined,
    task: Task(xev.Timer.RunError!void) = .{},

    pub fn schedule(self: *Sleep, loop: *xev.Loop, next_ms: u64) void {
        self.timer = try .init();
        self.timer.run(loop, &self.comp, next_ms, Sleep, self, sleepDriver);
    }

    pub fn sleepDriver(
        ud: ?*Sleep,
        _: *xev.Loop,
        _: *xev.Completion,
        res: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        return ud.?.task.ret(res);
    }
};

pub fn List(comptime T: type) type {
    return struct {
        root: ?*Node = null,

        pub const Node = struct {
            next: ?*Node,
        };

        const Self = @This();

        pub fn push(self: *Self, val: *T) void {
            comptime std.debug.assert(@sizeOf(T) >= 8 and @alignOf(T) >= 8);
            const node: *Node = @ptrCast(val);
            node.next = self.root;
            self.root = node;
        }

        pub fn pop(self: *Self) ?*T {
            const vl = self.root orelse return null;
            self.root = vl.next;
            return @ptrCast(@alignCast(vl));
        }
    };
}

test {
    std.testing.refAllDeclsRecursive(@This());
}
