const std = @import("std");
const gam = @import("gam");
const xev = @import("xev");

pub const ClientHandshake = struct {
    rng: std.Random,
    kp: *const gam.auth.KeyPair,
    server: std.net.Address,
    hello_timeout: gam.Timeout,
    interop: gam.UdpInterop = .{},
    task: gam.Task(Error!struct { gam.auth.Verified, xev.UDP }) = .{},
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

        self.task.res = .{ verified, sock };
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
