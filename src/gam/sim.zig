const std = @import("std");
const utils = @import("utils");

const gam = @import("../gam.zig");
const vec = gam.vec;

const Sim = @This();

pub const max_ents = 256;

pub const no_coll_id = std.math.maxInt(u32);

ents: SlotMap,
rng: std.Random.DefaultPrng = .init(0),
stats: []const Stats = &.{
    .{
        .friction = 1,
        .radius = 32,
        .max_health = 100,
        .reload_period = 0.6,
        .speed = 500,
        .cbs = .init(opaque {
            pub const bullet_speed = 1000;
            pub fn shoot(self: *Sim, ent: *Ent, dir: vec.T) void {
                const slot = self.ents.add() catch return;
                slot.pos = ent.pos;
                slot.vel = dir * vec.splat(self.stats[1].speed);
                slot.owner = ent.id;
                slot.stats = &self.stats[1];
                ent.vel += dir * vec.splat(100);
            }
        }),
    },
    .{
        .lifetime = 0.5,
        .radius = 15,
        .damage = 20,
        .speed = 1000,
        .cbs = .init(opaque {}),
    },
    .{
        .friction = 1,
        .radius = 32,
        .max_health = 150,
        .reload_period = 0.6,
        .mass_mult = 2,
        .speed = 600,
        .cbs = .init(opaque {
            pub fn shoot(self: *Sim, ent: *Ent, dir: vec.T) void {
                const rng = self.rng.random();
                for (0..10) |_| {
                    const slot = self.ents.add() catch return;
                    slot.pos = ent.pos + vec.unit(rng.float(f32) * std.math.tau) *
                        vec.splat(10);
                    slot.vel = vec.unit(vec.ang(dir) + rng.float(f32) * 0.1 - 0.05) *
                        vec.splat(self.stats[3].speed);
                    slot.owner = ent.id;
                    slot.stats = &self.stats[3];
                }
                ent.vel -= dir * vec.splat(350);
            }
        }),
    },
    .{
        .lifetime = 0.25,
        .radius = 8,
        .damage = 15,
        .speed = 1000,
        .cbs = .init(opaque {}),
    },
    .{
        .friction = 1,
        .radius = 32,
        .max_health = 80,
        .reload_period = 0.8,
        .speed = 550,
        .cbs = .init(opaque {
            pub fn shoot(self: *Sim, ent: *Ent, dir: vec.T) void {
                if (ent.counter != 0) {
                    ent.reload = 0.1;
                    ent.counter -= 1;
                } else {
                    ent.counter = 5;
                }
                const rng = self.rng.random();
                const slot = self.ents.add() catch return;
                slot.pos = ent.pos + vec.unit(rng.float(f32) * std.math.tau) *
                    vec.splat(5);
                slot.vel = vec.unit(vec.ang(dir) + rng.float(f32) * 0.02 - 0.01) *
                    vec.splat(self.stats[5].speed);
                slot.owner = ent.id;
                slot.stats = &self.stats[5];
                ent.vel += dir * vec.splat(50);
            }
        }),
    },
    .{
        .lifetime = 0.5,
        .radius = 8,
        .damage = 15,
        .mass_mult = 0.1,
        .speed = 1200,
        .cbs = .init(opaque {}),
    },
},

pub const SlotMap = struct {
    slots: std.ArrayList(Ent),
    free: ?*Ent = null,
    dont_modify: bool = false,

    pub fn init(scratch: *utils.Arena, cap: usize) !SlotMap {
        var self = SlotMap{
            .slots = try .initCapacity(scratch.allocator(), cap),
        };

        _ = self.remove((self.add() catch unreachable).id);

        return self;
    }

    pub fn add(self: *SlotMap) !*Ent {
        if (self.dont_modify) return error.OutOfMemory;

        if (self.free) |fent| {
            const idx = (@intFromPtr(fent) - @intFromPtr(self.slots.items.ptr)) /
                @sizeOf(Ent);
            self.free = fent.next_free;

            // eaven gen means we are alive
            fent.* = .{ .id = .{ .index = @intCast(idx), .gen = fent.id.gen + 1 } };

            return fent;
        }

        const slot = try self.slots.addOneBounded();
        slot.* = .{
            .id = .{ .index = @intCast(self.slots.items.len - 1), .gen = 0 },
        };

        return slot;
    }

    pub fn remove(self: *SlotMap, id: Id) bool {
        if (self.dont_modify) return false;

        const slot = self.get(id) orelse return false;
        slot.id.gen += 1;
        slot.next_free = self.free;
        self.free = slot;
        return true;
    }

    pub fn get(self: *SlotMap, id: Id) ?*Ent {
        const slot = &self.slots.items[id.index];
        if (slot.id.gen != id.gen) return null;
        return slot;
    }
};

pub const Ent = struct {
    stats: *const Stats = undefined,

    reload: f32 = 0.0,
    age: f32 = 0.0,
    missing_health: u32 = 0,
    counter: u32 = 0,

    owner: Id = .invalid,

    vel: vec.T = vec.zero,
    pos: vec.T = vec.zero,
    rot: f32 = 0.0,

    coll_id: u32 = no_coll_id,

    // TODO: make this relative to the slot map (index)
    next_free: ?*Ent = null,
    id: Id,

    // TODO: serialize the entity list into this when sending it
    pub const Compact = struct {
        stats: u32,
        gen: u32,

        reload: f32,
        age: f32,
        missing_health: u32,

        owner: Id = .invalid,

        vel: vec.Packed,
        pos: vec.Packed,
        rot: f32 = 0.0,

        pub fn expand(self: Compact, sim: *const Sim, idx: usize) Ent {
            var e: Ent = .{ .id = .{ .index = @intCast(idx), .gen = self.gen } };
            e.stats = &sim.stats[@intCast(self.stats)];

            inline for (std.meta.fields(Compact)[custom_init_count..]) |f| {
                @field(e, f.name) = @field(self, f.name);
            }

            return e;
        }
    };

    const custom_init_count = 2;

    comptime {
        //@compileError(std.fmt.comptimePrint(
        //    "{} {}",
        //    .{ @sizeOf(Compact), @alignOf(Compact) },
        //));
    }

    pub fn compact(self: Ent, sim: *const Sim) Compact {
        var c: Compact = undefined;
        inline for (std.meta.fields(Compact)[custom_init_count..]) |f| {
            @field(c, f.name) = @field(self, f.name);
        }

        c.stats = self.stats.id(sim);
        c.gen = self.id.gen;

        return c;
    }

    pub fn isAlive(self: Ent) bool {
        return self.id.gen % 2 == 0;
    }
};

pub const Stats = struct {
    friction: f32 = 0.0,
    radius: f32 = 0.0,
    mass_mult: f32 = 1.0,
    damage: u32 = 0,
    max_health: u32 = 0,
    lifetime: f32 = 0.0,
    reload_period: f32 = 0.0,
    speed: f32 = 0.0,

    cbs: Callbacks = .{},

    pub const Callbacks = struct {
        shoot: *const fn (self: *Sim, ent: *Ent, dir: vec.T) void = default.shoot,

        const default = opaque {
            pub fn shoot(self: *Sim, ent: *Ent, dir: vec.T) void {
                _ = self;
                _ = ent;
                _ = dir;
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

    pub const Id = enum(u16) { _ };

    pub fn id(self: *const Stats, sim: *const Sim) u32 {
        return @intCast((@intFromPtr(self) - @intFromPtr(sim.stats.ptr)) /
            @sizeOf(Stats));
    }
};

pub const Id = packed struct(u64) {
    index: u32,
    gen: u32,

    pub const invalid = Id{ .index = 0, .gen = std.math.maxInt(u32) };
};

pub const Ctx = struct {
    delta: f32,
};

pub const InputState = extern struct {
    seq: u32 = 0,
    key_mask: packed struct(u8) {
        up: bool = false,
        down: bool = false,
        left: bool = false,
        right: bool = false,
        shoot: bool = false,
        _padd: u3 = 0,
    } = .{},
    mouse_pos: vec.Packed = @splat(0),
};

pub fn init(scratch: *utils.Arena, ent_cap: usize) !Sim {
    return .{
        .ents = try .init(scratch, ent_cap),
    };
}

// TODO: move to SlotMap
pub fn reset(self: *Sim) void {
    self.ents.slots.items.len = 1;
}

pub fn initInput(self: *Sim, ent_id: Id, input: InputState) void {
    const ent = self.ents.get(ent_id) orelse return;
    ent.rot = vec.ang(input.mouse_pos - ent.pos);
}

pub fn handleInput(self: *Sim, ctx: Ctx, ent_id: Id, input: InputState) void {
    const ent = self.ents.get(ent_id) orelse return;

    var dir = vec.zero;
    if (input.key_mask.up) dir += .{ 0, -1 };
    if (input.key_mask.down) dir += .{ 0, 1 };
    if (input.key_mask.left) dir += .{ -1, 0 };
    if (input.key_mask.right) dir += .{ 1, 0 };
    dir = vec.norm(dir);

    ent.vel += dir * vec.splat(ent.stats.speed * ctx.delta);

    const look_dir = vec.unit(ent.rot);

    ent.reload -= ctx.delta;
    if (input.key_mask.shoot) {
        if (ent.reload <= 0) {
            ent.reload = ent.stats.reload_period;
            ent.stats.cbs.shoot(self, ent, look_dir);
        }
    }
}

pub fn simulate(self: *Sim, ctx: Ctx) void {
    errdefer unreachable;

    var tmp = utils.Arena.scrath(null);
    defer tmp.deinit();

    const Coll = struct { a: Id, b: Id, t: f32 };
    var collisions: std.ArrayList(Coll) = .empty;

    for (self.ents.slots.items) |*ent| {
        if (!ent.isAlive()) continue;

        ent.vel *= vec.splat(1 - (ent.stats.friction * ctx.delta));
        ent.pos += ent.vel * vec.splat(ctx.delta);

        collect_colls: for (self.ents.slots.items) |*oent| {
            if (!oent.isAlive() or oent == ent) continue;
            if (oent.owner == ent.id or ent.owner == oent.id) continue;

            const min_dist = ent.stats.radius + oent.stats.radius;
            const dist = vec.dist2(ent.pos, oent.pos);

            // get rid of overlaps
            if (min_dist * min_dist > dist) {
                if (ent.stats.radius > oent.stats.radius) {
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

            if (t < 0 or t > ctx.delta) continue;

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

        ent.age += ctx.delta;
        if (ent.stats.lifetime > 0) {
            if (ent.age >= ent.stats.lifetime) {
                _ = self.ents.remove(ent.id);
                continue;
            }
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

        const amass = aent.stats.radius * aent.stats.mass_mult;
        const bmass = bent.stats.radius * bent.stats.mass_mult;

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
            if (a.stats.max_health == 0) continue;
            a.missing_health += b.stats.damage;
            if (a.stats.max_health -| a.missing_health == 0) {
                _ = self.ents.remove(a.id);
            }
        }
    }
}
