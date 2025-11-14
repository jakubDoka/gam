const std = @import("std");
const utils = @import("utils");

const gam = @import("../gam.zig");
const vec = gam.vec;

const Sim = @This();

pub const max_ents = 256;
pub const reload_period = 0.5;

pub const no_coll_id = std.math.maxInt(u32);

pub const SlotMap = struct {
    slots: std.ArrayList(Ent),
    free: ?*Ent = null,
    dont_modify: bool = false,

    pub fn init(scratch: *utils.Arena, cap: usize) !SlotMap {
        return .{
            .slots = try .initCapacity(scratch.allocator(), cap),
        };
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
        self.free = slot.next_free;
        return true;
    }

    pub fn get(self: *SlotMap, id: Id) ?*Ent {
        const slot = &self.slots.items[id.index];
        if (slot.id.gen != id.gen) return null;
        return slot;
    }
};

pub const Ent = struct {
    kind: enum { bullet, player } = undefined,

    // mostly static
    friction: f32 = 0.0,
    radius: f32 = 0.0,
    mass_mult: f32 = 1.0,
    damage: u32 = 0,

    reload: f32 = 0.0,
    lifetime: f32 = 0.0,
    health: u32 = 0,

    owner: Id = .invalid,

    vel: vec.T = vec.zero,
    pos: vec.T = vec.zero,
    rot: f32 = 0.0,

    coll_id: u32 = no_coll_id,

    next_free: ?*Ent = null,
    id: Id,

    pub fn isAlive(self: Ent) bool {
        return self.id.gen % 2 == 0;
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

ents: SlotMap,

pub fn init(scratch: *utils.Arena, ent_cap: usize) !Sim {
    return .{
        .ents = try .init(scratch, ent_cap),
    };
}

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
    mouse_pos: vec.T = vec.zero,
};

pub fn handleInput(self: *Sim, ctx: Ctx, ent_id: Id, input: InputState) void {
    const ent = self.ents.get(ent_id) orelse return;

    ent.rot = vec.ang(input.mouse_pos - ent.pos);

    var dir = vec.zero;
    if (input.key_mask.up) dir += .{ 0, -1 };
    if (input.key_mask.down) dir += .{ 0, 1 };
    if (input.key_mask.left) dir += .{ -1, 0 };
    if (input.key_mask.right) dir += .{ 1, 0 };
    dir = vec.norm(dir);

    const player_acc = 500;

    ent.vel += dir * vec.splat(player_acc * ctx.delta);

    const look_dir = vec.norm(input.mouse_pos - ent.pos);
    const bullet_lifetime = 0.5;
    const bullet_speed = 1000;

    ent.reload -= ctx.delta;
    if (input.key_mask.shoot) {
        if (ent.reload <= 0) b: {
            const slot = self.ents.add() catch break :b;
            ent.reload = reload_period;

            slot.kind = .bullet;
            slot.pos = ent.pos;
            slot.vel = look_dir * vec.splat(bullet_speed);
            slot.owner = ent_id;
            slot.lifetime = bullet_lifetime;
            slot.radius = 15;
            slot.damage = 25;
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

        ent.vel *= vec.splat(1 - (ent.friction * ctx.delta));
        ent.pos += ent.vel * vec.splat(ctx.delta);

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

        const prev_lt = ent.lifetime;
        ent.lifetime -= ctx.delta;
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
