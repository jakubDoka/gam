const std = @import("std");

pub const T = @Vector(2, f32);

pub const zero = T{ 0, 0 };

pub const dirs = [_]T{ .{ 0, -1 }, .{ -1, 0 }, .{ 0, 1 }, .{ 1, 0 } };

pub inline fn tof(value: anytype) f32 {
    return @floatFromInt(value);
}

pub fn divToFloat(a: anytype, b: @TypeOf(a)) f32 {
    return @as(f32, @floatFromInt(a)) / @as(f32, @floatFromInt(b));
}

//pub fn fcolor(r: f32, g: f32, b: f32) rl.Color {
//    return .{
//        .r = @intFromFloat(r * 255),
//        .g = @intFromFloat(g * 255),
//        .b = @intFromFloat(b * 255),
//        .a = 255,
//    };
//}

pub fn moveTowardsAngle(from: f32, to: f32, max_step: f32) f32 {
    var delta = to - from;
    // Normalize delta to the range [-pi, pi]
    delta = @mod(delta + std.math.pi, std.math.tau) - std.math.pi;
    delta = std.math.clamp(delta, -max_step, max_step);
    return from + delta;
}

pub fn normalizeAng(angle: f32) f32 {
    return moveTowardsAngle(0, angle, std.math.pi);
}

//pub fn fromRl(v: rl.Vector2) T {
//    return @bitCast(v);
//}

pub fn asInt(a: T) [2]i32 {
    return .{ @intFromFloat(a[0]), @intFromFloat(a[1]) };
}

//pub fn asRl(a: T) rl.Vector2 {
//    return @bitCast(a);
//}

pub fn splat(scal: f32) T {
    return @splat(scal);
}

pub fn len2(a: T) f32 {
    return @reduce(.Add, a * a);
}

pub fn len(a: T) f32 {
    return std.math.sqrt(len2(a));
}

pub fn dist2(a: T, b: T) f32 {
    return len2(a - b);
}

pub fn dist(a: T, b: T) f32 {
    return len(a - b);
}

pub fn unit(angle: f32) T {
    return .{ @cos(angle), @sin(angle) };
}

pub fn rad(angle: f32, length: f32) T {
    return unit(angle) * splat(length);
}

pub fn orth(a: T) T {
    return .{ -a[1], a[0] };
}

pub fn norm(a: T) T {
    const l = len(a);
    if (l == 0.0) {
        return zero;
    }
    return a / splat(l);
}

pub fn ang(a: T) f32 {
    return std.math.atan2(a[1], a[0]);
}

pub fn dot(a: T, b: T) f32 {
    return @reduce(.Add, a * b);
}

pub fn angBetween(a: T, b: T) f32 {
    return std.math.acos(dot(a, b) / (len(a) * len(b)));
}

pub fn proj(a: T, b: T) ?T {
    const ln = len2(b);
    if (ln == 0.0) {
        return null;
    }
    return b * splat(dot(a, b) / ln);
}

pub fn clamp(a: T, max_len: f32) T {
    const l = len(a);
    if (l > max_len) {
        return a * splat(max_len / l);
    }
    return a;
}

pub fn intersect(comptime xd: usize, a: T, b: T, y: f32, mx: f32, xx: f32) ?T {
    const yd = 1 - xd;

    if ((a[yd] > y) == (b[yd] > y)) return null;

    const cof = (y - b[yd]) / (a[yd] - b[yd]);

    const x = (a[xd] - b[xd]) * cof + b[xd];

    if (x > xx or mx > x) return null;

    var res = zero;
    res[xd] = x;
    res[yd] = y;
    return res;
}

pub fn predictTarget(turret: T, target: T, target_vel: T, bullet_speed: f32) ?T {
    const rel = target - turret;
    const a = dot(target_vel, target_vel) - bullet_speed * bullet_speed;
    if (a == 0) return target;
    const b = 2 * dot(target_vel, rel);
    const c = dot(rel, rel);
    const d = b * b - 4 * a * c;
    if (d < 0) return null;
    const t = (-b - std.math.sqrt(d)) / (2 * a);
    return target + target_vel * splat(t);
}

test "projection" {
    const a = T{ 1.0, 2.0 };
    const b = T{ 3.0, 4.0 };
    const p = proj(a, b) orelse unreachable;
    const ort = a - p;
    try std.testing.expectApproxEqAbs(dot(p, ort), 0.0, 0.000001);
}
