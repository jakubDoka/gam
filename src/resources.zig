const rl = @import("rl").rl;
const std = @import("std");

pub const sprites = struct {
    pub const Frame = struct {
        r: union {
            f: rl.Rectangle,
            i: struct {
                x: u32 = undefined,
                y: u32 = undefined,
                width: u32,
                height: u32,
            },
        },
        id: u32 = undefined,

        fn byArea(_: void, a: Frame, b: Frame) bool {
            return (b.r.i.width * b.r.i.height) < (a.r.i.width * a.r.i.height);
        }

        fn byId(_: void, a: Frame, b: Frame) bool {
            return a.id < b.id;
        }
    };

    fn packFrames(gpa: std.mem.Allocator, frames: []Frame, size: u32) !void {
        var taken_set = try std.DynamicBitSetUnmanaged.initEmpty(gpa, size * size);
        defer taken_set.deinit(gpa);

        for (frames, 0..) |*frame, i| frame.id = @intCast(i);
        std.sort.pdq(Frame, frames, {}, Frame.byArea);

        m: for (frames) |*frame| {
            var iter = taken_set.iterator(.{ .kind = .unset });
            o: while (iter.next()) |pos| {
                const x = pos % size;
                const y = pos / size;

                if (x + frame.r.i.width > size or y + frame.r.i.height > size) continue :o;

                const spc = 1;

                const minx = x -| spc;
                const miny = y -| spc;
                const maxx = @min(x + frame.r.i.width + spc, size);
                const maxy = @min(y + frame.r.i.height + spc, size);

                inline for (.{ miny, maxy }) |dy| for (minx..maxx) |dx| {
                    if (taken_set.isSet(dx + dy * size)) continue :o;
                };
                inline for (.{ minx, maxx }) |dx| for (miny..maxy) |dy| {
                    if (taken_set.isSet(dx + dy * size)) continue :o;
                };

                frame.r.i.x = @intCast(x);
                frame.r.i.y = @intCast(y);
                for (y..y + frame.r.i.height) |dy| {
                    taken_set.setRangeValue(.{
                        .start = x + dy * size,
                        .end = x + frame.r.i.width + dy * size,
                    }, true);
                }

                continue :m;
            }

            return error.OutOfMemory;
        }

        std.sort.pdq(Frame, frames, {}, Frame.byId);
    }

    pub fn pack(gpa: std.mem.Allocator, textures: []const rl.Image, frames: []Frame, sheet_size: u32) !rl.Image {
        var image = rl.GenImageColor(@intCast(sheet_size), @intCast(sheet_size), rl.BLANK);

        for (frames, textures) |*frame, tex| {
            frame.* = .{ .r = .{ .i = .{ .width = @intCast(tex.width), .height = @intCast(tex.height) } } };
        }

        try packFrames(gpa, frames, sheet_size);

        for (frames, textures) |*frame, tex| {
            const rect = rl.Rectangle{
                .x = @floatFromInt(frame.r.i.x),
                .y = @floatFromInt(frame.r.i.y),
                .width = @floatFromInt(frame.r.i.width),
                .height = @floatFromInt(frame.r.i.height),
            };
            frame.r = .{ .f = rect };
            const src = rl.Rectangle{ .x = 0, .y = 0, .width = frame.r.f.width, .height = frame.r.f.height };
            rl.ImageDraw(&image, tex, src, frame.r.f, rl.WHITE);
        }

        return image;
    }
};

test {
    const alc = std.testing.allocator;

    var frames = [_]sprites.Frame{
        .{ .width = 256, .height = 256 },
        .{ .width = 256, .height = 256 },
        .{ .width = 256, .height = 256 },
        .{ .width = 128, .height = 128 },
        .{ .width = 128, .height = 128 },
        .{ .width = 128, .height = 128 },
        .{ .width = 128, .height = 128 },
    };

    try sprites.packFrames(&frames);

    rl.InitWindow(0, 0, "");
    defer rl.CloseWindow();

    var images = [_]rl.Image{
        rl.GenImageColor(256, 256, rl.Color.red),
        rl.GenImageColor(128, 128, rl.Color.green),
        rl.GenImageColor(64, 64, rl.Color.blue),
        rl.GenImageColor(32, 32, rl.Color.yellow),
    };
    defer for (images) |image| rl.UnloadImage(image);

    var fra: [4]sprites.Frame = undefined;
    const sheet = try sprites.pack(alc, &images, &fra, 512);
    rl.UnloadTexture(sheet);
}
