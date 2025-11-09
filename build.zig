const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const utils = b.dependency("utils", .{
        .target = target,
        .optimize = optimize,
    });

    const xev = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });

    const gam = b.addModule("gam", .{
        .root_source_file = b.path("src/gam.zig"),
        .target = target,
        .optimize = optimize,
    });
    gam.addAnonymousImport("zon", .{ .root_source_file = b.path("build.zig.zon") });
    gam.addImport("xev", xev.module("xev"));
    gam.addImport("utils", utils.module("utils"));

    const tests = b.addTest(.{ .root_module = gam });

    const server = b.addExecutable(.{
        .name = "server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/server.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
        }),
    });
    server.root_module.addImport("gam", gam);
    server.root_module.addImport("xev", xev.module("xev"));
    server.root_module.addImport("utils", utils.module("utils"));

    const raylib = b.dependency("raylib", .{
        .target = target,
        .optimize = optimize,
    });

    const raygui = b.dependency("raygui", .{
        .target = target,
        .optimize = optimize,
    });

    const raylib_build = @import("raylib");

    const lib = raylib.artifact("raylib");

    raylib_build.addRaygui(b, lib, raygui, .{});

    const client = b.addExecutable(.{
        .name = "client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/client.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
        }),
    });
    client.root_module.addImport("gam", gam);
    client.root_module.addImport("xev", xev.module("xev"));
    client.root_module.addImport("utils", utils.module("utils"));
    client.root_module.linkLibrary(lib);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    const check = b.step("check", "lsp check");
    check.dependOn(&server.step);
    check.dependOn(&client.step);
    check.dependOn(&tests.step);

    b.installArtifact(server);
    b.installArtifact(client);
}
