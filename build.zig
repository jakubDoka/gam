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

    const raylib_native = b.dependency("raylib", .{
        .target = b.graph.host,
        .optimize = .Debug,
    });
    const rl = b.createModule(.{
        .root_source_file = b.path("src/rl.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
        .single_threaded = true,
    });
    rl.linkLibrary(raylib_native.artifact("raylib"));

    const resources = b.createModule(.{
        .root_source_file = b.path("src/resources.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
        .single_threaded = true,
    });
    resources.addImport("rl", rl);

    const gen_sheet = b.addExecutable(.{
        .name = "gen_sheet",
        .root_module = b.createModule(.{
            .root_source_file = b.path("scripts/gen_sheet.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
            .single_threaded = true,
        }),
    });

    gen_sheet.root_module.addImport("rl", rl);
    gen_sheet.root_module.addImport("resources", resources);

    const gen_sheet_run = b.addRunArtifact(gen_sheet);
    gen_sheet_run.has_side_effects = false;
    gen_sheet_run.addDirectoryArg(b.path("assets/textures"));
    const sheet_png = gen_sheet_run.addOutputFileArg("sheet.png");
    const sheet_zig = gen_sheet_run.addOutputFileArg("sheet.zig");

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
    //lib.addIncludePath(b.path("assets/include/"));
    //lib.addLibraryPath(b.path("assets/lib/"));

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
    client.linkLibrary(lib);
    //client.root_module.addIncludePath(b.path("assets/include/"));
    //client.root_module.addLibraryPath(b.path("assets/lib/"));
    client.root_module.addAnonymousImport("sheet_png", .{
        .root_source_file = sheet_png,
    });
    client.root_module.addAnonymousImport("sheet_zig", .{
        .root_source_file = sheet_zig,
    });

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    const check = b.step("check", "lsp check");
    check.dependOn(&server.step);
    check.dependOn(&client.step);
    check.dependOn(&tests.step);

    b.installArtifact(server);
    b.installArtifact(client);
}
