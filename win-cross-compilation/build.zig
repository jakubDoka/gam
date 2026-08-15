const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const win_target = b.resolveTargetQuery(.{
        .os_tag = .windows,
        .cpu_arch = .x86_64,
        .abi = .gnu,
    });
    const optimize = std.builtin.OptimizeMode.ReleaseSmall;

    const sqlite = b.dependency("sqlite", .{
        .target = win_target,
        .optimize = optimize,
    });

    inline for (.{ .static, .dynamic }) |mode| {
        const sqlite_lib = b.addLibrary(.{
            .name = "sqlite",
            .linkage = mode,
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            }),
        });
        sqlite_lib.root_module.addCSourceFile(.{ .file = sqlite.path("sqlite3.c") });

        b.installArtifact(sqlite_lib);
    }

    const sqlite_lib = b.addLibrary(.{
        .name = "sqlite",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = win_target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    sqlite_lib.root_module.addCSourceFile(.{ .file = sqlite.path("sqlite3.c") });

    b.installArtifact(sqlite_lib);

    const raylib = b.dependency("raylib", .{
        .target = win_target,
        .optimize = optimize,
        .raygui = true,
    });

    var project_dir = try std.Io.Dir.cwd().openDir(b.graph.io, "..", .{ .iterate = true });
    var walker = try project_dir.walk(b.allocator);

    const compile_client = b.addSystemCommand(&.{
        "odin",
        "build",
        "../client",
        "-o:size",
        "-default-to-nil-allocator",
        "-no-type-assert",
        "-no-bounds-check",
        "-disable-assert",
        "-target=windows_amd64",
        "-build-mode=object",
    });

    while (try walker.next(b.graph.io)) |entry| {
        if (std.mem.endsWith(u8, entry.basename, ".odin")) {
            compile_client.addFileInput(
                b.path(try std.fs.path.join(b.allocator, &.{ "..", entry.path })),
            );
        }
    }

    const client = compile_client.addPrefixedOutputFileArg("-out:", "client.obj");

    const stub = b.addLibrary(.{
        .name = "stub",
        .root_module = b.createModule(.{
            .root_source_file = b.path("stub.zig"),
            .target = win_target,
            .optimize = optimize,
        }),
    });

    const win = b.addExecutable(.{
        .name = "gam",
        .root_module = b.createModule(.{
            .target = win_target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    win.root_module.addObjectFile(client);
    win.root_module.addCSourceFile(.{ .file = b.path("raylib_shim.c") });
    win.root_module.addIncludePath(raylib.path("src"));
    win.root_module.linkLibrary(raylib.artifact("raylib"));
    win.root_module.linkLibrary(sqlite_lib);
    win.root_module.linkSystemLibrary("ws2_32", .{});
    win.root_module.linkSystemLibrary("mswsock", .{});
    win.root_module.linkSystemLibrary("bcrypt", .{});
    win.root_module.linkSystemLibrary("ole32", .{});
    win.root_module.linkLibrary(stub);

    b.installArtifact(win);
}
