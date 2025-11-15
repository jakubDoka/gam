const std = @import("std");

pub fn build(b: *std.Build) !void {
    const git = try b.findProgram(&.{"git"}, &.{});
    const gh = try b.findProgram(&.{"gh"}, &.{});

    const version = b.option([]const u8, "version", "version to tag") orelse
        "unknown-release";

    const release_targets = [_]struct { []const u8, std.Build.ResolvedTarget }{
        .{
            "x86_64-windows",
            b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .windows }),
        },
        //.{
        //    "x86_64-linux",
        //    b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .linux, .glibc_version = .{ .major = 2, .minor = 35, .patch = 0 } }),
        //},
        .{
            "x86_64-linux",
            b.graph.host,
        },
    };

    const tag_release = b.addSystemCommand(&.{
        git,
        "tag",
        "-a",
        version,
        "-m",
        try std.mem.concat(b.allocator, u8, &.{ "Release ", version }),
    });

    const push_release = b.addSystemCommand(&.{ git, "push", "origin", version });
    push_release.step.dependOn(&tag_release.step);

    const create_release = b.addSystemCommand(&.{
        gh,
        "release",
        "create",
        version,
        "-t",
        version,
        "--verify-tag",
        "--latest",
        "--generate-notes",
    });
    create_release.step.dependOn(&push_release.step);

    for (release_targets) |tar| {
        const dep = b.dependency("project", .{
            .optimize = .ReleaseSmall,
            .target = tar[1],
        });

        inline for (.{ "client", "server" }) |art| {
            const artifact = dep.artifact(art);

            const artifact_bin = artifact.getEmittedBin();

            const install_artifact = b.addInstallBinFile(
                artifact_bin,
                try std.mem.concat(
                    b.allocator,
                    u8,
                    &.{ tar[0], "-", artifact.out_filename },
                ),
            );

            create_release.addArg(b.getInstallPath(
                install_artifact.dir,
                install_artifact.dest_rel_path,
            ));
            create_release.step.dependOn(&install_artifact.step);
        }
    }

    const release_step = b.step("release", "make the release and publish it to github");
    release_step.dependOn(&create_release.step);
}
