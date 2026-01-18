const std = @import("std");
const protobuf = @import("protobuf");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const npcap_sdk = b.dependency("npcap_sdk", .{});
    const npcap_mod = b.createModule(.{
        .root_source_file = b.path("src/pcap.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    npcap_mod.addIncludePath(npcap_sdk.path("Include/"));
    // TODO: check architecture
    npcap_mod.addObjectFile(npcap_sdk.path("Lib/x64/wpcap.lib"));

    const protobuf_dep = b.dependency("protobuf", .{
        .target = target,
        .optimize = optimize,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "pcap", .module = npcap_mod },
            .{ .name = "protobuf", .module = protobuf_dep.module("protobuf") },
        },
    });
    const exe_options: std.Build.ExecutableOptions = .{
        .name = "sdrsniff",
        .root_module = exe_mod,
    };
    const exe = b.addExecutable(exe_options);
    const exe_check = b.addExecutable(exe_options);
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const check_step = b.step("check", "Check if the app builds");
    check_step.dependOn(&exe_check.step);

    const gen_proto = b.step("gen-proto", "Generate compiled protobuf files");
    const protoc_step = protobuf.RunProtocStep.create(protobuf_dep.builder, target, .{
        .destination_directory = b.path("src/proto"),
        .source_files = &.{
            b.path("proto/steamdatagram_messages_auth.proto"),
            b.path("proto/steamdatagram_messages_sdr.proto"),
            b.path("proto/steamnetworkingsockets_messages.proto"),
            b.path("proto/steamnetworkingsockets_messages_certs.proto"),
        },
        .include_directories = &.{b.path("proto/")},
    });
    gen_proto.dependOn(&protoc_step.step);
}
