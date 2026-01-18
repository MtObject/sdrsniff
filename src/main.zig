const std = @import("std");

const bytes = @import("./bytes.zig");
const pcap = @import("pcap");
const proto = @import("./proto.zig");
const sdr = @import("./sdr.zig");
const UdpReassembler = @import("./UdpReassembler.zig");
const CertStore = @import("./CertStore.zig");

pub const std_options = std.Options{ .fmt_max_depth = 100000 };

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) {
        std.debug.print("usage: {s} <path to pcap> [path to sdr config]\n", .{args[0]});
        return;
    }
    const device_name = args[1];
    const config_path = if (args.len > 2) args[2] else null;

    var known_relays: std.AutoHashMap(std.Io.net.Ip4Address, void) = .init(init.gpa);
    var cert_store: CertStore = try .init(init.gpa);
    defer known_relays.deinit();
    defer cert_store.deinit();

    if (config_path) |config_path_| {
        const config_file = try std.Io.Dir.cwd().openFile(init.io, config_path_, .{ .mode = .read_only });
        defer config_file.close(init.io);
        var buffer: [1024]u8 = undefined;
        var reader = config_file.reader(init.io, &buffer);
        try parse_config(init.gpa, &reader.interface, &cert_store);
    }

    var reassembler = UdpReassembler.init();
    try pcap.init();
    std.log.debug("libpcap version: \"{s}\"", .{pcap.libVersion()});

    // TODO: bpf filter
    // const cap = try pcap.Capture.openLive(device_name, 262144, false, 100);
    const cap = try pcap.Capture.openOffline(device_name);
    if (try cap.datalinkType() != .ethernet) {
        std.debug.print("error: packet capture interface doesn't provide ethernet packets\n", .{});
        return;
    }

    var decode_arena: std.heap.ArenaAllocator = .init(init.gpa);
    defer decode_arena.deinit();
    while (true) {
        _ = decode_arena.reset(.retain_capacity);

        switch (try cap.next()) {
            .timeout => {
                continue;
            },
            .finished => {
                break;
            },
            .ok => |packet| {
                if (packet.data.len != packet.wire_len) {
                    std.log.warn("packet data size does not match wire size: {} != {}", .{ packet.data.len, packet.wire_len });
                }

                if (reassembler.parse(packet.data)) |reassembled_packet| {
                    if (sdr.isPingRequest(reassembled_packet.data)) {
                        // the client sends ping requests *to* a relay, so the dest address is always the relay
                        if (!known_relays.contains(reassembled_packet.dest)) {
                            std.log.info("discovered new relay {f}", .{reassembled_packet.dest});
                            try known_relays.put(reassembled_packet.dest, {});
                        }
                    }

                    const source: sdr.PacketSource =
                        if (known_relays.contains(reassembled_packet.dest))
                            .client
                        else if (known_relays.contains(reassembled_packet.source))
                            .relay
                        else
                            continue;
                    const decoded_packet = sdr.decodePacket(decode_arena.allocator(), reassembled_packet.data, source) catch |err| {
                        std.log.err("Failed to decode SDR packet from {} ({}): {x}", .{ source, err, reassembled_packet.data });
                        continue;
                    };
                    std.log.info("{f} ({}) -> {f}: {}", .{ reassembled_packet.source, source, reassembled_packet.dest, decoded_packet });
                }
            },
        }
    }
}

fn parse_config(alloc: std.mem.Allocator, config: *std.Io.Reader, cert_store: *CertStore) !void {
    const Config = struct {
        revision: u32,
        // base64-encoded
        certs: [][]const u8,
    };
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    var json_reader = std.json.Reader.init(arena.allocator(), config);
    const parsed = try std.json.parseFromTokenSource(Config, arena.allocator(), &json_reader, .{
        .ignore_unknown_fields = true,
    });

    for (parsed.value.certs) |cert_base64| {
        const decoded_len = try std.crypto.codecs.base64.decodedLen(cert_base64.len, .standard);
        const decoded_buf = try arena.allocator().alloc(u8, decoded_len);
        const decoded = try std.crypto.codecs.base64.decode(decoded_buf, cert_base64, .standard);

        var decoded_reader = std.Io.Reader.fixed(decoded);
        const parsed_cert = try proto.steam.CMsgSteamDatagramCertificateSigned.decode(&decoded_reader, arena.allocator());

        _ = try cert_store.addCACert(parsed_cert);
    }

    std.log.info("loaded config revision {}", .{parsed.value.revision});
}
