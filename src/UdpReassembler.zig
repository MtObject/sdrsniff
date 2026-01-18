const std = @import("std");
const bytes = @import("./bytes.zig");
const Ip4Address = std.Io.net.Ip4Address;
const log = std.log.scoped(.reassembler);

pub const ReassembledPacket = struct {
    source: Ip4Address,
    dest: Ip4Address,
    data: []const u8,
};

const MacAddress = [6]u8;
const EthernetHeader = extern struct {
    pub const EtherType = enum(u16) { ipv4 = 0x0800, _ };

    dest: MacAddress,
    src: MacAddress,
    ether_type: EtherType,
};
const IPv4Header = extern struct {
    pub const Protocol = enum(u8) { udp = 17, _ };
    pub const VersionAndIHL = packed struct {
        ihl: u4,
        version: u4,
    };
    pub const DSCPAndECN = packed struct {
        ecn: u2,
        dscp: u6,
    };
    pub const FragmentInfo = packed struct {
        fragment_offset: u13,

        more_fragments: bool,
        dont_fragment: bool,
        reserved: bool,
    };

    version_ihl: VersionAndIHL,
    dscp_ecn: DSCPAndECN,
    total_length: u16,
    identification: u16,
    fragment_info: FragmentInfo,
    ttl: u8,
    protocol: Protocol,
    header_checksum: u16,
    source_address: u32,
    dest_address: u32,
};
const UDPHeader = extern struct {
    source_port: u16,
    dest_port: u16,
    length: u16,
    checksum: u16,
};

pub fn init() @This() {
    log.debug("initialized packet reassembler", .{});
    return .{};
}

pub fn parse(self: *@This(), packet: []const u8) ?ReassembledPacket {
    _ = self;

    const ethernet_header, const ethernet_body = bytes.readStructPrefix(
        EthernetHeader,
        .big,
        packet,
    ) catch {
        return null;
    };
    // For now, we don't support IPv6. This should be fine, since SDR relays don't support it either.
    if (ethernet_header.ether_type != .ipv4) {
        return null;
    }

    const ipv4_header, const ipv4_body = bytes.readStructPrefix(
        IPv4Header,
        .big,
        ethernet_body,
    ) catch {
        return null;
    };
    if (ipv4_header.version_ihl.version != 4) {
        log.debug("got an ipv4 packet with a version that isn't 4?? {}", .{ipv4_header});
        return null;
    }
    if (ipv4_header.version_ihl.ihl != 5) {
        log.warn("got a packet with a weird IHL, ignoring for now: {}", .{ipv4_header});
        return null;
    }
    // SDR communicates over UDP, so we don't care about anything else.
    if (ipv4_header.protocol != .udp) {
        return null;
    }
    if (ipv4_header.fragment_info.fragment_offset != 0 or ipv4_header.fragment_info.more_fragments) {
        log.warn("TODO: actually implement IP packet reassembly!", .{});
        return null;
    }

    const udp_header, const udp_body = bytes.readStructPrefix(UDPHeader, .big, ipv4_body) catch {
        return null;
    };
    if (udp_header.length < @sizeOf(UDPHeader) or udp_header.length > (udp_body.len + @sizeOf(UDPHeader))) {
        log.debug("invalid UDP packet len. specified length is {}, we have {} bytes", .{ udp_header.length, udp_body.len });
        return null;
    }

    // TODO: verify both IP & UDP checksums, if available

    const source = bytes.convertRawAddressToIp4Address(ipv4_header.source_address, udp_header.source_port);
    const dest = bytes.convertRawAddressToIp4Address(ipv4_header.dest_address, udp_header.dest_port);
    return .{
        .source = source,
        .dest = dest,
        .data = udp_body[0 .. udp_header.length - @sizeOf(UDPHeader)],
    };
}
