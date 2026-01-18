const std = @import("std");

pub fn readStructPrefix(struct_type: type, endian: std.builtin.Endian, data: []const u8) error{TooShort}!struct { struct_type, []const u8 } {
    if (data.len < @sizeOf(struct_type)) {
        return error.TooShort;
    }

    var struct_value = std.mem.bytesToValue(struct_type, data);
    if (endian == std.builtin.Endian.foreign) {
        std.mem.byteSwapAllFields(struct_type, &struct_value);
    }

    return .{ struct_value, data[@sizeOf(struct_type)..] };
}

pub fn convertRawAddressToIp4Address(ip: u32, port: u16) std.Io.net.Ip4Address {
    const ip_bytes = [4]u8{
        @intCast(ip >> 24),
        @intCast(ip >> 16 & 0xff),
        @intCast(ip >> 8 & 0xff),
        @intCast(ip & 0xff),
    };

    return .{ .bytes = ip_bytes, .port = port };
}
