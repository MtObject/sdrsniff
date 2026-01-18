const std = @import("std");
const c = @cImport({
    @cInclude("pcap/pcap.h");
});

pub fn libVersion() []const u8 {
    return std.mem.span(c.pcap_lib_version());
}

pub fn init() error{InitFailed}!void {
    // TODO: do something with this message
    var err_buf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    const c_err = c.pcap_init(c.PCAP_CHAR_ENC_UTF_8, &err_buf);
    if (c_err == c.PCAP_ERROR) {
        return error.InitFailed;
    }
}

pub const DatalinkType = enum(c_int) {
    ethernet = c.DLT_EN10MB,
    _,
};

pub const Capture = struct {
    inner: *c.pcap_t,

    pub fn openLive(device_name: [*:0]const u8, snaplen: c_int, promisc: bool, timeout_ms: c_int) error{OpenFailed}!Capture {
        // TODO: return error message and log warnings
        var err_buf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
        const capture = c.pcap_open_live(device_name, snaplen, if (promisc) 1 else 0, timeout_ms, &err_buf);
        if (capture) |capture_| {
            return .{ .inner = capture_ };
        }

        return error.OpenFailed;
    }

    pub fn openOffline(filename: [*:0]const u8) error{OpenFailed}!Capture {
        // TODO: return error message and log warnings
        var err_buf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
        const capture = c.pcap_open_offline(filename, &err_buf);
        if (capture) |capture_| {
            return .{ .inner = capture_ };
        }

        return error.OpenFailed;
    }

    pub fn datalinkType(self: Capture) error{NotActivated}!DatalinkType {
        const result = c.pcap_datalink(self.inner);
        if (result == c.PCAP_ERROR_NOT_ACTIVATED) {
            return error.NotActivated;
        }
        return @enumFromInt(result);
    }

    pub fn next(self: Capture) error{NextPacketFailed}!NextPacket {
        var hdr: [*c]c.pcap_pkthdr = undefined;
        var data: [*c]const u8 = undefined;
        const c_err = c.pcap_next_ex(self.inner, &hdr, &data);
        switch (c_err) {
            0 => return .timeout,
            1 => return .{
                .ok = Packet{
                    .timestamp = .{
                        .sec = hdr.*.ts.tv_sec,
                        .usec = hdr.*.ts.tv_usec,
                    },
                    .wire_len = hdr.*.len,
                    .data = data[0..hdr.*.caplen],
                },
            },
            c.PCAP_ERROR_BREAK => return .finished,
            // TODO: return error message text
            c.PCAP_ERROR => return error.NextPacketFailed,
            else => unreachable,
        }
    }
};

pub const NextPacketTag = enum { timeout, finished, ok };
pub const NextPacket = union(NextPacketTag) { timeout: void, finished: void, ok: Packet };

pub const Packet = struct {
    timestamp: std.c.timeval,
    wire_len: u32,
    data: []const u8,
};
