const std = @import("std");
const bytes = @import("./bytes.zig");
const proto = @import("./proto.zig");

const log = std.log.scoped(.sdr);

pub const DecodeError = error{
    NoCmd,
    UnknownCmd,
    UnhandledCmd,
    InvalidBody,
};

pub const PacketSource = enum {
    client,
    relay,
};

pub const PacketTag = enum {
    router_ping_request,
    router_ping_reply,
    gameserver_session_request,
    gameserver_session_established,
    connection_closed,
    no_connection,
    stats,
    no_session,
    diagnostic,
    client_ping_sample_request,
    connect_ok,
    p2p_session_established,
    p2p_stats_client,
    p2p_bad_route,
    connect_request,
    client_ping_sample_reply,
    client_to_router_switched_primary,
    p2p_session_request,
    data,
};

pub const Packet = union(PacketTag) {
    router_ping_request: RouterPingRequestMessage,
    router_ping_reply: proto.steam.CMsgSteamDatagramRouterPingReply,
    gameserver_session_request: proto.steam.CMsgSteamDatagramGameserverSessionRequest,
    gameserver_session_established: proto.steam.CMsgSteamDatagramGameserverSessionEstablished,
    connection_closed: proto.steam.CMsgSteamDatagramConnectionClosed,
    no_connection: proto.steam.CMsgSteamDatagramNoConnection,
    stats: union(PacketSource) {
        client: proto.steam.CMsgSteamDatagramConnectionStatsClientToRouter,
        relay: proto.steam.CMsgSteamDatagramConnectionStatsRouterToClient,
    },
    no_session: proto.steam.CMsgSteamDatagramNoSessionRelayToClient,
    diagnostic: proto.steam.CMsgSteamDatagramDiagnostic,
    client_ping_sample_request: proto.steam.CMsgSteamDatagramClientPingSampleRequest,
    connect_ok: proto.steam.CMsgSteamDatagramConnectOK,
    p2p_session_established: proto.steam.CMsgSteamDatagramP2PSessionEstablished,
    p2p_stats_client: union(PacketSource) {
        client: proto.steam.CMsgSteamDatagramConnectionStatsP2PClientToRouter,
        relay: proto.steam.CMsgSteamDatagramConnectionStatsP2PRouterToClient,
    },
    p2p_bad_route: proto.steam.CMsgSteamDatagramP2PBadRouteRouterToClient,
    connect_request: proto.steam.CMsgSteamDatagramConnectRequest,
    client_ping_sample_reply: proto.steam.CMsgSteamDatagramClientPingSampleReply,
    client_to_router_switched_primary: proto.steam.CMsgSteamDatagramClientSwitchedPrimary,
    p2p_session_request: proto.steam.CMsgSteamDatagramP2PSessionRequest,
    data: struct {
        cmd: Cmd,
        header: DataPacketHeader,
        stats: ?[]const u8,
        timestamp: ?u16,
        encrypted_payload: []const u8,
    },
};

pub const RouterPingRequestMessage = extern struct {
    pub const VersionAndFlags = packed struct {
        version: u7, // version of ping message, currently 2
        minimal: bool,
    };

    cmd: u8, // FIXME: move this out
    version_and_flags: VersionAndFlags,
    sdping: [6]u8, // must always be "sdping"
    client_timestamp: u32, // time since client has started
    address_mask: u32, // random value
    always_0: u32,
    config_revision: u32, // "revision" key in GetSDRConfig response
    masked_ip: u32, // ipv4 address of relay, xored with address_mask
    masked_port: u16, // port of relay, xored with address_mask
    protocol_version: u16, // currently 12
    // FIXME: there are some values related to DSCP and ECN here.

    // the full message is padded to 0x514 bytes, unless the minimal flag is
    // set, in which case it is padded to 0x64 bytes.
};

pub const DataPacketHeader = extern struct {
    e2e_seq: u16,
    relay_seq: u16,
    connection_id: u32,
};

// packet layout:
// cr......
//  c: client -> relay data flag
//  r: relay  -> client data flag
// if c is set:
//  10p000ts <end-to-end sequence number: u16> <relay sequence number: u16> <connection id: u32> [stats blob len: varint] [stats blob] [timestamp: u16] <encrypted snp data>
//   p: connection is p2p (not hosted server)
//   t: contains timestamp
//   s: contains stats blob
// if r is set:
//  010???ts <end-to-end sequence number: u16> <relay sequence number: u16> <connection id: u32> [stats blob len: varint] [stats blob] [timestamp: u16] <encrypted snp data>
//   t: contains timestamp
//   s: contains stats blob
//   ???: always 001 in my traces
// else: <ESteamDatagramMsgID> <control packet body>
const Cmd = packed struct(u8) {
    const Remaining = packed union {
        ctrl: u6,
        data: packed struct(u6) {
            stats: bool,
            timestamp: bool,
            unk1: u3,
            p2p: bool,
        },
    };
    remaining: Remaining,
    relay_data: bool,
    client_data: bool,
};

pub fn isPingRequest(packet: []const u8) bool {
    const ping_message, _ = bytes.readStructPrefix(RouterPingRequestMessage, .little, packet) catch {
        return false;
    };
    return ping_message.cmd == 1 and std.mem.eql(u8, &ping_message.sdping, "sdping");
}

pub fn decodePacket(alloc: std.mem.Allocator, packet: []const u8, source: PacketSource) DecodeError!Packet {
    if (packet.len < 1) {
        return DecodeError.NoCmd;
    }
    const cmd: Cmd = @bitCast(packet[0]);
    const decode_ctx: DecodePbCtx = .{
        .alloc = alloc,
        .source = source,
        .body = packet[1..],
    };

    if (cmd.client_data or cmd.relay_data) {
        return decodeDataPacket(cmd, decode_ctx);
    } else {
        const ctrl_type: proto.steam.ESteamDatagramMsgID = @enumFromInt(cmd.remaining.ctrl);
        switch (ctrl_type) {
            .k_ESteamDatagramMsg_RouterPingRequest => {
                const decoded_body, _ = bytes.readStructPrefix(
                    RouterPingRequestMessage,
                    .little,
                    packet, // full packet is intentionally passed in, instead of just the body
                ) catch {
                    return DecodeError.InvalidBody;
                };

                return .{ .router_ping_request = decoded_body };
            },
            .k_ESteamDatagramMsg_RouterPingReply => return decodeCtrlPb(.router_ping_reply, decode_ctx),
            .k_ESteamDatagramMsg_GameserverSessionRequest => return decodeCtrlPb(.gameserver_session_request, decode_ctx),
            .k_ESteamDatagramMsg_GameserverSessionEstablished => return decodeCtrlPb(.gameserver_session_established, decode_ctx),
            .k_ESteamDatagramMsg_NoSession => return decodeCtrlPb(.no_session, decode_ctx),
            .k_ESteamDatagramMsg_Diagnostic => return decodeCtrlPb(.diagnostic, decode_ctx),
            .k_ESteamDatagramMsg_Stats => return decodeCtrlPb(.stats, decode_ctx),
            .k_ESteamDatagramMsg_ConnectionClosed => return decodeCtrlPb(.connection_closed, decode_ctx),
            .k_ESteamDatagramMsg_NoConnection => return decodeCtrlPb(.no_connection, decode_ctx),
            .k_ESteamDatagramMsg_ClientPingSampleRequest => return decodeCtrlPb(.client_ping_sample_request, decode_ctx),
            .k_ESteamDatagramMsg_ConnectOK => return decodeCtrlPb(.connect_ok, decode_ctx),
            .k_ESteamDatagramMsg_P2PSessionEstablished => return decodeCtrlPb(.p2p_session_established, decode_ctx),
            .k_ESteamDatagramMsg_P2PStatsClient => return decodeCtrlPb(.p2p_stats_client, decode_ctx),
            .k_ESteamDatagramMsg_P2PBadRoute => return decodeCtrlPb(.p2p_bad_route, decode_ctx),
            .k_ESteamDatagramMsg_ConnectRequest => return decodeCtrlPb(.connect_request, decode_ctx),
            .k_ESteamDatagramMsg_ClientPingSampleReply => return decodeCtrlPb(.client_ping_sample_reply, decode_ctx),
            .k_ESteamDatagramMsg_ClientToRouterSwitchedPrimary => return decodeCtrlPb(.client_to_router_switched_primary, decode_ctx),
            .k_ESteamDatagramMsg_P2PSessionRequest => return decodeCtrlPb(.p2p_session_request, decode_ctx),

            .k_ESteamDatagramMsg_GameserverPingRequest,
            .k_ESteamDatagramMsg_DataClientToRouter,
            .k_ESteamDatagramMsg_DataRouterToServer,
            .k_ESteamDatagramMsg_DataServerToRouter,
            .k_ESteamDatagramMsg_DataRouterToClient,
            .k_ESteamDatagramMsg_RelayHealth,
            .k_ESteamDatagramMsg_TicketDecryptRequest,
            .k_ESteamDatagramMsg_TicketDecryptReply,
            .k_ESteamDatagramMsg_P2PStatsRelay,
            .k_ESteamDatagramMsg_GameserverPingReply,
            .k_ESteamDatagramMsg_LegacyGameserverRegistration,
            .k_ESteamDatagramMsg_SetSecondaryAddressRequest,
            .k_ESteamDatagramMsg_SetSecondaryAddressResult,
            .k_ESteamDatagramMsg_RelayToRelayPingRequest,
            .k_ESteamDatagramMsg_RelayToRelayPingReply,
            => {
                return DecodeError.UnhandledCmd;
            },

            .k_ESteamDatagramMsg_Invalid,
            _,
            => return DecodeError.UnknownCmd,
        }
    }
}

// Convenience struct to avoid repeating params
const DecodePbCtx = struct {
    alloc: std.mem.Allocator,
    source: PacketSource,
    body: []const u8,
};

fn decodeDataPacket(cmd: Cmd, ctx: DecodePbCtx) DecodeError!Packet {
    var body_reader = std.Io.Reader.fixed(ctx.body);
    const header = body_reader.takeStruct(DataPacketHeader, .little) catch return DecodeError.InvalidBody;
    var stats: ?[]const u8 = null;
    var timestamp: ?u16 = null;

    if (cmd.remaining.data.stats) {
        const stats_len = body_reader.takeLeb128(u32) catch return DecodeError.InvalidBody;
        stats = body_reader.readAlloc(ctx.alloc, stats_len) catch return DecodeError.InvalidBody;
    }
    if (cmd.remaining.data.timestamp) {
        timestamp = body_reader.takeInt(u16, .little) catch return DecodeError.InvalidBody;
    }

    const encrypted_payload = body_reader.allocRemaining(ctx.alloc, .unlimited) catch return DecodeError.InvalidBody;
    return .{
        .data = .{
            .cmd = cmd,
            .header = header,
            .stats = stats,
            .timestamp = timestamp,
            .encrypted_payload = encrypted_payload,
        },
    };
}

fn decodeCtrlPb(comptime tag: PacketTag, ctx: DecodePbCtx) DecodeError!Packet {
    const field = std.meta.fieldInfo(Packet, tag).type;
    var body_reader = std.Io.Reader.fixed(ctx.body);
    switch (@typeInfo(field)) {
        .@"struct" => {
            const body = field.decode(&body_reader, ctx.alloc) catch {
                return DecodeError.InvalidBody;
            };

            return @unionInit(Packet, std.enums.tagName(PacketTag, tag).?, body);
        },
        .@"union" => |u| {
            inline for (u.fields) |union_field| {
                const source = std.meta.stringToEnum(PacketSource, union_field.name).?;
                if (source == ctx.source) {
                    const body = union_field.type.decode(&body_reader, ctx.alloc) catch {
                        return DecodeError.InvalidBody;
                    };
                    const inner_union = @unionInit(field, union_field.name, body);
                    return @unionInit(Packet, std.enums.tagName(PacketTag, tag).?, inner_union);
                }
            }
            unreachable;
        },
        else => @compileError("Invalid packet type"),
    }
}
