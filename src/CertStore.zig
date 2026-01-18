const std = @import("std");
const log = std.log.scoped(.CertStore);
const Sha256 = std.crypto.hash.sha2.Sha256;
const Ed25519 = std.crypto.sign.Ed25519;

const proto = @import("./proto.zig");
const CertStore = @This();
const KeyID = u64;

const PublicKeyAlgorithm = enum {
    ed25519,
};

const PublicKey = union(PublicKeyAlgorithm) {
    ed25519: Ed25519.PublicKey,
};

const Certificate = struct {
    public_key: PublicKey,
    identity: ?[]const u8,
    app_ids: []const u32,
    time_created: u32,
    time_expiry: u32,

    fn deinit(self: *Certificate, alloc: std.mem.Allocator) void {
        if (self.identity) |identity| {
            alloc.free(identity);
        }
        alloc.free(self.app_ids);
    }

    fn keyID(self: Certificate) u64 {
        return calculateKeyID(self.public_key);
    }
};

// i'd love to know why valve stores this as an ssh public key
const root_public_key_hex = "9aeca04e1751ce6268d569002ca1e1fa1b2dbc26d36b4ea3a0083ad372829b84";

alloc: std.mem.Allocator,
certs: std.AutoHashMapUnmanaged(KeyID, Certificate),

pub fn init(alloc: std.mem.Allocator) error{OutOfMemory}!CertStore {
    var self = CertStore{
        .alloc = alloc,
        .certs = .empty,
    };

    const root_certificate = Certificate{
        .public_key = .{
            .ed25519 = comptime blk: {
                var bytes: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&bytes, root_public_key_hex) catch unreachable;
                break :blk Ed25519.PublicKey.fromBytes(bytes) catch unreachable;
            },
        },
        .identity = null,
        .app_ids = &.{},
        .time_created = 0,
        .time_expiry = 0,
    };
    try self.certs.put(self.alloc, root_certificate.keyID(), root_certificate);

    return self;
}

pub fn deinit(self: *CertStore) void {
    var cert_iter = self.certs.valueIterator();
    while (cert_iter.next()) |cert| {
        cert.deinit(self.alloc);
    }

    self.certs.deinit(self.alloc);
}

pub fn addCACert(self: *CertStore, signed_certificate: proto.steam.CMsgSteamDatagramCertificateSigned) !void {
    const certificate = try self.parseCertificate(self.alloc, signed_certificate);
    const key_id = certificate.keyID();

    try self.certs.put(self.alloc, key_id, certificate);
    log.debug("added ca cert {}", .{key_id});
}

pub fn parseCertificate(self: *CertStore, alloc: std.mem.Allocator, signed_certificate: proto.steam.CMsgSteamDatagramCertificateSigned) !Certificate {
    const signature_bytes = signed_certificate.ca_signature orelse return error.NoSignature;
    const certificate_bytes = signed_certificate.cert orelse return error.NoCertificate;

    // TODO: check expiry, revocation, blah blah blah
    var certificate_reader = std.Io.Reader.fixed(certificate_bytes);
    var certificate_proto = try proto.steam.CMsgSteamDatagramCertificate.decode(&certificate_reader, self.alloc);
    defer certificate_proto.deinit(self.alloc);

    const public_key: PublicKey = switch (certificate_proto.key_type orelse .INVALID) {
        .INVALID, _ => return error.InvalidKeyType,
        .ED25519 => blk: {
            const key_data = certificate_proto.key_data.?;
            if (key_data.len != Ed25519.PublicKey.encoded_length) {
                return error.InvalidPublicKey;
            }

            break :blk .{
                .ed25519 = try Ed25519.PublicKey.fromBytes(key_data[0..Ed25519.PublicKey.encoded_length].*),
            };
        },
    };

    const identity = if (certificate_proto.identity_string) |identity|
        try alloc.dupe(u8, identity)
    else
        null;
    const app_ids = try alloc.dupe(u32, certificate_proto.app_ids.items);

    const certificate = Certificate{
        .public_key = public_key,
        .identity = identity,
        .app_ids = app_ids,
        .time_created = certificate_proto.time_created orelse 0,
        .time_expiry = certificate_proto.time_expiry orelse 0,
    };

    const parent_ = self.certs.get(signed_certificate.ca_key_id orelse 0);
    if (parent_) |parent| {
        if (!verify(certificate_bytes, signature_bytes, parent)) {
            return error.InvalidSignature;
        }
    } else {
        std.log.warn("could not find CA with id {}, skipping verification", .{signed_certificate.ca_key_id orelse 0});
    }

    return certificate;
}

pub fn verify(data: []const u8, signature: []const u8, certificate: Certificate) bool {
    switch (certificate.public_key) {
        .ed25519 => |parent_public_key_ed25119| {
            if (signature.len != Ed25519.Signature.encoded_length) {
                return false;
            }

            const parsed_signature = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
            _ = parsed_signature.verify(data, parent_public_key_ed25119) catch return false;
            return true;
        },
    }
}

fn calculateKeyID(public_key: PublicKey) u64 {
    switch (public_key) {
        .ed25519 => |public_key_ed25519| {
            var hash: [32]u8 = undefined;
            Sha256.hash(&public_key_ed25519.toBytes(), &hash, .{});
            return std.mem.readInt(u64, hash[0..8], .little);
        },
    }
}
