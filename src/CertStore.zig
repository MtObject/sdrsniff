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

// i'd love to know why valve stores this as an ssh public key
const root_public_key_hex = "9aeca04e1751ce6268d569002ca1e1fa1b2dbc26d36b4ea3a0083ad372829b84";

alloc: std.mem.Allocator,
certs: std.AutoHashMapUnmanaged(KeyID, PublicKey),

pub fn init(alloc: std.mem.Allocator) error{OutOfMemory}!CertStore {
    var self = CertStore{
        .alloc = alloc,
        .certs = .empty,
    };

    // FIXME: cleanup block
    comptime var root_public_key_bytes: [32]u8 = undefined;
    _ = try comptime std.fmt.hexToBytes(&root_public_key_bytes, root_public_key_hex);
    const root_public_key_inner = try comptime Ed25519.PublicKey.fromBytes(root_public_key_bytes);
    const root_public_key = PublicKey{
        .ed25519 = root_public_key_inner,
    };
    try self.certs.put(self.alloc, calculateKeyID(root_public_key), root_public_key);

    return self;
}

pub fn deinit(self: *CertStore) void {
    self.certs.deinit(self.alloc);
}

pub fn addCACert(self: *CertStore, signed_certificate: proto.steam.CMsgSteamDatagramCertificateSigned) !KeyID {
    const signature_bytes = signed_certificate.ca_signature orelse return error.MissingSignature;
    const certificate_bytes = signed_certificate.cert orelse return error.MissingCert;

    if (!self.verify(certificate_bytes, signature_bytes, signed_certificate.ca_key_id orelse return error.MissingCAKeyID)) {
        return error.InvalidSignature;
    }

    // TODO: check expiry, revocation, blah blah blah
    var certificate_reader = std.Io.Reader.fixed(certificate_bytes);
    var certificate = try proto.steam.CMsgSteamDatagramCertificate.decode(&certificate_reader, self.alloc);
    defer certificate.deinit(self.alloc);

    const public_key: PublicKey = switch (certificate.key_type orelse .INVALID) {
        .ED25519 => blk: {
            const key_data = certificate.key_data orelse &[_]u8{};
            if (key_data.len != Ed25519.PublicKey.encoded_length) {
                return error.InvalidPublicKey;
            }

            break :blk .{
                .ed25519 = try Ed25519.PublicKey.fromBytes(key_data[0..Ed25519.PublicKey.encoded_length].*),
            };
        },
        .INVALID, _ => return error.InvalidKeyType,
    };
    const key_id = calculateKeyID(public_key);
    try self.certs.put(self.alloc, key_id, public_key);

    log.debug("added ca cert {}, valid for apps: {any}", .{ key_id, certificate.app_ids.items });

    return key_id;
}

pub fn verify(self: *CertStore, data: []const u8, signature: []const u8, ca_key_id: KeyID) bool {
    const parent_public_key = self.certs.get(ca_key_id) orelse {
        return false;
    };
    switch (parent_public_key) {
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
