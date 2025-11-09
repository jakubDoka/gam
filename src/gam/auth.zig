const std = @import("std");

pub const signer = std.crypto.sign.Ed25519;
pub const KeyPair = std.crypto.sign.Ed25519.KeyPair;
pub const Identity = std.crypto.sign.Ed25519.PublicKey;
pub const Signature = std.crypto.sign.Ed25519.Signature;
pub const cipher = std.crypto.aead.aes_gcm.Aes256Gcm;
pub const asoc_data = "gam " ++ @import("zon").version;
pub const CipherKey = [cipher.key_length]u8;
pub const Challenge = [32]u8;

pub const max_conns_reached = "max conns reached";

pub const Verified = struct {
    id: Identity,
    secret: CipherKey,
};

pub const SignedData = struct {
    server_challenge: Challenge,
    client_challenge: Challenge,

    pub fn sign(self: SignedData, rng: std.Random, kp: KeyPair) Signature {
        var buf: [@sizeOf(SignedData) + asoc_data.len]u8 = undefined;
        @memcpy(buf[0..@sizeOf(SignedData)], std.mem.asBytes(&self));
        @memcpy(buf[@sizeOf(SignedData)..], asoc_data);

        var noise: [32]u8 = undefined;
        rng.bytes(&noise);

        return kp.sign(&buf, noise) catch unreachable;
    }

    pub fn verify(
        self: SignedData,
        kp: Identity,
        sig: Signature,
    ) signer.Signature.VerifyError!void {
        var buf: [@sizeOf(SignedData) + asoc_data.len]u8 = undefined;
        @memcpy(buf[0..@sizeOf(SignedData)], std.mem.asBytes(&self));
        @memcpy(buf[@sizeOf(SignedData)..], asoc_data);

        try sig.verify(&buf, kp);
    }
};

pub const ClientHello = struct {
    kw: [keyword.len]u8 = keyword.*,
    identity: Identity,
    challenge: Challenge,

    pub const keyword = "client hello";
    pub const signed_data = asoc_data ++ " client-init";

    pub fn init(rng: std.Random, id: Identity) ClientHello {
        var challenge: [32]u8 = undefined;
        rng.bytes(&challenge);

        return .{
            .identity = id,
            .challenge = challenge,
        };
    }
};

pub const ServerHello = struct {
    identity: Identity,
    challenge: Challenge,
    sign: Signature,

    pub fn init(rng: std.Random, kp: KeyPair, hello: ClientHello) ServerHello {
        var challenge: [32]u8 = undefined;
        rng.bytes(&challenge);

        const signed_data = SignedData{
            .server_challenge = challenge,
            .client_challenge = hello.challenge,
        };

        return .{
            .identity = kp.public_key,
            .challenge = challenge,
            .sign = signed_data.sign(rng, kp),
        };
    }
};

pub const Finished = struct {
    sign: Signature,

    pub fn init(
        rng: std.Random,
        kp: KeyPair,
        ch: ClientHello,
        sh: ServerHello,
    ) signer.Signature.VerifyError!struct { Finished, Verified } {
        const signed_data = SignedData{
            .server_challenge = sh.challenge,
            .client_challenge = ch.challenge,
        };

        try signed_data.verify(sh.identity, sh.sign);

        const keypair = try std.crypto.dh.X25519.KeyPair.fromEd25519(kp);
        const pk = try std.crypto.dh.X25519.publicKeyFromEd25519(sh.identity);

        return .{ .{ .sign = signed_data.sign(rng, kp) }, .{
            .id = sh.identity,
            .secret = try std.crypto.dh.X25519.scalarmult(keypair.secret_key, pk),
        } };
    }

    pub fn verify(self: Finished, kp: KeyPair, ch: ClientHello, sh: ServerHello) !Verified {
        const signed_data = SignedData{
            .server_challenge = sh.challenge,
            .client_challenge = ch.challenge,
        };

        try signed_data.verify(ch.identity, self.sign);

        const keypair = try std.crypto.dh.X25519.KeyPair.fromEd25519(kp);
        const pk = try std.crypto.dh.X25519.publicKeyFromEd25519(ch.identity);

        return .{
            .id = ch.identity,
            .secret = try std.crypto.dh.X25519.scalarmult(keypair.secret_key, pk),
        };
    }
};
