package sim

import "../simt/nbio"
import aes "core:crypto/aes"
import "core:crypto/blake2s"
import ed "core:crypto/ed25519"
import x "core:crypto/x25519"
import "core:reflect"
import "core:testing"

Private_Key :: distinct [32]u8
Identity :: distinct [32]u8
Secret_Key :: distinct [32]u8
Challenge :: distinct [32]u8
Signature :: distinct [64]u8
Tag :: distinct [12 + 16]u8
Hash :: distinct [32]u8
Payload :: [64]u8

AAD: string : "gam"

split_crypt_tag :: proc(
	bytes: []u8,
	ln := int(~uint(0) >> 1),
) -> (
	^Tag,
	[]u8,
) {
	return auto_cast raw_data(bytes),
		bytes[size_of(Tag):][:min(ln, len(bytes) - size_of(Tag))]
}

encrypt :: proc(sk: ^Secret_Key, tag: ^Tag, text: []u8) {
	nbio.rand_bytes(tag[:12])
	ctx: aes.Context_GCM
	aes.init_gcm(&ctx, sk[:])
	aes.seal_gcm(&ctx, text, tag[12:], tag[:12], transmute([]u8)AAD, text)
}

decrypt :: proc(sk: ^Secret_Key, tag: ^Tag, ciphertext: []u8) -> bool {
	ctx: aes.Context_GCM
	aes.init_gcm(&ctx, sk[:])
	return aes.open_gcm(
		&ctx,
		ciphertext,
		tag[:12],
		transmute([]u8)AAD,
		ciphertext,
		tag[12:],
	)
}

Client_Hello :: struct {
	id:        Identity,
	x:         Identity,
	challenge: Challenge,
	payload:   Payload,
}

client_handshake_init :: proc(
	pk: ^Private_Key,
	xpk: ^Private_Key,
	res: ^Client_Hello,
) {
	expkey: ed.Private_Key
	ok := ed.private_key_set_bytes(&expkey, pk[:])
	assert(ok)

	id: ed.Public_Key
	ed.public_key_set_priv(&id, &expkey)

	nbio.rand_bytes(res.challenge[:])
	ed.public_key_bytes(&id, res.id[:])

	nbio.rand_bytes(xpk[:])
	x.scalarmult_basepoint(res.x[:], xpk[:])

	return
}

Server_Hello :: struct {
	id:        Identity,
	x:         Identity,
	challenge: Challenge,
	sig:       Signature,
	payload:   Payload,
}

server_handshake_init :: proc(
	pk: ^Private_Key,
	xpk: ^Private_Key,
	hello: ^Client_Hello,
	res: ^Server_Hello,
) {

	expkey: ed.Private_Key
	ok := ed.private_key_set_bytes(&expkey, pk[:])
	assert(ok)

	id: ed.Public_Key
	ed.public_key_set_priv(&id, &expkey)

	nbio.rand_bytes(res.challenge[:])
	ed.public_key_bytes(&id, res.id[:])

	nbio.rand_bytes(xpk[:])
	x.scalarmult_basepoint(res.x[:], xpk[:])

	sig_msg := Sig_Msg {
		client_challenge = hello.challenge,
		server_challenge = res.challenge,
		x                = res.x,
		payload          = res.payload,
	}

	sign_sig_msg(pk, sig_msg, &res.sig)

	return
}

Client_End_Hello :: struct {
	sig: Signature,
}

client_handshake_end :: proc(
	pk: ^Private_Key,
	xpk: ^Private_Key,
	ch: ^Client_Hello,
	sh: ^Server_Hello,
	res: ^Client_End_Hello,
	skres: ^Secret_Key,
) -> bool {

	server_sig_msg := Sig_Msg {
		client_challenge = ch.challenge,
		server_challenge = sh.challenge,
		x                = sh.x,
		payload          = sh.payload,
	}
	if !verify_sig_msg(&sh.id, server_sig_msg, &sh.sig) {
		return false
	}

	x.scalarmult(skres[:], xpk[:], sh.x[:])

	expkey: ed.Private_Key
	ok := ed.private_key_set_bytes(&expkey, pk[:])
	assert(ok)

	client_sig_msg := Sig_Msg {
		client_challenge = ch.challenge,
		server_challenge = sh.challenge,
		x                = ch.x,
		payload          = ch.payload,
	}
	sign_sig_msg(pk, client_sig_msg, &res.sig)

	return true
}

server_handshake_end :: proc(
	pk: ^Private_Key,
	xpk: ^Private_Key,
	ch: ^Client_Hello,
	sh: ^Server_Hello,
	seh: ^Client_End_Hello,
	res: ^Secret_Key,
) -> bool {

	id: ed.Public_Key
	ok := ed.public_key_set_bytes(&id, ch.id[:])
	assert(ok)

	sig_msg := Sig_Msg {
		client_challenge = ch.challenge,
		server_challenge = sh.challenge,
		x                = ch.x,
		payload          = ch.payload,
	}

	if !verify_sig_msg(&ch.id, sig_msg, &seh.sig) {
		return false
	}

	x.scalarmult(res[:], xpk[:], ch.x[:])

	return true
}

Content_Spec :: struct {
	hash:   Hash,
	length: int,
}

hash :: proc(content: []u8, out: ^Hash) {
	config_hash_ctx: blake2s.Context
	blake2s.init(&config_hash_ctx)
	blake2s.update(&config_hash_ctx, content)
	blake2s.final(&config_hash_ctx, out[:])
}

hash_prefix :: proc(h: ^Hash) -> Asset_ID {
	return (^Asset_ID)(h)^
}

content_spec_init :: proc(csp: ^Content_Spec, content: []u8) {
	hash(content, &csp.hash)
	csp.length = len(content)
}

content_spec_validate :: proc(csp: ^Content_Spec, content: []u8) -> bool {
	if csp.length != len(content) {
		return false
	}

	ref_spec: Content_Spec
	content_spec_init(&ref_spec, content)

	return csp.hash == ref_spec.hash
}

Sig_Msg :: struct {
	client_challenge: Challenge,
	server_challenge: Challenge,
	x:                Identity,
	payload:          Payload,
}

sign_sig_msg :: proc(pk: ^Private_Key, msg: any, sig: ^Signature) {
	expkey: ed.Private_Key
	ok := ed.private_key_set_bytes(&expkey, pk[:])
	assert(ok)

	bytes := reflect.as_bytes(msg)

	ed.sign(&expkey, bytes[:], sig[:])
}

verify_sig_msg :: proc(pk: ^Identity, msg: any, sig: ^Signature) -> bool {
	id: ed.Public_Key
	ok := ed.public_key_set_bytes(&id, pk[:])
	assert(ok)

	bytes := reflect.as_bytes(msg)

	return ed.verify(&id, bytes[:], sig[:])
}

private_key_generate :: proc(pk: ^Private_Key) {
	expkey: ed.Private_Key
	ok := ed.private_key_generate(&expkey)
	assert(ok)
	ed.private_key_bytes(&expkey, pk[:])
}

@(test)
test :: proc(t: ^testing.T) {
	cxpk: Private_Key
	cpk: Private_Key
	private_key_generate(&cpk)
	ch: Client_Hello
	client_handshake_init(&cpk, &cxpk, &ch)

	sxpk: Private_Key
	spk: Private_Key
	private_key_generate(&spk)
	sh: Server_Hello
	server_handshake_init(&spk, &sxpk, &ch, &sh)

	ceh: Client_End_Hello
	cpriv: Secret_Key
	cok := client_handshake_end(&cpk, &cxpk, &ch, &sh, &ceh, &cpriv)
	testing.expect(t, cok, "signature should match")

	spriv: Secret_Key
	sok := server_handshake_end(&spk, &sxpk, &ch, &sh, &ceh, &spriv)
	testing.expect(t, sok, "signature should match")

	testing.expect(t, cpriv == spriv, "private key should match")

	msg := "hello"
	bed := make([]u8, len(msg))
	defer delete(bed)
	copy(bed, msg)

	tag: Tag
	encrypt(&cpriv, &tag, bed)
	decrypt(&spriv, &tag, bed)
}
