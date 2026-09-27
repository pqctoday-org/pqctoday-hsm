/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 OSSLEDPublicKey.cpp

 OpenSSL EDDSA public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_EDDSA
#include "log.h"
#include "DerUtil.h"
#include "OSSLEDPublicKey.h"
#include "OSSLUtil.h"
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <string.h>
#include <vector>
#include <openssl/err.h>

#define X25519_KEYLEN	32
#define X448_KEYLEN	56
#define ED448_KEYLEN	57

#define PREFIXLEN	12

// Prefixes
const unsigned char x25519_prefix[] = {
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
	0x6e, 0x03, 0x21, 0x00
};

const unsigned char x448_prefix[] = {
	0x30, 0x42, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
	0x6f, 0x03, 0x39, 0x00
};

const unsigned char ed25519_prefix[] = {
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
	0x70, 0x03, 0x21, 0x00
};

const unsigned char ed448_prefix[] = {
	0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
	0x71, 0x03, 0x3a, 0x00
};

// Constructors
OSSLEDPublicKey::OSSLEDPublicKey()
{
	nid = NID_undef;
	pkey = NULL;
}

OSSLEDPublicKey::OSSLEDPublicKey(const EVP_PKEY* inPKEY)
{
	nid = NID_undef;
	pkey = NULL;

	setFromOSSL(inPKEY);
}

// Destructor
OSSLEDPublicKey::~OSSLEDPublicKey()
{
	EVP_PKEY_free(pkey);
}

// The type
/*static*/ const char* OSSLEDPublicKey::type = "OpenSSL EDDSA Public Key";

// Get the base point order length
unsigned long OSSLEDPublicKey::getOrderLength() const
{
	if (nid == NID_ED25519)
		return X25519_KEYLEN;
	if (nid == NID_ED448)
		return ED448_KEYLEN;
	return 0;
}

// Set from OpenSSL representation
// Returns false when the key could not be populated.
//
// CHANGED FROM void 2026-08-10. Every early return below leaves the key
// object EMPTY, and because this reported nothing, OSSLEDDSA::generateKeyPair
// and OSSLEDPrivateKey::PKCS8Decode both went on to return success with an
// unpopulated key. The failure then resurfaced somewhere unrelated as a
// generic non-CKR_OK, which is why the intermittent p11test EdDSA failures
// pointed at derive and sign when both were actually dying in KEYGEN.
bool OSSLEDPublicKey::setFromOSSL(const EVP_PKEY* inPKEY)
{
	nid = EVP_PKEY_id(inPKEY);
	if (nid == NID_undef)
	{
		return false;
	}
	ByteString inEC = OSSL::oid2ByteString(nid);
	EDPublicKey::setEC(inEC);

	// i2d_PUBKEY incorrectly does not const the key argument?!
        EVP_PKEY* key = const_cast<EVP_PKEY*>(inPKEY);
	int len = i2d_PUBKEY(key, NULL);
	if (len <= 0)
	{
		ERROR_MSG("Could not encode EDDSA public key");
		return false;
	}
	ByteString der;
	der.resize(len);
	unsigned char *p = &der[0];
	i2d_PUBKEY(key, &p);
	ByteString raw;
	switch (nid) {
	case NID_X25519:
	case NID_ED25519:
		if (len != (X25519_KEYLEN + PREFIXLEN))
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X25519_KEYLEN + PREFIXLEN, len);
			return false;
		}
		raw.resize(X25519_KEYLEN);
		memcpy(&raw[0], &der[PREFIXLEN], X25519_KEYLEN);
		break;
	case NID_X448:
		if (len != (X448_KEYLEN + PREFIXLEN))
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X448_KEYLEN + PREFIXLEN, len);
			return false;
		}
		raw.resize(X448_KEYLEN);
		memcpy(&raw[0], &der[PREFIXLEN], X448_KEYLEN);
		break;
	case NID_ED448:
		if (len != (ED448_KEYLEN + PREFIXLEN))
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu",
				  ED448_KEYLEN + PREFIXLEN, len);
			return false;
		}
		raw.resize(ED448_KEYLEN);
		memcpy(&raw[0], &der[PREFIXLEN], ED448_KEYLEN);
		break;
	default:
		return false;
	}
	// E4 (2026-08-13). PKCS#11 v3.2's Edwards and Montgomery public-key tables
	// define this attribute as "Public key bytes in little endian order as
	// defined in [RFC 8032]/[RFC 7748]" — deliberately different wording from
	// the Weierstrass table's "DER-encoding of ANSI X9.62 ECPoint value Q".
	// That difference IS the specification, so the DER OCTET STRING wrapper
	// this used to apply (34 bytes for Ed25519 where 32 are defined) is gone.
	// createOSSLKey() below still accepts the wrapped form on input.
	setA(raw);

	return true;
}

// Check if the key is of the given type
bool OSSLEDPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the EDDSA public key components
void OSSLEDPublicKey::setEC(const ByteString& inEC)
{
	EDPublicKey::setEC(inEC);

	nid = OSSL::byteString2oid(inEC);
	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

void OSSLEDPublicKey::setA(const ByteString& inA)
{
	EDPublicKey::setA(inA);

	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
}

// Retrieve the OpenSSL representation of the key
EVP_PKEY* OSSLEDPublicKey::getOSSLKey()
{
	if (pkey == NULL) createOSSLKey();

	return pkey;
}

// ── Edwards public-key validation (RFC 8032) ────────────────────────────────
// Twisted Edwards a*x^2 + y^2 = 1 + d*x^2*y^2 over GF(p). Ed25519: a = -1,
// d = -121665/121666, p = 2^255 - 19. Ed448: a = 1, d = -39081,
// p = 2^448 - 2^224 - 1. Both have a non-square d (and a square a), so the
// unified addition below is complete: no exceptional inputs, the identity
// included. Extended coordinates (X:Y:Z:T), x = X/Z, y = Y/Z, xy = T/Z
// (Hisil-Wong-Carter-Dawson 2008, "add-2008-hwcd").
namespace {

struct EdCurve
{
	BIGNUM* p; BIGNUM* d; BIGNUM* order; bool aIsMinusOne;
	size_t len;          // encoding length
	int yBits;           // bits of y in the encoding
};

struct EdPoint { BIGNUM *X, *Y, *Z, *T; };

bool edNew(EdPoint& P)
{
	P.X = BN_new(); P.Y = BN_new(); P.Z = BN_new(); P.T = BN_new();
	return P.X && P.Y && P.Z && P.T;
}
void edFree(EdPoint& P) { BN_free(P.X); BN_free(P.Y); BN_free(P.Z); BN_free(P.T); }

// R = P + Q (R may alias P or Q).
bool edAdd(const EdCurve& c, EdPoint& R, const EdPoint& P, const EdPoint& Q, BN_CTX* ctx)
{
	BN_CTX_start(ctx);
	BIGNUM *A = BN_CTX_get(ctx), *B = BN_CTX_get(ctx), *C = BN_CTX_get(ctx), *D = BN_CTX_get(ctx);
	BIGNUM *E = BN_CTX_get(ctx), *F = BN_CTX_get(ctx), *G = BN_CTX_get(ctx), *H = BN_CTX_get(ctx);
	BIGNUM *t1 = BN_CTX_get(ctx), *t2 = BN_CTX_get(ctx);
	bool ok = t2 != NULL &&
		BN_mod_mul(A, P.X, Q.X, c.p, ctx) &&
		BN_mod_mul(B, P.Y, Q.Y, c.p, ctx) &&
		BN_mod_mul(C, P.T, Q.T, c.p, ctx) && BN_mod_mul(C, C, c.d, c.p, ctx) &&
		BN_mod_mul(D, P.Z, Q.Z, c.p, ctx) &&
		BN_mod_add(t1, P.X, P.Y, c.p, ctx) && BN_mod_add(t2, Q.X, Q.Y, c.p, ctx) &&
		BN_mod_mul(E, t1, t2, c.p, ctx) && BN_mod_sub(E, E, A, c.p, ctx) && BN_mod_sub(E, E, B, c.p, ctx) &&
		BN_mod_sub(F, D, C, c.p, ctx) &&
		BN_mod_add(G, D, C, c.p, ctx) &&
		// H = B - a*A
		(c.aIsMinusOne ? BN_mod_add(H, B, A, c.p, ctx) : BN_mod_sub(H, B, A, c.p, ctx)) &&
		BN_mod_mul(R.X, E, F, c.p, ctx) &&
		BN_mod_mul(R.Y, G, H, c.p, ctx) &&
		BN_mod_mul(R.T, E, H, c.p, ctx) &&
		BN_mod_mul(R.Z, F, G, c.p, ctx);
	BN_CTX_end(ctx);
	return ok;
}

bool edIsIdentity(const EdCurve& c, const EdPoint& P, BN_CTX* ctx)
{
	BN_CTX_start(ctx);
	BIGNUM* t = BN_CTX_get(ctx);
	bool id = t != NULL && BN_is_zero(P.X) && BN_mod_sub(t, P.Y, P.Z, c.p, ctx) && BN_is_zero(t);
	BN_CTX_end(ctx);
	return id;
}

// RFC 8032 §5.1.3 / §5.2.3 strict decoding to (x, y), then the subgroup test.
bool edValidate(const EdCurve& c, const unsigned char* enc, BN_CTX* ctx)
{
	// Little-endian encoding: y in the low yBits, x's sign in the top bit.
	std::vector<unsigned char> be(c.len);
	for (size_t i = 0; i < c.len; i++) be[i] = enc[c.len - 1 - i];
	const int sign = (enc[c.len - 1] >> 7) & 1;
	be[0] &= 0x7f;
	// Ed448: the last byte carries only the sign bit; its low 7 bits must be 0.
	if (c.len == 57 && (enc[56] & 0x7f) != 0) return false;

	BN_CTX_start(ctx);
	BIGNUM *y = BN_CTX_get(ctx), *yy = BN_CTX_get(ctx), *u = BN_CTX_get(ctx), *v = BN_CTX_get(ctx);
	BIGNUM *x2 = BN_CTX_get(ctx), *x = BN_CTX_get(ctx), *chk = BN_CTX_get(ctx);
	EdPoint Q, R;
	Q.X = Q.Y = Q.Z = Q.T = R.X = R.Y = R.Z = R.T = NULL;
	bool ok = false;
	do
	{
		if (chk == NULL || BN_bin2bn(be.data(), (int)c.len, y) == NULL) break;
		if (BN_cmp(y, c.p) >= 0) break;                          // non-canonical y
		// x^2 = (y^2 - 1) / (d*y^2 - a)
		if (!BN_mod_sqr(yy, y, c.p, ctx) || !BN_sub(u, yy, BN_value_one()) ||
		    !BN_nnmod(u, u, c.p, ctx) || !BN_mod_mul(v, c.d, yy, c.p, ctx)) break;
		if (c.aIsMinusOne ? !BN_mod_add(v, v, BN_value_one(), c.p, ctx)
		                  : !BN_mod_sub(v, v, BN_value_one(), c.p, ctx)) break;
		if (BN_mod_inverse(v, v, c.p, ctx) == NULL || !BN_mod_mul(x2, u, v, c.p, ctx)) break;
		if (BN_is_zero(x2))
		{
			if (sign) break;                                      // x = 0 with sign 1
			BN_zero(x);
		}
		else
		{
			if (BN_mod_sqrt(x, x2, c.p, ctx) == NULL) { ERR_clear_error(); break; }
			if (!BN_mod_sqr(chk, x, c.p, ctx) || BN_cmp(chk, x2) != 0) break;   // not on curve
			if (BN_is_odd(x) != sign && !BN_sub(x, c.p, x)) break;
		}
		if (!edNew(Q) || !edNew(R)) break;
		if (!BN_copy(Q.X, x) || !BN_copy(Q.Y, y) || !BN_one(Q.Z) || !BN_mod_mul(Q.T, x, y, c.p, ctx)) break;
		if (edIsIdentity(c, Q, ctx)) break;                       // the identity itself
		// R = L*Q, left-to-right double-and-add.
		BN_zero(R.X); BN_one(R.Y); BN_one(R.Z); BN_zero(R.T);
		bool step = true;
		for (int i = BN_num_bits(c.order) - 1; i >= 0 && step; i--)
		{
			step = edAdd(c, R, R, R, ctx);
			if (step && BN_is_bit_set(c.order, i)) step = edAdd(c, R, R, Q, ctx);
		}
		ok = step && edIsIdentity(c, R, ctx);
	} while (false);
	if (Q.X) edFree(Q);
	if (R.X) edFree(R);
	BN_CTX_end(ctx);
	return ok;
}

} // namespace

bool OSSLEDPublicKey::isInPrimeOrderSubgroup()
{
	EVP_PKEY* key = getOSSLKey();
	if (key == NULL) return false;
	const int id = EVP_PKEY_id(key);
	if (id != NID_ED25519 && id != NID_ED448) return false;
	unsigned char enc[57];
	size_t encLen = sizeof(enc);
	if (EVP_PKEY_get_raw_public_key(key, enc, &encLen) != 1) return false;

	EdCurve c;
	c.p = BN_new(); c.d = BN_new(); c.order = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	bool ok = false;
	if (c.p && c.d && c.order && ctx)
	{
		bool setup;
		if (id == NID_ED25519)
		{
			c.aIsMinusOne = true; c.len = 32; c.yBits = 255;
			// d = -121665 / 121666 mod p
			BIGNUM* den = BN_new();
			setup = den != NULL &&
				BN_hex2bn(&c.p, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed") &&
				BN_hex2bn(&c.order, "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed") &&
				BN_set_word(c.d, 121665) && BN_sub(c.d, c.p, c.d) &&
				BN_set_word(den, 121666) && BN_mod_inverse(den, den, c.p, ctx) != NULL &&
				BN_mod_mul(c.d, c.d, den, c.p, ctx);
			BN_free(den);
		}
		else
		{
			c.aIsMinusOne = false; c.len = 57; c.yBits = 448;
			setup =
				BN_hex2bn(&c.p, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff") &&
				BN_hex2bn(&c.order, "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3") &&
				BN_set_word(c.d, 39081) && BN_sub(c.d, c.p, c.d);
		}
		ok = setup && encLen == c.len && edValidate(c, enc, ctx);
	}
	BN_free(c.p); BN_free(c.d); BN_free(c.order);
	BN_CTX_free(ctx);
	return ok;
}

// Create the OpenSSL representation of the key
void OSSLEDPublicKey::createOSSLKey()
{
	if (pkey != NULL) return;

	ByteString der;
	// Tolerant reader: the bare RFC 8032 / RFC 7748 bytes are what this engine
	// now stores and what §6.3.17 requires a token to accept, but a DER OCTET
	// STRING wrapper — this engine's own pre-2026-08-13 encoding, and what the
	// spec's "MAY, in addition, support ... DER-encoded ECPoint" allows — must
	// keep working. Prefer the bare form; unwrap only if that is the wrong size.
	size_t expected = 0;
	switch (nid) {
	case NID_X25519:
	case NID_ED25519: expected = X25519_KEYLEN; break;
	case NID_X448:    expected = X448_KEYLEN;   break;
	case NID_ED448:   expected = ED448_KEYLEN;  break;
	default: break;
	}
	ByteString raw = a;
	if (expected != 0 && raw.size() != expected)
	{
		ByteString unwrapped = DERUTIL::octet2Raw(a);
		if (unwrapped.size() == expected) raw = unwrapped;
	}
	size_t len = raw.size();
	if (len == 0) return;

	switch (nid) {
	case NID_X25519:
		if (len != X25519_KEYLEN)
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X25519_KEYLEN, len);
			return;
		}
		der.resize(PREFIXLEN + X25519_KEYLEN);
		memcpy(&der[0], x25519_prefix, PREFIXLEN);
		memcpy(&der[PREFIXLEN], raw.const_byte_str(), X25519_KEYLEN);
		break;
	case NID_ED25519:
		if (len != X25519_KEYLEN)
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X25519_KEYLEN, len);
			return;
		}
		der.resize(PREFIXLEN + X25519_KEYLEN);
		memcpy(&der[0], ed25519_prefix, PREFIXLEN);
		memcpy(&der[PREFIXLEN], raw.const_byte_str(), X25519_KEYLEN);
		break;
	case NID_X448:
		if (len != X448_KEYLEN)
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", X448_KEYLEN, len);
			return;
		}
		der.resize(PREFIXLEN + X448_KEYLEN);
		memcpy(&der[0], x448_prefix, PREFIXLEN);
		memcpy(&der[PREFIXLEN], raw.const_byte_str(), X448_KEYLEN);
		break;
	case NID_ED448:
		if (len != ED448_KEYLEN)
		{
			ERROR_MSG("Invalid size. Expected: %lu, Actual: %lu", ED448_KEYLEN, len);
			return;
		}
		der.resize(PREFIXLEN + ED448_KEYLEN);
		memcpy(&der[0], ed448_prefix, PREFIXLEN);
		memcpy(&der[PREFIXLEN], raw.const_byte_str(), ED448_KEYLEN);
		break;
	default:
		return;
	}
	const unsigned char *p = &der[0];
	pkey = d2i_PUBKEY(NULL, &p, (long)der.size());
}
#endif
