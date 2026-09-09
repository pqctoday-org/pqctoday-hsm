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
 OSSLClassicMcEliece.cpp

 Classic McEliece (BSI TR-02102-1 §2.4.2) KEM implementation, backed by
 liboqs's C API (OQS_KEM_new/keypair/encaps/decaps/free) directly — see
 OSSLClassicMcEliece.h for why (D-2: no OpenSSL-EVP route exists).
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLClassicMcEliece.h"
#include "ClassicMcElieceParameters.h"
#include "ClassicMcEliecePublicKey.h"
#include "OSSLClassicMcElieceKeyPair.h"
#include "OSSLClassicMcEliecePublicKey.h"
#include "OSSLClassicMcEliecePrivateKey.h"
#include "../vendor_mechanisms.h"
#ifdef WITH_LIBOQS
#include <oqs/oqs.h>
#endif

// ─── liboqs name mapping ────────────────────────────────────────────────────

#ifdef WITH_LIBOQS
/*static*/ const char* OSSLClassicMcEliece::paramSetToOqsName(CK_ULONG ps)
{
	switch (ps)
	{
		case CKP_CLASSIC_MCELIECE_348864:   return OQS_KEM_alg_classic_mceliece_348864;
		case CKP_CLASSIC_MCELIECE_348864F:  return OQS_KEM_alg_classic_mceliece_348864f;
		case CKP_CLASSIC_MCELIECE_460896:   return OQS_KEM_alg_classic_mceliece_460896;
		case CKP_CLASSIC_MCELIECE_460896F:  return OQS_KEM_alg_classic_mceliece_460896f;
		case CKP_CLASSIC_MCELIECE_6688128:  return OQS_KEM_alg_classic_mceliece_6688128;
		case CKP_CLASSIC_MCELIECE_6688128F: return OQS_KEM_alg_classic_mceliece_6688128f;
		case CKP_CLASSIC_MCELIECE_6960119:  return OQS_KEM_alg_classic_mceliece_6960119;
		case CKP_CLASSIC_MCELIECE_6960119F: return OQS_KEM_alg_classic_mceliece_6960119f;
		case CKP_CLASSIC_MCELIECE_8192128:  return OQS_KEM_alg_classic_mceliece_8192128;
		case CKP_CLASSIC_MCELIECE_8192128F: return OQS_KEM_alg_classic_mceliece_8192128f;
		default:                            return NULL;
	}
}
#else
/*static*/ const char* OSSLClassicMcEliece::paramSetToOqsName(CK_ULONG /*ps*/)
{
	// Built without WITH_LIBOQS (e.g. the Emscripten wasm build, D-4) — no
	// liboqs algorithm names exist to map to.
	return NULL;
}
#endif

#ifdef WITH_LIBOQS
namespace {

// Thin RAII wrapper around liboqs's OQS_KEM* — the whole point of D-2's
// "one thin RAII wrapper selected by set name" design: this is the only
// place in the C++ engine that touches liboqs's C lifetime API directly.
class ScopedOqsKem
{
public:
	explicit ScopedOqsKem(const char* algName) : kem(OQS_KEM_new(algName)) { }
	~ScopedOqsKem() { if (kem != NULL) OQS_KEM_free(kem); }
	OQS_KEM* get() const { return kem; }
	bool valid() const { return kem != NULL; }

	// Non-copyable
	ScopedOqsKem(const ScopedOqsKem&) = delete;
	ScopedOqsKem& operator=(const ScopedOqsKem&) = delete;

private:
	OQS_KEM* kem;
};

} // anonymous namespace

// ─── KEM operations ───────────────────────────────────────────────────────────

bool OSSLClassicMcEliece::encapsulate(PublicKey* publicKey,
                                       ByteString& ciphertext,
                                       ByteString& sharedSecret)
{
	if (!publicKey->isOfType(OSSLClassicMcEliecePublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied for Classic McEliece encapsulate");
		return false;
	}

	ClassicMcEliecePublicKey* pk = (ClassicMcEliecePublicKey*)publicKey;
	const char* algName = paramSetToOqsName(pk->getParameterSet());
	if (algName == NULL)
	{
		ERROR_MSG("Unknown Classic McEliece parameter set %lu", pk->getParameterSet());
		return false;
	}

	ScopedOqsKem kem(algName);
	if (!kem.valid())
	{
		ERROR_MSG("liboqs OQS_KEM_new(%s) failed — algorithm disabled at build time?", algName);
		return false;
	}

	const ByteString& pkBytes = pk->getValue();
	if (pkBytes.size() != kem.get()->length_public_key)
	{
		ERROR_MSG("Classic McEliece public key length mismatch: have %lu, expected %zu",
		          (unsigned long)pkBytes.size(), kem.get()->length_public_key);
		return false;
	}

	ciphertext.resize(kem.get()->length_ciphertext);
	sharedSecret.resize(kem.get()->length_shared_secret);

	OQS_STATUS rv = OQS_KEM_encaps(kem.get(), &ciphertext[0], &sharedSecret[0], pkBytes.const_byte_str());
	if (rv != OQS_SUCCESS)
	{
		ERROR_MSG("OQS_KEM_encaps failed for %s", algName);
		return false;
	}

	return true;
}

bool OSSLClassicMcEliece::decapsulate(PrivateKey* privateKey,
                                       const ByteString& ciphertext,
                                       ByteString& sharedSecret)
{
	if (!privateKey->isOfType(OSSLClassicMcEliecePrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied for Classic McEliece decapsulate");
		return false;
	}

	ClassicMcEliecePrivateKey* sk = (ClassicMcEliecePrivateKey*)privateKey;
	const char* algName = paramSetToOqsName(sk->getParameterSet());
	if (algName == NULL)
	{
		ERROR_MSG("Unknown Classic McEliece parameter set %lu", sk->getParameterSet());
		return false;
	}

	ScopedOqsKem kem(algName);
	if (!kem.valid())
	{
		ERROR_MSG("liboqs OQS_KEM_new(%s) failed — algorithm disabled at build time?", algName);
		return false;
	}

	const ByteString& skBytes = sk->getValue();
	if (skBytes.size() != kem.get()->length_secret_key)
	{
		ERROR_MSG("Classic McEliece secret key length mismatch: have %lu, expected %zu",
		          (unsigned long)skBytes.size(), kem.get()->length_secret_key);
		return false;
	}
	if (ciphertext.size() != kem.get()->length_ciphertext)
	{
		ERROR_MSG("Classic McEliece ciphertext length mismatch: have %lu, expected %zu",
		          (unsigned long)ciphertext.size(), kem.get()->length_ciphertext);
		return false;
	}

	sharedSecret.resize(kem.get()->length_shared_secret);

	// FIPS-203-style implicit rejection is Classic McEliece's own design
	// too (the OQS reference always returns OQS_SUCCESS and a
	// well-formed-looking but wrong shared secret for a bit-flipped
	// ciphertext, rather than an error — verified directly, P0-5) — a
	// non-success return here is a genuine liboqs-level failure (e.g. a
	// malformed length passed through despite the checks above), not a
	// tampered-ciphertext signal, so it is reported as an error rather
	// than silently producing a secret.
	OQS_STATUS rv = OQS_KEM_decaps(kem.get(), &sharedSecret[0], ciphertext.const_byte_str(), skBytes.const_byte_str());
	if (rv != OQS_SUCCESS)
	{
		ERROR_MSG("OQS_KEM_decaps failed for %s", algName);
		return false;
	}

	return true;
}

// ─── Sign / Verify / Encrypt / Decrypt (not applicable) ──────────────────────

bool OSSLClassicMcEliece::sign(PrivateKey* /*pk*/, const ByteString& /*data*/,
                     ByteString& /*sig*/, const AsymMech::Type /*mech*/,
                     const void* /*param*/, const size_t /*paramLen*/)
{
	ERROR_MSG("Classic McEliece does not support signing");
	return false;
}

bool OSSLClassicMcEliece::signInit(PrivateKey* /*pk*/, const AsymMech::Type /*mech*/,
                          const void* /*param*/, const size_t /*paramLen*/)
{
	ERROR_MSG("Classic McEliece does not support signing");
	return false;
}

bool OSSLClassicMcEliece::signUpdate(const ByteString& /*data*/)
{
	ERROR_MSG("Classic McEliece does not support signing");
	return false;
}

bool OSSLClassicMcEliece::signFinal(ByteString& /*sig*/)
{
	ERROR_MSG("Classic McEliece does not support signing");
	return false;
}

bool OSSLClassicMcEliece::verify(PublicKey* /*pk*/, const ByteString& /*data*/,
                       const ByteString& /*sig*/, const AsymMech::Type /*mech*/,
                       const void* /*param*/, const size_t /*paramLen*/)
{
	ERROR_MSG("Classic McEliece does not support verification");
	return false;
}

bool OSSLClassicMcEliece::verifyInit(PublicKey* /*pk*/, const AsymMech::Type /*mech*/,
                            const void* /*param*/, const size_t /*paramLen*/)
{
	ERROR_MSG("Classic McEliece does not support verification");
	return false;
}

bool OSSLClassicMcEliece::verifyUpdate(const ByteString& /*data*/)
{
	ERROR_MSG("Classic McEliece does not support verification");
	return false;
}

bool OSSLClassicMcEliece::verifyFinal(const ByteString& /*sig*/)
{
	ERROR_MSG("Classic McEliece does not support verification");
	return false;
}

bool OSSLClassicMcEliece::encrypt(PublicKey* /*pk*/, const ByteString& /*data*/,
                         ByteString& /*enc*/, const AsymMech::Type /*pad*/)
{
	ERROR_MSG("Classic McEliece does not support encryption");
	return false;
}

bool OSSLClassicMcEliece::decrypt(PrivateKey* /*pk*/, const ByteString& /*enc*/,
                         ByteString& /*data*/, const AsymMech::Type /*pad*/)
{
	ERROR_MSG("Classic McEliece does not support decryption");
	return false;
}

bool OSSLClassicMcEliece::deriveKey(SymmetricKey** /*ppKey*/, PublicKey* /*pub*/, PrivateKey* /*priv*/)
{
	ERROR_MSG("Classic McEliece does not support key derivation (use encapsulate/decapsulate)");
	return false;
}

// ─── Key factory ─────────────────────────────────────────────────────────────

bool OSSLClassicMcEliece::generateKeyPair(AsymmetricKeyPair** ppKeyPair,
                                           AsymmetricParameters* parameters, RNG* /*rng*/)
{
	if (ppKeyPair == NULL || parameters == NULL) return false;

	if (!parameters->areOfType(ClassicMcElieceParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for Classic McEliece key generation");
		return false;
	}

	ClassicMcElieceParameters* params = (ClassicMcElieceParameters*)parameters;
	CK_ULONG ps = params->getParameterSet();
	const char* algName = paramSetToOqsName(ps);
	if (algName == NULL)
	{
		ERROR_MSG("Unknown Classic McEliece parameter set %lu", ps);
		return false;
	}

	ScopedOqsKem kem(algName);
	if (!kem.valid())
	{
		ERROR_MSG("liboqs OQS_KEM_new(%s) failed — algorithm disabled at build time?", algName);
		return false;
	}

	ByteString pkBytes, skBytes;
	pkBytes.resize(kem.get()->length_public_key);
	skBytes.resize(kem.get()->length_secret_key);

	// liboqs's own CI shows leak-test failures for 460896/460896f/6960119/
	// 6960119f under clang -O2/-O3 (implementation plan §1.1) — tracked as
	// a Phase 2 exit criterion (ASan/LSan run, §5.4), not fixed here; the
	// keypair generation call itself is otherwise identical for all 10 sets.
	OQS_STATUS rv = OQS_KEM_keypair(kem.get(), &pkBytes[0], &skBytes[0]);
	if (rv != OQS_SUCCESS)
	{
		ERROR_MSG("OQS_KEM_keypair failed for %s", algName);
		return false;
	}

	OSSLClassicMcElieceKeyPair* kp = new OSSLClassicMcElieceKeyPair();
	((ClassicMcEliecePublicKey*)kp->getPublicKey())->setParameterSet(ps);
	((ClassicMcEliecePublicKey*)kp->getPublicKey())->setValue(pkBytes);
	((ClassicMcEliecePrivateKey*)kp->getPrivateKey())->setParameterSet(ps);
	((ClassicMcEliecePrivateKey*)kp->getPrivateKey())->setValue(skBytes);

	*ppKeyPair = kp;
	return true;
}

#else // !WITH_LIBOQS

// Built without WITH_LIBOQS (the Emscripten wasm build, D-4) — the C++ wasm
// engine keeps not advertising Classic McEliece at all (SoftHSM_slots.cpp
// never lists these mechanisms there), so these three bodies are never
// actually reached in that build; they exist so the class remains
// well-formed (AsymAlgo::CLASSICMCELIECE is still a valid enum value, and
// OSSLCryptoFactory::getAsymmetricAlgorithm still unconditionally
// instantiates OSSLClassicMcEliece for it) rather than requiring the
// factory dispatch itself to be conditionally compiled.

bool OSSLClassicMcEliece::encapsulate(PublicKey* /*publicKey*/,
                                       ByteString& /*ciphertext*/,
                                       ByteString& /*sharedSecret*/)
{
	ERROR_MSG("Classic McEliece unavailable: built without WITH_LIBOQS");
	return false;
}

bool OSSLClassicMcEliece::decapsulate(PrivateKey* /*privateKey*/,
                                       const ByteString& /*ciphertext*/,
                                       ByteString& /*sharedSecret*/)
{
	ERROR_MSG("Classic McEliece unavailable: built without WITH_LIBOQS");
	return false;
}

bool OSSLClassicMcEliece::generateKeyPair(AsymmetricKeyPair** /*ppKeyPair*/,
                                           AsymmetricParameters* /*parameters*/, RNG* /*rng*/)
{
	ERROR_MSG("Classic McEliece unavailable: built without WITH_LIBOQS");
	return false;
}

#endif // WITH_LIBOQS

// ─── The rest of the key factory needs no liboqs at all — always compiled ────

unsigned long OSSLClassicMcEliece::getMinKeySize()
{
	// Public-key BYTES (not bits — matches C_GetMechanismInfo's convention
	// for this mechanism family, see SoftHSM_slots.cpp; unlike OSSLMLKEM's
	// getMinKeySize/getMaxKeySize, which report security-strength bits
	// on this same pair of virtuals — a pre-existing inconsistency in this
	// engine this class deliberately does not repeat).
	return 261120;  // mceliece348864
}

unsigned long OSSLClassicMcEliece::getMaxKeySize()
{
	return 1357824;  // mceliece8192128 / mceliece8192128f
}

bool OSSLClassicMcEliece::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	if (ppKeyPair == NULL || serialisedData.size() == 0) return false;

	ByteString dPub  = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLClassicMcElieceKeyPair* kp = new OSSLClassicMcElieceKeyPair();
	bool rv = true;
	if (!((ClassicMcEliecePublicKey*)kp->getPublicKey())->deserialise(dPub))    rv = false;
	if (!((ClassicMcEliecePrivateKey*)kp->getPrivateKey())->deserialise(dPriv)) rv = false;
	if (!rv) { delete kp; return false; }
	*ppKeyPair = kp;
	return true;
}

bool OSSLClassicMcEliece::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	if (ppPublicKey == NULL || serialisedData.size() == 0) return false;
	OSSLClassicMcEliecePublicKey* pub = new OSSLClassicMcEliecePublicKey();
	if (!pub->deserialise(serialisedData)) { delete pub; return false; }
	*ppPublicKey = pub;
	return true;
}

bool OSSLClassicMcEliece::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	if (ppPrivateKey == NULL || serialisedData.size() == 0) return false;
	OSSLClassicMcEliecePrivateKey* priv = new OSSLClassicMcEliecePrivateKey();
	if (!priv->deserialise(serialisedData)) { delete priv; return false; }
	*ppPrivateKey = priv;
	return true;
}

bool OSSLClassicMcEliece::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	if (ppParams == NULL || serialisedData.size() == 0) return false;
	ClassicMcElieceParameters* params = new ClassicMcElieceParameters();
	if (!params->deserialise(serialisedData)) { delete params; return false; }
	*ppParams = params;
	return true;
}

PublicKey* OSSLClassicMcEliece::newPublicKey()
{
	return (PublicKey*) new OSSLClassicMcEliecePublicKey();
}

PrivateKey* OSSLClassicMcEliece::newPrivateKey()
{
	return (PrivateKey*) new OSSLClassicMcEliecePrivateKey();
}

AsymmetricParameters* OSSLClassicMcEliece::newParameters()
{
	return (AsymmetricParameters*) new ClassicMcElieceParameters();
}
