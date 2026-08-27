/*
 * SoftHSMv3 HD Wallet Derivation (BIP32 / SLIP-0010)
 */

#include "HDWalletDerivation.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

// secp256k1 OID
const std::string OID_SECP256K1 = "06052B8104000A";
// p256 OID
const std::string OID_P256 = "06082A8648CE3D030107";
// ed25519 OID
const std::string OID_ED25519 = "06032B6570";

bool HDWalletDerivation::hmacSha512(const ByteString& key, const ByteString& data, ByteString& outMac) {
    size_t macLen = 64;
    unsigned char mac[64];
    
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MAC *mac_alg = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac_alg) return false;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac_alg);
    if (!ctx) { EVP_MAC_free(mac_alg); return false; }
    
    OSSL_PARAM params[2], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string("digest", (char*)"SHA512", 0);
    *p = OSSL_PARAM_construct_end();
    
    if (EVP_MAC_init(ctx, key.const_byte_str(), key.size(), params) <= 0 ||
        EVP_MAC_update(ctx, data.const_byte_str(), data.size()) <= 0 ||
        EVP_MAC_final(ctx, mac, &macLen, sizeof(mac)) <= 0) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac_alg);
        return false;
    }
    
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac_alg);
#else
    if (!HMAC(EVP_sha512(), key.const_byte_str(), key.size(), data.const_byte_str(), data.size(), mac, &macLen)) {
        return false;
    }
#endif

    outMac = ByteString(mac, macLen);
    return true;
}

bool HDWalletDerivation::deriveMasterNode(const ByteString& seed, const std::string& curveOid, ByteString& outPrivKey, ByteString& outChainCode) {
    ByteString masterKey;
    if (curveOid == OID_SECP256K1) {
        masterKey = ByteString((const unsigned char*)"Bitcoin seed", 12);
    } else if (curveOid == OID_P256) {
        masterKey = ByteString((const unsigned char*)"Nist256p1 seed", 14);
    } else if (curveOid == OID_ED25519) {
        masterKey = ByteString((const unsigned char*)"ed25519 seed", 12);
    } else {
        return false;
    }
    
    ByteString macOut;
    if (!hmacSha512(masterKey, seed, macOut) || macOut.size() != 64) {
        return false;
    }
    
    outPrivKey = macOut.substr(0, 32);
    outChainCode = macOut.substr(32, 32);
    return true;
}

bool HDWalletDerivation::deriveChildNode(const ByteString& parentPriv, const ByteString& parentChainCode, CK_ULONG index, bool hardened, const std::string& curveOid, ByteString& outPrivKey, ByteString& outChainCode) {
    CK_ULONG actualIndex = hardened ? (index | 0x80000000) : index;
    ByteString data;
    
    if (curveOid == OID_ED25519) {
        if (!hardened) return false; // ed25519 SLIP10 requires hardened derivation
        data += ByteString("00");
        data += parentPriv;
        ByteString idxStr; idxStr.resize(4);
        idxStr[0] = (actualIndex >> 24) & 0xFF;
        idxStr[1] = (actualIndex >> 16) & 0xFF;
        idxStr[2] = (actualIndex >> 8) & 0xFF;
        idxStr[3] = actualIndex & 0xFF;
        data += idxStr;
        
        ByteString macOut;
        if (!hmacSha512(parentChainCode, data, macOut) || macOut.size() != 64) return false;
        
        outPrivKey = macOut.substr(0, 32);
        outChainCode = macOut.substr(32, 32);
        return true;
    }
    
    // For secp256k1 and p256
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *il = BN_new();
    BIGNUM *parentSecret = BN_new();
    BIGNUM *childSecret = BN_new();
    
    int curveNid = (curveOid == OID_SECP256K1) ? NID_secp256k1 : NID_X9_62_prime256v1;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(curveNid);
    if (!group || !ctx || !il || !parentSecret || !childSecret) {
        if(group) EC_GROUP_free(group);
        if(ctx) BN_CTX_free(ctx);
        if(il) BN_free(il);
        if(parentSecret) BN_free(parentSecret);
        if(childSecret) BN_free(childSecret);
        return false;
    }
    
    BN_bin2bn(parentPriv.const_byte_str(), parentPriv.size(), parentSecret);
    
    if (hardened) {
        data += ByteString("00");
        data += parentPriv;
    } else {
        // Calculate public key point
        EC_POINT *pubPoint = EC_POINT_new(group);
        EC_POINT_mul(group, pubPoint, parentSecret, NULL, NULL, ctx);
        size_t len = EC_POINT_point2oct(group, pubPoint, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx);
        ByteString pubComp; pubComp.resize(len);
        EC_POINT_point2oct(group, pubPoint, POINT_CONVERSION_COMPRESSED, pubComp.byte_str(), len, ctx);
        data += pubComp;
        EC_POINT_free(pubPoint);
    }
    
    ByteString idxStr; idxStr.resize(4);
    idxStr[0] = (actualIndex >> 24) & 0xFF;
    idxStr[1] = (actualIndex >> 16) & 0xFF;
    idxStr[2] = (actualIndex >> 8) & 0xFF;
    idxStr[3] = actualIndex & 0xFF;
    data += idxStr;
    
    ByteString macOut;
    if (!hmacSha512(parentChainCode, data, macOut) || macOut.size() != 64) {
        EC_GROUP_free(group); BN_CTX_free(ctx); BN_free(il); BN_free(parentSecret); BN_free(childSecret);
        return false;
    }
    
    outChainCode = macOut.substr(32, 32);
    BN_bin2bn(macOut.substr(0, 32).const_byte_str(), 32, il);
    
    // Check if il >= n or childSecret == 0
    const BIGNUM *order = EC_GROUP_get0_order(group);
    if (BN_cmp(il, order) >= 0) {
        EC_GROUP_free(group); BN_CTX_free(ctx); BN_free(il); BN_free(parentSecret); BN_free(childSecret);
        return false;
    }
    
    // childSecret = (il + parentSecret) mod n
    BN_mod_add(childSecret, il, parentSecret, order, ctx);
    if (BN_is_zero(childSecret)) {
        EC_GROUP_free(group); BN_CTX_free(ctx); BN_free(il); BN_free(parentSecret); BN_free(childSecret);
        return false;
    }
    
    outPrivKey.resize(32);
    BN_bn2binpad(childSecret, outPrivKey.byte_str(), 32);
    
    EC_GROUP_free(group); BN_CTX_free(ctx); BN_free(il); BN_free(parentSecret); BN_free(childSecret);
    return true;
}
