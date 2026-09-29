// Kitchen sink: a single-shot correctness pass over every module covered by
// this library's other examples - Random, Hash, AES (ECB/CBC/CTR), ChaCha20
// (stream), ChaCha20-Poly1305 (AEAD, skipped if disabled), Ed25519, X25519
// (paired with ChaCha20-Poly1305, same as the X25519_ChachaPoly example),
// ECDSA (secp256r1), RSA-2048 (skipped if disabled), and HKDF+HMAC (skipped
// if disabled).
//
// Unlike the individual examples, nothing here loops for a second to measure
// throughput, and nothing halts on failure - each section prints OK/FAIL (or
// VALID/INVALID) and the sketch moves on, so one broken section doesn't hide
// the results of the rest.

#include <Adafruit_nRFCrypto.h>
#include <hexdump.h>  // https://github.com/Kongduino/hexdump

nRFCrypto_AES aes;

#if NRFCRYPTO_WITH_CHACHA
nRFCrypto_Chacha chacha;
nRFCrypto_ChachaPoly cp;
#endif

nRFCrypto_Ed25519 ed25519;
nRFCrypto_X25519 aliceX, bobX;
nRFCrypto_ECC_PrivateKey ecdsaPriv;
nRFCrypto_ECC_PublicKey ecdsaPub;

#if NRFCRYPTO_WITH_HKDF_HMAC
nRFCrypto_HMAC hmac;
#endif

#if NRFCRYPTO_WITH_RSA
nRFCrypto_RSA_PublicKey rsaPub;
nRFCrypto_RSA_PrivateKey rsaPriv;

// Demo-only RSA-2048 key pair (not for production use) - see RSA_Sign_Verify
// for how this was generated (openssl genrsa, N/D/E extracted as raw bytes).
static const uint8_t rsaModulus[256] = {
  0xA5,
  0x2F,
  0xE9,
  0x71,
  0x3A,
  0xDA,
  0xB2,
  0xA1,
  0x7E,
  0x9F,
  0xA5,
  0x4B,
  0x04,
  0xB5,
  0xC3,
  0x18,
  0x39,
  0xB5,
  0x0B,
  0x76,
  0x98,
  0x0A,
  0x4F,
  0xEF,
  0x18,
  0x67,
  0xDA,
  0x6E,
  0x4F,
  0x7C,
  0x64,
  0x12,
  0x41,
  0xAC,
  0xF5,
  0x24,
  0xAB,
  0xC1,
  0x7C,
  0x8F,
  0xB5,
  0x4A,
  0xB4,
  0xDD,
  0x41,
  0x38,
  0x4C,
  0x5B,
  0xB5,
  0x5F,
  0xA0,
  0xCD,
  0x04,
  0x8F,
  0x0D,
  0xF7,
  0xCD,
  0x63,
  0xF3,
  0x02,
  0x2D,
  0xC6,
  0x75,
  0xED,
  0x30,
  0x02,
  0xAD,
  0xED,
  0x7D,
  0xED,
  0xE9,
  0x65,
  0x07,
  0x1E,
  0x9B,
  0x41,
  0x1F,
  0x64,
  0x2C,
  0x5F,
  0xD4,
  0xB4,
  0x31,
  0x86,
  0x56,
  0x03,
  0xB7,
  0x39,
  0x5F,
  0x83,
  0xB4,
  0x9F,
  0x3E,
  0x6C,
  0xA5,
  0xE0,
  0xA4,
  0x28,
  0x46,
  0x73,
  0x22,
  0x6C,
  0x88,
  0xA2,
  0x38,
  0xDD,
  0x75,
  0xE1,
  0xBE,
  0xE4,
  0x1A,
  0x10,
  0x0C,
  0x7D,
  0x35,
  0x58,
  0x26,
  0x50,
  0xCC,
  0x10,
  0xC8,
  0xBC,
  0xC4,
  0x99,
  0xD4,
  0xD3,
  0x52,
  0xDE,
  0xFF,
  0x9D,
  0xE3,
  0xC6,
  0x04,
  0x1B,
  0xD6,
  0xA7,
  0xAD,
  0x02,
  0xC3,
  0x7F,
  0x55,
  0x46,
  0x1C,
  0xDB,
  0x39,
  0x9D,
  0x2C,
  0x15,
  0x23,
  0x25,
  0x9E,
  0x81,
  0x4D,
  0xCE,
  0x8E,
  0x30,
  0x92,
  0x83,
  0xB3,
  0x9B,
  0x33,
  0xB8,
  0xA5,
  0x97,
  0x8D,
  0x60,
  0x7D,
  0xD3,
  0x12,
  0x76,
  0x93,
  0xE7,
  0xA2,
  0x83,
  0x23,
  0xF4,
  0x77,
  0xD9,
  0x79,
  0xA0,
  0x49,
  0xB3,
  0xFD,
  0x41,
  0x31,
  0x40,
  0xFC,
  0x80,
  0x10,
  0xEE,
  0xBF,
  0x6F,
  0xA1,
  0x3A,
  0x11,
  0x71,
  0xCB,
  0x2D,
  0x48,
  0x9B,
  0xC3,
  0x92,
  0x0D,
  0x10,
  0x00,
  0x5F,
  0xA6,
  0x8C,
  0x45,
  0xA9,
  0xFD,
  0xDE,
  0xE7,
  0x86,
  0x99,
  0x55,
  0xDA,
  0xA6,
  0x97,
  0x4C,
  0x0E,
  0x3F,
  0x18,
  0x26,
  0xBE,
  0x73,
  0xBC,
  0x02,
  0x37,
  0xF8,
  0x9D,
  0x74,
  0x9D,
  0x3F,
  0x27,
  0xD2,
  0x53,
  0x43,
  0x38,
  0x43,
  0x7E,
  0xAE,
  0x10,
  0x02,
  0x2F,
  0x5C,
  0x82,
  0xD8,
  0xB9,
  0x95,
  0xBE,
  0xAC,
  0xE0,
  0x46,
  0xA9,
  0x9B,
};

static const uint8_t rsaPrivExponent[256] = {
  0x14,
  0xC0,
  0xAF,
  0xB1,
  0xCF,
  0x84,
  0x91,
  0x43,
  0x93,
  0xBE,
  0x67,
  0xCC,
  0x44,
  0x73,
  0xB7,
  0x66,
  0x70,
  0x3D,
  0x8C,
  0x0A,
  0xA2,
  0xB0,
  0x4C,
  0xF9,
  0x8B,
  0x55,
  0xE4,
  0xCD,
  0xCE,
  0x03,
  0xA1,
  0x28,
  0xE0,
  0x02,
  0x64,
  0x2B,
  0xEE,
  0xBE,
  0x18,
  0xB1,
  0x8F,
  0x43,
  0xAA,
  0xF4,
  0x4F,
  0x10,
  0xCD,
  0x1B,
  0x0A,
  0x6E,
  0xD0,
  0xAB,
  0x61,
  0x22,
  0xBD,
  0xCC,
  0xFF,
  0x8B,
  0x4A,
  0x88,
  0xE0,
  0x0A,
  0x5A,
  0x5F,
  0x69,
  0x94,
  0x34,
  0x98,
  0xAD,
  0x24,
  0xFA,
  0x18,
  0xFC,
  0xAB,
  0x7E,
  0x32,
  0xD0,
  0xC8,
  0x4B,
  0x80,
  0xE0,
  0x9E,
  0xA0,
  0xC8,
  0x31,
  0x3F,
  0x37,
  0x42,
  0x28,
  0x7B,
  0x49,
  0xF2,
  0x65,
  0xAB,
  0xCD,
  0xAD,
  0x2A,
  0xC2,
  0x7A,
  0x93,
  0x55,
  0x64,
  0x50,
  0x48,
  0x1D,
  0x1F,
  0xC9,
  0x83,
  0x0A,
  0x71,
  0xEA,
  0xCA,
  0x50,
  0x5F,
  0x5C,
  0x97,
  0xCD,
  0xFC,
  0x81,
  0x9E,
  0xAC,
  0x31,
  0x76,
  0xFB,
  0xA2,
  0x8E,
  0xC8,
  0x0E,
  0xD3,
  0x4A,
  0xB8,
  0x08,
  0xDB,
  0xB8,
  0xD5,
  0x8D,
  0x55,
  0xCF,
  0xBF,
  0xC0,
  0x0D,
  0x64,
  0x38,
  0x50,
  0xF7,
  0x1A,
  0xF1,
  0x86,
  0x36,
  0xED,
  0x96,
  0x16,
  0x6A,
  0x16,
  0x75,
  0x44,
  0x92,
  0xC8,
  0xDA,
  0x92,
  0xFB,
  0x95,
  0xAE,
  0xC9,
  0xEE,
  0x6F,
  0xB1,
  0x2D,
  0x8F,
  0x66,
  0x7E,
  0x82,
  0x94,
  0x96,
  0x00,
  0xC5,
  0xE9,
  0x15,
  0x79,
  0xD8,
  0x86,
  0xB3,
  0xF5,
  0xA7,
  0x9A,
  0xE3,
  0xCD,
  0x44,
  0x6E,
  0x1F,
  0x26,
  0xB6,
  0xC2,
  0x88,
  0xF1,
  0x58,
  0x0E,
  0x95,
  0x72,
  0xCB,
  0x6E,
  0x6B,
  0x1E,
  0x9C,
  0x1D,
  0x68,
  0xDD,
  0x28,
  0xD9,
  0xFE,
  0xF1,
  0x6F,
  0x5A,
  0x0F,
  0x4F,
  0x4E,
  0x9D,
  0x84,
  0x04,
  0xE2,
  0x40,
  0x79,
  0x19,
  0x1D,
  0xA8,
  0xBD,
  0xBE,
  0x64,
  0x1E,
  0xD1,
  0xBE,
  0x6A,
  0xF6,
  0x77,
  0xAE,
  0x5D,
  0xB0,
  0xD9,
  0x39,
  0x9B,
  0xAF,
  0xD9,
  0xA4,
  0x78,
  0xBD,
  0xE9,
  0x45,
  0xF2,
  0x77,
  0x9E,
  0x43,
  0x38,
  0xA6,
  0x88,
  0x63,
  0xA9,
};

static const uint8_t rsaPubExponent[3] = { 0x01, 0x00, 0x01 };  // 65537
#endif

void test_random() {
  Serial.println("\n=== Random ===");
  uint8_t buf[16];
  nRFCrypto.Random.generate(buf, sizeof(buf));
  hexDump(buf, sizeof(buf));
}

void test_hash() {
  Serial.println("\n=== Hash (SHA-256) ===");
  nRFCrypto_Hash h;
  const char* text = "Hello from Arduino nRF52840!";
  h.begin(CRYS_HASH_SHA256_mode);
  h.update((uint8_t*)text, strlen(text));
  uint8_t digest[32];
  uint8_t len = h.end(digest);
  Serial.println(len == 32 ? "OK: " : "FAIL: ");
  hexDump(digest, len);
}

void test_aes() {
  Serial.println("\n=== AES (ECB / CBC / CTR) ===");
  if (!aes.begin()) {
    Serial.println("begin FAIL");
    return;
  }
  char msg[] = "Hello nRF52840 AES!";
  uint8_t msgLen = strlen(msg);
  char encBuf[64], decBuf[64];
  uint8_t key[16], iv[16];
  nRFCrypto.Random.generate(key, sizeof(key));

  nRFCrypto.Random.generate(iv, sizeof(iv));
  int rslt = aes.Process(msg, msgLen, iv, key, sizeof(key), encBuf, aes.encryptFlag, aes.ecbMode);
  int rslt2 = (rslt > 0) ? aes.Process(encBuf, rslt, iv, key, sizeof(key), decBuf, aes.decryptFlag, aes.ecbMode) : -1;
  Serial.print("ECB: ");
  Serial.println((rslt > 0 && rslt2 == rslt && memcmp(decBuf, msg, msgLen) == 0) ? "OK" : "FAIL");

  nRFCrypto.Random.generate(iv, sizeof(iv));
  rslt = aes.Process(msg, msgLen, iv, key, sizeof(key), encBuf, aes.encryptFlag, aes.cbcMode);
  rslt2 = (rslt > 0) ? aes.Process(encBuf, rslt, iv, key, sizeof(key), decBuf, aes.decryptFlag, aes.cbcMode) : -1;
  Serial.print("CBC: ");
  Serial.println((rslt > 0 && rslt2 == rslt && memcmp(decBuf, msg, msgLen) == 0) ? "OK" : "FAIL");

  nRFCrypto.Random.generate(iv, sizeof(iv));
  rslt = aes.Process(msg, msgLen, iv, key, sizeof(key), encBuf, aes.encryptFlag, aes.ctrMode);
  rslt2 = (rslt > 0) ? aes.Process(encBuf, rslt, iv, key, sizeof(key), decBuf, aes.decryptFlag, aes.ctrMode) : -1;
  Serial.print("CTR: ");
  Serial.println((rslt > 0 && rslt2 == rslt && memcmp(decBuf, msg, msgLen) == 0) ? "OK" : "FAIL");
}

void test_chacha() {
  Serial.println("\n=== ChaCha20 (stream) ===");
#if !NRFCRYPTO_WITH_CHACHA
  Serial.println("skipped (NRFCRYPTO_WITH_CHACHA is 0 in nRFCrypto_Config.h)");
  return;
#else
  chacha.begin();
  uint8_t keyNonce[44];  // first 32 bytes = key, next 12 = nonce
  nRFCrypto.Random.generate(keyNonce, sizeof(keyNonce));
  uint8_t orig[93], buf[93];
  nRFCrypto.Random.generate(orig, sizeof(orig));
  memcpy(buf, orig, sizeof(orig));

  bool ok = chacha.Process(buf, sizeof(buf), keyNonce, chacha.encryptFlag) == CRYS_OK;
  if (ok) ok = chacha.Process(buf, sizeof(buf), keyNonce, chacha.decryptFlag) == CRYS_OK;
  if (ok) ok = memcmp(buf, orig, sizeof(orig)) == 0;
  Serial.println(ok ? "OK" : "FAIL");
#endif /* NRFCRYPTO_WITH_CHACHA */
}

void test_x25519_chachapoly() {
  Serial.println("\n=== X25519 + ChaCha20-Poly1305 ===");
#if !NRFCRYPTO_WITH_CHACHA
  Serial.println("skipped (NRFCRYPTO_WITH_CHACHA is 0 in nRFCrypto_Config.h)");
  return;
#else
  aliceX.begin();
  bobX.begin();
  cp.begin();

  uint8_t alicePub[nRFCrypto_X25519::PUBLIC_KEY_LEN], aliceSecret[nRFCrypto_X25519::SECRET_KEY_LEN];
  uint8_t bobPub[nRFCrypto_X25519::PUBLIC_KEY_LEN], bobSecret[nRFCrypto_X25519::SECRET_KEY_LEN];
  if (!aliceX.keygen(alicePub, aliceSecret) || !bobX.keygen(bobPub, bobSecret)) {
    Serial.println("keygen FAIL");
    return;
  }

  uint8_t sharedA[nRFCrypto_X25519::SHARED_SECRET_LEN], sharedB[nRFCrypto_X25519::SHARED_SECRET_LEN];
  if (!aliceX.agree(sharedA, aliceSecret, bobPub) || !bobX.agree(sharedB, bobSecret, alicePub)) {
    Serial.println("ECDH agree FAIL");
    return;
  }
  Serial.print("ECDH shared secrets match: ");
  Serial.println(memcmp(sharedA, sharedB, sizeof(sharedA)) == 0 ? "YES" : "NO (bug!)");

  // Never use a raw ECDH output directly as a symmetric key - hash it first.
  nRFCrypto_Hash h;
  uint8_t keyA[32], keyB[32];
  h.begin(CRYS_HASH_SHA256_mode);
  h.update(sharedA, sizeof(sharedA));
  h.end(keyA);
  h.begin(CRYS_HASH_SHA256_mode);
  h.update(sharedB, sizeof(sharedB));
  h.end(keyB);

  const char* text = "Hello from Alice, over LoRa!";
  uint8_t msg[64];
  size_t msgLen = strlen(text);
  memcpy(msg, text, msgLen);

  uint8_t nonce[nRFCrypto_ChachaPoly::NONCE_LEN];
  nRFCrypto.Random.generate(nonce, sizeof(nonce));
  const uint8_t aad[] = { 0x01 };
  uint8_t mac[nRFCrypto_ChachaPoly::MAC_LEN];

  bool ok = cp.encrypt(msg, msgLen, keyA, nonce, aad, sizeof(aad), mac) == CRYS_OK;
  if (ok) ok = cp.decrypt(msg, msgLen, keyB, nonce, aad, sizeof(aad), mac) == CRYS_OK;
  if (ok) ok = memcmp(msg, text, msgLen) == 0;
  Serial.print("Encrypt/decrypt roundtrip: ");
  Serial.println(ok ? "OK" : "FAIL");
#endif /* NRFCRYPTO_WITH_CHACHA */
}

void test_ed25519() {
  Serial.println("\n=== Ed25519 ===");
  if (!ed25519.begin()) {
    Serial.println("begin FAIL");
    return;
  }

  uint8_t pub[nRFCrypto_Ed25519::PUBLIC_KEY_LEN];
  uint8_t secret[nRFCrypto_Ed25519::SECRET_KEY_LEN];
  uint8_t sig[nRFCrypto_Ed25519::SIGNATURE_LEN];

  const char* text = "Hello from Arduino nRF52840!";
  const uint8_t* msg = (const uint8_t*)text;
  size_t msgLen = strlen(text);

  if (!ed25519.keygen(pub, secret)) {
    Serial.println("keygen FAIL");
    return;
  }
  if (!ed25519.sign(sig, msg, msgLen, secret)) {
    Serial.println("sign FAIL");
    return;
  }
  Serial.print("Verify (good msg): ");
  Serial.println(ed25519.verify(sig, msg, msgLen, pub) ? "VALID" : "INVALID");

  uint8_t bad[nRFCrypto_Ed25519::SIGNATURE_LEN];
  memcpy(bad, sig, sizeof(bad));
  bad[0] ^= 1;
  Serial.print("Verify (bad sig):  ");
  Serial.println(ed25519.verify(bad, msg, msgLen, pub) ? "VALID (unexpected!)" : "INVALID (expected)");
}

void test_ecdsa() {
  Serial.println("\n=== ECDSA (secp256r1) ===");
  if (!ecdsaPriv.begin(CRYS_ECPKI_DomainID_secp256r1) || !ecdsaPub.begin(CRYS_ECPKI_DomainID_secp256r1)) {
    Serial.println("Domain init FAIL");
    return;
  }
  if (!nRFCrypto_ECC::genKeyPair(ecdsaPriv, ecdsaPub)) {
    Serial.println("genKeyPair FAIL");
    return;
  }

  const char* text = "Hello from Arduino nRF52840!";
  const uint8_t* msg = (const uint8_t*)text;
  size_t msgLen = strlen(text);

  uint8_t sig[64];  // 2 * order size (32 bytes for P-256)
  uint32_t sigLen = nRFCrypto_ECC::sign(ecdsaPriv, CRYS_ECPKI_HASH_SHA256_mode, msg, msgLen, sig, sizeof(sig));
  if (sigLen == 0) {
    Serial.println("sign FAIL");
    return;
  }
  Serial.print("Verify (good msg): ");
  Serial.println(nRFCrypto_ECC::verify(ecdsaPub, CRYS_ECPKI_HASH_SHA256_mode, msg, msgLen, sig, sigLen) ? "VALID" : "INVALID");

  uint8_t bad[64];
  memcpy(bad, sig, sigLen);
  bad[0] ^= 1;
  Serial.print("Verify (bad sig):  ");
  Serial.println(nRFCrypto_ECC::verify(ecdsaPub, CRYS_ECPKI_HASH_SHA256_mode, msg, msgLen, bad, sigLen) ? "VALID (unexpected!)" : "INVALID (expected)");
}

void test_rsa() {
  Serial.println("\n=== RSA-2048 (PKCS#1 v1.5) ===");
#if NRFCRYPTO_WITH_RSA
  if (!rsaPub.begin(rsaModulus, sizeof(rsaModulus), rsaPubExponent, sizeof(rsaPubExponent))
      || !rsaPriv.begin(rsaModulus, sizeof(rsaModulus), rsaPrivExponent, sizeof(rsaPrivExponent),
                        rsaPubExponent, sizeof(rsaPubExponent))) {
    Serial.println("Key build FAIL");
    return;
  }

  const char* text = "Hello from Arduino nRF52840!";
  const uint8_t* msg = (const uint8_t*)text;
  size_t msgLen = strlen(text);

  uint8_t sig[256];
  uint16_t sigLen = nRFCrypto_RSA::sign(rsaPriv, CRYS_RSA_HASH_SHA256_mode, msg, msgLen, sig, sizeof(sig));
  if (sigLen == 0) {
    Serial.println("sign FAIL");
    return;
  }
  Serial.print("Verify (good msg): ");
  Serial.println(nRFCrypto_RSA::verify(rsaPub, CRYS_RSA_HASH_SHA256_mode, msg, msgLen, sig, sigLen) ? "VALID" : "INVALID");

  uint8_t bad[256];
  memcpy(bad, sig, sigLen);
  bad[0] ^= 1;
  Serial.print("Verify (bad sig):  ");
  Serial.println(nRFCrypto_RSA::verify(rsaPub, CRYS_RSA_HASH_SHA256_mode, msg, msgLen, bad, sigLen) ? "VALID (unexpected!)" : "INVALID (expected)");
#else
  Serial.println("skipped (NRFCRYPTO_WITH_RSA is 0 in nRFCrypto_Config.h)");
#endif
}

#if NRFCRYPTO_WITH_HKDF_HMAC
static bool deriveKeys(uint8_t encKey[32], uint8_t macKey[32], const uint8_t sharedSecret[32]) {
  const char* salt = "nRFCrypto-HKDF-demo";
  bool ok = true;
  ok &= nRFCrypto_HKDF::derive(CRYS_HKDF_HASH_SHA256_mode,
                               (const uint8_t*)salt, strlen(salt),
                               sharedSecret, 32,
                               (const uint8_t*)"encryption", 10,
                               encKey, 32);
  ok &= nRFCrypto_HKDF::derive(CRYS_HKDF_HASH_SHA256_mode,
                               (const uint8_t*)salt, strlen(salt),
                               sharedSecret, 32,
                               (const uint8_t*)"authentication", 14,
                               macKey, 32);
  return ok;
}

void test_hkdf_hmac() {
  Serial.println("\n=== HKDF + HMAC ===");
  uint8_t secret[32];
  nRFCrypto.Random.generate(secret, sizeof(secret));

  uint8_t encKey[32], macKey[32];
  if (!deriveKeys(encKey, macKey, secret)) {
    Serial.println("HKDF derive FAIL");
    return;
  }

  const char* text = "Hello from Arduino nRF52840!";
  const uint8_t* msg = (const uint8_t*)text;
  size_t msgLen = strlen(text);

  uint32_t tag[16];
  uint8_t tagLen = nRFCrypto_HMAC::compute(CRYS_HASH_SHA256_mode, macKey, sizeof(macKey), (uint8_t*)msg, msgLen, tag);
  if (tagLen == 0) {
    Serial.println("HMAC compute FAIL");
    return;
  }

  uint32_t tagCheck[16];
  hmac.begin(CRYS_HASH_SHA256_mode, macKey, sizeof(macKey));
  hmac.update((uint8_t*)msg, msgLen);
  uint8_t tagCheckLen = hmac.end(tagCheck);
  bool ok = (tagCheckLen == tagLen) && memcmp(tag, tagCheck, tagLen) == 0;
  Serial.print("Verify (good msg): ");
  Serial.println(ok ? "VALID" : "INVALID");

  const char* badText = "Hello from Mallory, over LoRa!";
  hmac.begin(CRYS_HASH_SHA256_mode, macKey, sizeof(macKey));
  hmac.update((uint8_t*)badText, strlen(badText));
  hmac.end(tagCheck);
  bool bad = memcmp(tag, tagCheck, tagLen) == 0;
  Serial.print("Verify (tampered msg): ");
  Serial.println(bad ? "VALID (unexpected!)" : "INVALID (expected)");
}
#else
void test_hkdf_hmac() {
  Serial.println("\n=== HKDF + HMAC ===");
  Serial.println("skipped (NRFCRYPTO_WITH_HKDF_HMAC is 0 in nRFCrypto_Config.h)");
}
#endif /* NRFCRYPTO_WITH_HKDF_HMAC */

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);  // remove if running without a serial monitor
  Serial.println("--- nRFCrypto kitchen sink ---");

  nRFCrypto.begin();

  test_random();
  test_hash();
  test_aes();
  test_chacha();
  test_x25519_chachapoly();
  test_ed25519();
  test_ecdsa();
  test_rsa();
  test_hkdf_hmac();

  Serial.println("\n--- done ---");
}

void loop() {}
