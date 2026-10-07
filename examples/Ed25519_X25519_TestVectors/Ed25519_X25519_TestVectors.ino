// Known-answer and cross-check tests for nRFCrypto_Ed25519 and
// nRFCrypto_X25519 on the nRF52840 CryptoCell CC310.
//
// 1. Known answers: RFC 8032 section 7.1 (Ed25519) and RFC 7748 sections
//    5.2 and 6.1 (X25519), plus inputs that must be rejected.
// 2. Lifecycle: the wrappers keep working after nRFCrypto.end(), and between
//    per-call nRFCrypto.begin()/end() pairs.
// 3. Cross-check (WITH_SOFTWARE_CROSSCHECK): random keys, with every CC310
//    result compared with Rhys Weatherley's software Curve25519/Ed25519, and
//    XEdDSA signatures (as Meshtastic sends them) verified on the CC310.
//    Needs the Crypto library; meshtastic/Crypto adds XEdDSA:
//    https://github.com/meshtastic/Crypto
//
// Lines start with PASS, FAIL or INFO. INFO lines report how strict each
// implementation is with malformed input; they are not failures.
//
// The tests run in their own task: software Curve25519::eval alone needs
// about 3 KB of stack, more than the default loop task has left.

#include <Adafruit_nRFCrypto.h>

// Set to 0 to build without the Crypto library.
#define WITH_SOFTWARE_CROSSCHECK 1

#if WITH_SOFTWARE_CROSSCHECK
#include <Curve25519.h>
#include <Ed25519.h>
#include <XEdDSA.h>
#endif

#define CROSSCHECK_ROUNDS 32
#define TEST_TASK_STACK_WORDS 4096  // 16 KB

nRFCrypto_Ed25519 ed;
nRFCrypto_X25519 x;

static int passed = 0;
static int failed = 0;

// ---- Test vectors --------------------------------------------------------
// Generated with python-cryptography and checked against the RFC texts.

struct EdVector {
  const char* name;
  uint8_t seed[32];
  uint8_t pub[32];
  uint8_t msg[2];
  size_t msgLen;
  uint8_t sig[64];
};

// RFC 8032 section 7.1, TEST 1-3.
static const EdVector ED_VECTORS[] = {
  { "RFC8032 test 1",
    {
      0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
      0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60 },
    {
      0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
      0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a },
    { 0 }, 0,
    {
      0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
      0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
      0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
      0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b } },
  { "RFC8032 test 2",
    {
      0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
      0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb },
    {
      0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
      0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c },
    { 0x72 }, 1,
    {
      0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
      0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
      0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
      0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00 } },
  { "RFC8032 test 3",
    {
      0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7, 0xb1,
      0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7 },
    {
      0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
      0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25 },
    { 0xaf, 0x82 }, 2,
    {
      0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02, 0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe, 0x01, 0xa3,
      0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44, 0x5e, 0x36, 0x80, 0xd7, 0xdb, 0x5a, 0xc3, 0xac,
      0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90, 0xae, 0x67, 0xf7, 0x60, 0x98, 0x4d, 0xc6, 0x59,
      0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d, 0xc0, 0x27, 0xbe, 0xce, 0xea, 0x1e, 0xc4, 0x0a } }
};

// RFC 8032 TEST 1 signature with L added to S. Same group element, so a
// verifier that skips the S < L check accepts it; RFC 8032 says reject.
static const uint8_t ED_SIG_S_PLUS_L[64] = {
      0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
      0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
      0x4c, 0x8c, 0x78, 0x72, 0xaa, 0x06, 0x4e, 0x04, 0x9d, 0xbb, 0x30, 0x13, 0xfb, 0xf2, 0x93, 0x80,
      0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x1b };

struct XVector {
  const char* name;
  uint8_t scalar[32];
  uint8_t u[32];
  uint8_t out[32];
};

// RFC 7748 section 5.2. Both scalars are unclamped and the second u has its
// top bit set, so these also check clamping and masking.
static const XVector X_VECTORS[] = {
  { "RFC7748 5.2 #1",
    {
      0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
      0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4 },
    {
      0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
      0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c },
    {
      0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
      0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52 } },
  { "RFC7748 5.2 #2",
    {
      0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26, 0x91, 0x95, 0x7d, 0x6a, 0xf5,
      0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e, 0x79, 0x18, 0xba, 0x0d },
    {
      0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38, 0xae, 0x2c,
      0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49, 0xc7, 0x15, 0xa4, 0x93 },
    {
      0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad, 0xe4, 0x5c, 0xb4, 0xb8, 0x73, 0xf8,
      0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f, 0xa1, 0x52, 0xe6, 0xf8, 0xf7, 0x64, 0x7a, 0xac, 0x79, 0x57 } }
};

// RFC 7748 section 6.1 (Alice and Bob).
static const uint8_t X_ALICE_PRIV[32] = {
  0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
  0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};
static const uint8_t X_ALICE_PUB[32] = {
  0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
  0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
};
static const uint8_t X_BOB_PRIV[32] = {
  0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
  0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
};
static const uint8_t X_BOB_PUB[32] = {
  0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
  0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};
static const uint8_t X_SHARED[32] = {
  0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
  0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
};

// Small-order points (u = 0, u = 1, and an order-8 point): the shared secret
// is all zeros, so agree() must fail.
static const uint8_t X_SMALL_ORDER[][32] = {
  {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
  {
      0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
  {
      0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
      0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 }
};

// u = p = 2^255 - 19, not a canonical field element.
static const uint8_t X_U_EQUALS_P[32] = {
  0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};

// ---- Helpers ---------------------------------------------------------------

static void check(const char* name, bool ok) {
  Serial.printf("%s  %s\n", ok ? "PASS" : "FAIL", name);
  if (ok) passed++;
  else failed++;
}

static void printHex(const char* label, const uint8_t* buf, size_t len) {
  Serial.printf("      %s ", label);
  for (size_t i = 0; i < len; i++) Serial.printf("%02x", buf[i]);
  Serial.println();
}

// Compares and, on mismatch, prints both values.
static bool same(const uint8_t* got, const uint8_t* want, size_t len) {
  if (memcmp(got, want, len) == 0) return true;
  printHex("got: ", got, len);
  printHex("want:", want, len);
  return false;
}

#if WITH_SOFTWARE_CROSSCHECK
// RFC 7748 clamping, for feeding Curve25519::eval (which does not clamp).
static void clamp(uint8_t k[32]) {
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
}
#endif

// ---- Ed25519 known answers ---------------------------------------------------

static void testEd25519Vectors() {
  Serial.println("\n== Ed25519, RFC 8032 ==");
  char name[64];
  for (const EdVector& v : ED_VECTORS) {
    // CC310 DMA reads RAM only, so stage everything there.
    alignas(4) uint8_t secret[64];
    alignas(4) uint8_t msg[4];
    alignas(4) uint8_t sig[64];
    memcpy(secret, v.seed, 32);
    memcpy(secret + 32, v.pub, 32);
    memcpy(msg, v.msg, v.msgLen);

    bool ok = ed.sign(sig, msg, v.msgLen, secret);
    snprintf(name, sizeof(name), "%s: sign matches", v.name);
    check(name, ok && same(sig, v.sig, 64));

    snprintf(name, sizeof(name), "%s: verify accepts", v.name);
    check(name, ed.verify(v.sig, msg, v.msgLen, v.pub));

    memcpy(sig, v.sig, 64);
    sig[0] ^= 0x01;
    snprintf(name, sizeof(name), "%s: verify rejects bad R", v.name);
    check(name, !ed.verify(sig, msg, v.msgLen, v.pub));

    memcpy(sig, v.sig, 64);
    sig[40] ^= 0x01;
    snprintf(name, sizeof(name), "%s: verify rejects bad S", v.name);
    check(name, !ed.verify(sig, msg, v.msgLen, v.pub));

    if (v.msgLen > 0) {
      msg[0] ^= 0x01;
      snprintf(name, sizeof(name), "%s: verify rejects bad msg", v.name);
      check(name, !ed.verify(v.sig, msg, v.msgLen, v.pub));
      msg[0] ^= 0x01;
    }

#if WITH_SOFTWARE_CROSSCHECK
    snprintf(name, sizeof(name), "%s: software verify accepts", v.name);
    check(name, Ed25519::verify(v.sig, v.pub, msg, v.msgLen));
#endif
    memset(secret, 0, sizeof(secret));
  }

  // S + L: RFC 8032 section 5.1.7 requires rejecting S >= L.
  alignas(4) uint8_t msg[4];
  const EdVector& t1 = ED_VECTORS[0];
  // Neither the CC310 nor the software checks S < L. What matters on a mesh
  // is that every node gives the same answer.
  bool hw = ed.verify(ED_SIG_S_PLUS_L, msg, t1.msgLen, t1.pub);
#if WITH_SOFTWARE_CROSSCHECK
  bool sw = Ed25519::verify(ED_SIG_S_PLUS_L, t1.pub, msg, t1.msgLen);
  Serial.printf("INFO  S + L: CC310 %s, software %s (RFC 8032 says reject)\n", hw ? "accepts" : "rejects",
                sw ? "accepts" : "rejects");
  check("RFC 8032 test 1 with S + L: CC310 and software agree", hw == sw);
#else
  Serial.printf("INFO  S + L: CC310 %s (RFC 8032 says reject)\n", hw ? "accepts" : "rejects");
#endif
}

// ---- X25519 known answers ----------------------------------------------------

static void testX25519Vectors() {
  Serial.println("\n== X25519, RFC 7748 ==");
  alignas(4) uint8_t out[32];
  char name[64];

  check("6.1 Alice public key", x.publicKey(out, X_ALICE_PRIV) && same(out, X_ALICE_PUB, 32));
  check("6.1 Bob public key", x.publicKey(out, X_BOB_PRIV) && same(out, X_BOB_PUB, 32));
  check("6.1 Alice shared secret", x.agree(out, X_ALICE_PRIV, X_BOB_PUB) && same(out, X_SHARED, 32));
  check("6.1 Bob shared secret", x.agree(out, X_BOB_PRIV, X_ALICE_PUB) && same(out, X_SHARED, 32));

  for (const XVector& v : X_VECTORS) {
    snprintf(name, sizeof(name), "%s: agree matches", v.name);
    check(name, x.agree(out, v.scalar, v.u) && same(out, v.out, 32));
#if WITH_SOFTWARE_CROSSCHECK
    // Curve25519::eval masks u's top bit but does not clamp the scalar;
    // the firmware only ever passes it clamped keys (from dh1).
    alignas(4) uint8_t k[32];
    memcpy(k, v.scalar, 32);
    clamp(k);
    snprintf(name, sizeof(name), "%s: software, clamped scalar", v.name);
    check(name, Curve25519::eval(out, k, v.u) && same(out, v.out, 32));
    bool rawOk = Curve25519::eval(out, v.scalar, v.u) && memcmp(out, v.out, 32) == 0;
    Serial.printf("INFO  %s: software with the raw unclamped scalar %s\n", v.name,
                  rawOk ? "matches" : "differs (eval does not clamp)");
#endif
  }

  for (size_t i = 0; i < sizeof(X_SMALL_ORDER) / sizeof(X_SMALL_ORDER[0]); i++) {
    snprintf(name, sizeof(name), "small-order point %u: agree fails", (unsigned)i);
    check(name, !x.agree(out, X_ALICE_PRIV, X_SMALL_ORDER[i]));
  }

  bool hw = x.agree(out, X_ALICE_PRIV, X_U_EQUALS_P);
#if WITH_SOFTWARE_CROSSCHECK
  alignas(4) uint8_t k[32];
  memcpy(k, X_ALICE_PRIV, 32);
  clamp(k);
  bool sw = Curve25519::eval(out, k, X_U_EQUALS_P);
  Serial.printf("INFO  u = p (non-canonical): CC310 %s, software %s\n", hw ? "accepts" : "rejects",
                sw ? "accepts" : "rejects");
#else
  Serial.printf("INFO  u = p (non-canonical): CC310 %s\n", hw ? "accepts" : "rejects");
#endif
}

// ---- Lifecycle ---------------------------------------------------------------

static bool edVerifyTest1() {
  alignas(4) uint8_t msg[4];
  const EdVector& t1 = ED_VECTORS[0];
  return ed.verify(t1.sig, msg, t1.msgLen, t1.pub);
}

static bool xAgreeRfc() {
  alignas(4) uint8_t out[32];
  return x.agree(out, X_ALICE_PRIV, X_BOB_PUB) && memcmp(out, X_SHARED, 32) == 0;
}

static void testLifecycle() {
  Serial.println("\n== Lifecycle ==");
  // Meshtastic calls nRFCrypto.end() after each AES/RNG operation.
  nRFCrypto.end();
  check("Ed25519 verify after nRFCrypto.end()", edVerifyTest1());
  nRFCrypto.end();
  check("X25519 agree after nRFCrypto.end()", xAgreeRfc());

  bool ok = true;
  for (int i = 0; i < 4; i++) {
    nRFCrypto.begin();
    ok &= edVerifyTest1();
    nRFCrypto.end();
    nRFCrypto.begin();
    ok &= xAgreeRfc();
    nRFCrypto.end();
  }
  check("per-call nRFCrypto.begin()/end() pairs", ok);

  nRFCrypto.end();
  alignas(4) uint8_t pub[32];
  alignas(4) uint8_t secret[64];
  check("Ed25519 keygen after nRFCrypto.end() (shared RNG)", ed.keygen(pub, secret));
  nRFCrypto.end();
  check("X25519 keygen after nRFCrypto.end() (shared RNG)", x.keygen(pub, secret));
  memset(secret, 0, sizeof(secret));
}

// ---- Cross-check against software --------------------------------------------

#if WITH_SOFTWARE_CROSSCHECK
static void testCrossCheck() {
  Serial.printf("\n== Cross-check with software, %d random keys ==\n", CROSSCHECK_ROUNDS);
  int pubMismatch = 0, sharedMismatch = 0, xeddsaHwReject = 0, xeddsaSwReject = 0, tamperAccept = 0;
  uint32_t tHwVerify = 0, tSwVerify = 0, tHwAgree = 0, tSwAgree = 0, tSwSign = 0;

  for (int r = 0; r < CROSSCHECK_ROUNDS; r++) {
    alignas(4) uint8_t privA[32], privB[32], pubA[32], pubB[32], swPub[32];
    alignas(4) uint8_t hwShared[32], swShared[32];
    nRFCrypto.Random.generate(privA, 32);
    nRFCrypto.Random.generate(privB, 32);
    clamp(privA);  // as Curve25519::dh1 stores them
    clamp(privB);

    // Public keys.
    x.publicKey(pubA, privA);
    x.publicKey(pubB, privB);
    Curve25519::eval(swPub, privA, nullptr);
    if (memcmp(pubA, swPub, 32) != 0) pubMismatch++;

    // Shared secret.
    uint32_t t0 = micros();
    bool hwOk = x.agree(hwShared, privA, pubB);
    uint32_t t1 = micros();
    bool swOk = Curve25519::eval(swShared, privA, pubB);
    uint32_t t2 = micros();
    tHwAgree += t1 - t0;
    tSwAgree += t2 - t1;
    if (!hwOk || !swOk || memcmp(hwShared, swShared, 32) != 0) sharedMismatch++;

    // XEdDSA: sign in software exactly as the firmware does, verify on CC310.
    alignas(4) uint8_t edPriv[32], edPub[32], sig[64], msg[200];
    size_t msgLen = 1 + (r * 37) % sizeof(msg);
    nRFCrypto.Random.generate(msg, msgLen);
    XEdDSA::priv_curve_to_ed_keys(privA, edPriv, edPub);
    nRFCrypto.Random.generate(sig, 32);  // hedging randomness Z
    t0 = micros();
    XEdDSA::sign(sig, edPriv, edPub, msg, msgLen);
    t1 = micros();
    hwOk = ed.verify(sig, msg, msgLen, edPub);
    t2 = micros();
    swOk = Ed25519::verify(sig, edPub, msg, msgLen);
    uint32_t t3 = micros();
    tSwSign += t1 - t0;
    tHwVerify += t2 - t1;
    tSwVerify += t3 - t2;
    if (!hwOk) xeddsaHwReject++;
    if (!swOk) xeddsaSwReject++;
    msg[msgLen / 2] ^= 0x80;
    if (ed.verify(sig, msg, msgLen, edPub)) tamperAccept++;

    memset(privA, 0, 32);
    memset(privB, 0, 32);
    memset(edPriv, 0, 32);
  }

  check("X25519 public keys match software", pubMismatch == 0);
  check("X25519 shared secrets match software", sharedMismatch == 0);
  check("XEdDSA signatures verify on CC310", xeddsaHwReject == 0);
  check("XEdDSA signatures verify in software", xeddsaSwReject == 0);
  check("CC310 rejects XEdDSA signature on tampered message", tamperAccept == 0);

  Serial.println("\nAverage time per operation (us):");
  Serial.printf("  X25519 shared secret   CC310 %6lu   software %6lu\n",
                (unsigned long)(tHwAgree / CROSSCHECK_ROUNDS), (unsigned long)(tSwAgree / CROSSCHECK_ROUNDS));
  Serial.printf("  Ed25519 verify         CC310 %6lu   software %6lu\n",
                (unsigned long)(tHwVerify / CROSSCHECK_ROUNDS), (unsigned long)(tSwVerify / CROSSCHECK_ROUNDS));
  Serial.printf("  XEdDSA sign                          software %6lu\n",
                (unsigned long)(tSwSign / CROSSCHECK_ROUNDS));
}
#endif

// ---- Main ----------------------------------------------------------------------

static void runTests(void*) {
  Serial.println("--- nRFCrypto Ed25519 / X25519 test vectors ---");

  if (!nRFCrypto.begin()) {
    Serial.println("nRFCrypto.begin() failed");
    vTaskDelete(NULL);
  }

  testEd25519Vectors();
  testX25519Vectors();
  testLifecycle();
#if WITH_SOFTWARE_CROSSCHECK
  testCrossCheck();
#endif

  Serial.printf("\nRESULT: %d passed, %d failed\n", passed, failed);
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);  // remove if running without a serial monitor
  if (xTaskCreate(runTests, "tests", TEST_TASK_STACK_WORDS, NULL, TASK_PRIO_LOW, NULL) != pdPASS)
    Serial.println("could not create the test task (out of heap?)");
}

void loop() {}
