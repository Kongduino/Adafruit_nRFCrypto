// XEdDSA signing with R = r * B computed on the nRF52840 CryptoCell CC310.
//
// 1. nRFCrypto_Ed25519::scalarMultBase() against reference points
//    (RFC 8032 arithmetic, including the RFC 8032 TEST 1 public key).
// 2. Its run time for small, large and random scalars: it adds 4q so every
//    scalar has 255 bits, and the times should not depend on the scalar.
// 3. XEdDSA signatures built with it against XEdDSA::sign from
//    meshtastic/Crypto (https://github.com/meshtastic/Crypto), which must be
//    byte-identical for the same random Z, and verified by the CC310 and in
//    software.
//
// Lines start with PASS, FAIL or INFO.

#include <Adafruit_nRFCrypto.h>
#include <Ed25519.h>
#include <SHA512.h>
#include <XEdDSA.h>

#define ROUNDS 32
#define TIMING_RUNS 16
#define TEST_TASK_STACK_WORDS 4096  // 16 KB; software Ed25519 needs several KB

nRFCrypto_Ed25519 ed;

static int passed = 0;
static int failed = 0;

// ---- Reference points -------------------------------------------------------
// scalar * B from RFC 8032 section 5.1 arithmetic (Python), checked against
// the RFC 8032 TEST 1 public key. Scalars and points are little-endian.

struct BaseVector {
  const char* name;
  uint8_t scalar[32];
  uint8_t point[32];
};

static const BaseVector BASE_VECTORS[] = {
  {"1",
    {
     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {
     0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
     0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}},
  {"2",
    {
     0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {
     0xc9, 0xa3, 0xf8, 0x6a, 0xae, 0x46, 0x5f, 0x0e, 0x56, 0x51, 0x38, 0x64, 0x51, 0x0f, 0x39, 0x97,
     0x56, 0x1f, 0xa2, 0xc9, 0xe8, 0x5e, 0xa2, 0x1d, 0xc2, 0x29, 0x23, 0x09, 0xf3, 0xcd, 0x60, 0x22}},
  {"q-1",
    {
     0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
    {
     0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
     0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0xe6}},
  {"2^251+12345",
    {
     0x39, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
    {
     0x13, 0xa4, 0xa5, 0xf2, 0x93, 0x28, 0x5c, 0xcd, 0x43, 0xe6, 0x4c, 0x4a, 0x90, 0xd3, 0x1b, 0x4e,
     0xe3, 0x18, 0x92, 0xed, 0x18, 0x29, 0x53, 0x88, 0xa0, 0x2c, 0x5d, 0x85, 0x3d, 0x1b, 0xc1, 0x24}},
  {"RFC8032 test 1 (a mod q)",
    {
     0x7c, 0x2c, 0xac, 0x12, 0xe6, 0x9b, 0xe9, 0x6a, 0xe9, 0x06, 0x50, 0x65, 0x46, 0x23, 0x85, 0xe8,
     0xfc, 0xff, 0x27, 0x68, 0xd9, 0x80, 0xc0, 0xa3, 0xa5, 0x20, 0xf0, 0x06, 0x90, 0x4d, 0xe9, 0x0f},
    {
     0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
     0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a}}
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

static bool same(const uint8_t* got, const uint8_t* want, size_t len) {
  if (memcmp(got, want, len) == 0) return true;
  printHex("got: ", got, len);
  printHex("want:", want, len);
  return false;
}

// ---- Scalars mod q (TweetNaCl, public domain) --------------------------------

static const int64_t L[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                              0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0,
                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

static void modL(uint8_t* r, int64_t x[64]) {
  int64_t carry, i, j;
  for (i = 63; i >= 32; --i) {
    carry = 0;
    for (j = i - 32; j < i - 12; ++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry << 8;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  for (j = 0; j < 32; ++j) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  for (j = 0; j < 32; ++j) x[j] -= carry * L[j];
  for (i = 0; i < 32; ++i) {
    x[i + 1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

// 64-byte little-endian value -> 32-byte value mod q.
static void reduce64(uint8_t out[32], const uint8_t in[64]) {
  int64_t x[64];
  for (int i = 0; i < 64; i++) x[i] = in[i];
  modL(out, x);
}

// ---- XEdDSA sign with R on the CC310 -------------------------------------------

// Same steps as XEdDSA::sign: a = edPriv, prefix = SHA-512(edPriv)[32..63],
// r = SHA-512(prefix || M || Z) mod q, R = r * B, k = SHA-512(R || A || M) mod q,
// s = r + k * a mod q. sig[0..31] holds Z on entry, as for XEdDSA::sign.
static bool hwXEdDSASign(uint8_t sig[64], const uint8_t edPriv[32], const uint8_t edPub[32],
                         const uint8_t* msg, size_t len, uint32_t* baseMulMicros) {
  SHA512 hash;
  uint8_t h[64], r[32], k[32];

  hash.reset();
  hash.update(edPriv, 32);
  hash.finalize(h, 64);

  hash.reset();
  hash.update(h + 32, 32);
  hash.update(msg, len);
  hash.update(sig, 32);
  hash.finalize(h, 64);
  reduce64(r, h);

  uint32_t t0 = micros();
  bool ok = ed.scalarMultBase(sig, r);
  if (baseMulMicros) *baseMulMicros += micros() - t0;
  if (!ok) return false;

  hash.reset();
  hash.update(sig, 32);
  hash.update(edPub, 32);
  hash.update(msg, len);
  hash.finalize(h, 64);
  reduce64(k, h);

  int64_t x[64] = {0};
  for (int i = 0; i < 32; i++) x[i] = r[i];
  for (int i = 0; i < 32; i++)
    for (int j = 0; j < 32; j++) x[i + j] += (int64_t)k[i] * edPriv[j];
  modL(sig + 32, x);

  memset(h, 0, sizeof(h));
  memset(r, 0, sizeof(r));
  return true;
}

// ---- Tests ---------------------------------------------------------------------

static void testScalarMultBase() {
  Serial.println("\n== scalarMultBase, reference points ==");
  char name[80];
  alignas(4) uint8_t out[32];
  for (const BaseVector& v : BASE_VECTORS) {
    snprintf(name, sizeof(name), "%s * B", v.name);
    bool ok = ed.scalarMultBase(out, v.scalar);
    if (!ok) Serial.printf("      CC310 error 0x%08lx\n", (unsigned long)ed.lastError());
    check(name, ok && same(out, v.point, 32));
  }
  uint8_t big[32] = {0};
  big[31] = 0x20;  // 2^253: refused
  check("scalar >= 2^253 refused", !ed.scalarMultBase(out, big));
}

static void timeClass(const char* label, const uint8_t* fixed) {
  alignas(4) uint8_t s[32], out[32];
  uint32_t lo = 0xFFFFFFFF, hi = 0;
  for (int i = 0; i < TIMING_RUNS; i++) {
    if (fixed) memcpy(s, fixed, 32);
    else {
      uint8_t wide[64];
      nRFCrypto.Random.generate(wide, 64);
      reduce64(s, wide);
    }
    uint32_t t0 = micros();
    ed.scalarMultBase(out, s);
    uint32_t dt = micros() - t0;
    if (dt < lo) lo = dt;
    if (dt > hi) hi = dt;
  }
  Serial.printf("INFO  %-22s min %6lu us  max %6lu us\n", label, (unsigned long)lo, (unsigned long)hi);
}

static void testTiming() {
  Serial.printf("\n== scalarMultBase run time, %d runs each ==\n", TIMING_RUNS);
  uint8_t one[32] = {1};
  timeClass("scalar = 1", one);
  timeClass("scalar = q - 1", BASE_VECTORS[2].scalar);
  timeClass("random scalars", nullptr);
}

static void testSign() {
  Serial.printf("\n== XEdDSA sign with CC310 R, %d random keys ==\n", ROUNDS);
  int mismatch = 0, hwVerifyFail = 0, swVerifyFail = 0, signFail = 0;
  uint32_t tSw = 0, tHw = 0, tBaseMul = 0;
  for (int i = 0; i < ROUNDS; i++) {
    uint8_t curvePriv[32], edPriv[32], edPub[32], z[32];
    alignas(4) uint8_t msg[200];
    alignas(4) uint8_t swSig[64], hwSig[64];
    size_t len = 1 + (i * 37) % sizeof(msg);
    nRFCrypto.Random.generate(curvePriv, 32);
    curvePriv[0] &= 248;
    curvePriv[31] = (curvePriv[31] & 127) | 64;
    nRFCrypto.Random.generate(msg, len);
    nRFCrypto.Random.generate(z, 32);
    XEdDSA::priv_curve_to_ed_keys(curvePriv, edPriv, edPub);

    memcpy(swSig, z, 32);
    uint32_t t0 = micros();
    XEdDSA::sign(swSig, edPriv, edPub, msg, len);
    uint32_t t1 = micros();
    memcpy(hwSig, z, 32);
    bool ok = hwXEdDSASign(hwSig, edPriv, edPub, msg, len, &tBaseMul);
    uint32_t t2 = micros();
    tSw += t1 - t0;
    tHw += t2 - t1;

    if (!ok) signFail++;
    else if (memcmp(swSig, hwSig, 64) != 0) {
      if (mismatch++ == 0) {
        printHex("software:", swSig, 64);
        printHex("CC310:   ", hwSig, 64);
      }
    }
    if (!ed.verify(hwSig, msg, len, edPub)) hwVerifyFail++;
    if (!Ed25519::verify(hwSig, edPub, msg, len)) swVerifyFail++;
    memset(curvePriv, 0, 32);
    memset(edPriv, 0, 32);
  }
  check("CC310 sign succeeded", signFail == 0);
  check("signatures identical to XEdDSA::sign", mismatch == 0);
  check("CC310-made signatures verify on the CC310", hwVerifyFail == 0);
  check("CC310-made signatures verify in software", swVerifyFail == 0);

  Serial.println("\nAverage time per signature (us):");
  Serial.printf("  XEdDSA::sign (software)      %6lu\n", (unsigned long)(tSw / ROUNDS));
  Serial.printf("  XEdDSA with CC310 R          %6lu\n", (unsigned long)(tHw / ROUNDS));
  Serial.printf("    of which scalarMultBase    %6lu\n", (unsigned long)(tBaseMul / ROUNDS));
}

// ---- Main ----------------------------------------------------------------------

static void runTests(void*) {
  Serial.println("--- XEdDSA with CC310 scalarMultBase ---");
  if (!nRFCrypto.begin()) {
    Serial.println("nRFCrypto.begin() failed");
    vTaskDelete(NULL);
  }
  testScalarMultBase();
  testTiming();
  testSign();
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
