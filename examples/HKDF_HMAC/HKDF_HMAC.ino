// Example: deriving per-purpose session keys from an X25519 shared secret
// with HKDF (RFC 5869), then authenticating a message with HMAC-SHA256
// using one of those keys - the combo you'd use instead of a full AEAD
// when you want authentication only, or need more than one derived key
// (e.g. a separate encryption key and MAC key) from a single ECDH.

#include <Adafruit_nRFCrypto.h>
#include <hexdump.h>  // https://github.com/Kongduino/hexdump

nRFCrypto_X25519 aliceX, bobX;
nRFCrypto_HMAC hmac;

static bool deriveKeys(uint8_t encKey[32], uint8_t macKey[32], const uint8_t sharedSecret[32]) {
  const char* salt = "nRFCrypto-HKDF-demo";
  bool ok = true;
  ok &= nRFCrypto_HKDF::derive(
    CRYS_HKDF_HASH_SHA256_mode,
    (const uint8_t*)salt, strlen(salt),
    sharedSecret, 32,
    (const uint8_t*)"encryption", 10,
    encKey, 32);
  ok &= nRFCrypto_HKDF::derive(
    CRYS_HKDF_HASH_SHA256_mode,
    (const uint8_t*)salt, strlen(salt),
    sharedSecret, 32,
    (const uint8_t*)"authentication", 14,
    macKey, 32);
  return ok;
}

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);  // remove if running without a serial monitor
  Serial.println("--- nRFCrypto HKDF + HMAC demo ---");

  nRFCrypto.begin();
  aliceX.begin();
  bobX.begin();

  uint8_t alicePub[nRFCrypto_X25519::PUBLIC_KEY_LEN], aliceSecret[nRFCrypto_X25519::SECRET_KEY_LEN];
  uint8_t bobPub[nRFCrypto_X25519::PUBLIC_KEY_LEN], bobSecret[nRFCrypto_X25519::SECRET_KEY_LEN];
  if (!aliceX.keygen(alicePub, aliceSecret) || !bobX.keygen(bobPub, bobSecret)) {
    Serial.println("keygen failed");
    while (1)
      ;
  }

  uint8_t sharedA[nRFCrypto_X25519::SHARED_SECRET_LEN];
  uint8_t sharedB[nRFCrypto_X25519::SHARED_SECRET_LEN];
  if (!aliceX.agree(sharedA, aliceSecret, bobPub) || !bobX.agree(sharedB, bobSecret, alicePub)) {
    Serial.println("ECDH agree failed");
    while (1)
      ;
  }

  // Each side derives the same two keys from its own copy of the shared
  // secret - only the raw ECDH output ever needed to match; the derived
  // keys never cross the wire.
  uint8_t encKeyA[32], macKeyA[32];
  uint8_t encKeyB[32], macKeyB[32];
  if (!deriveKeys(encKeyA, macKeyA, sharedA) || !deriveKeys(encKeyB, macKeyB, sharedB)) {
    Serial.println("HKDF derive failed");
    while (1)
      ;
  }
  Serial.print("Derived keys match: ");
  Serial.println((memcmp(encKeyA, encKeyB, 32) == 0 && memcmp(macKeyA, macKeyB, 32) == 0) ? "YES" : "NO (bug!)");
  Serial.println("MAC key (Alice):");
  hexDump(macKeyA, 32);

  const char* text = "Hello from Alice, over LoRa!";
  const uint8_t* msg = (const uint8_t*)text;
  size_t msgLen = strlen(text);

  // Alice tags the message with the one-shot HMAC call.
  uint32_t tag[16];
  uint8_t tagLen = nRFCrypto_HMAC::compute(CRYS_HASH_SHA256_mode, macKeyA, sizeof(macKeyA), (uint8_t*)msg, msgLen, tag);
  if (tagLen == 0) {
    Serial.println("HMAC compute failed");
    while (1)
      ;
  }
  Serial.println("Tag:");
  hexDump((uint8_t*)tag, tagLen);

  // Bob checks it with the streaming API and his independently-derived key.
  uint32_t tagCheck[16];
  hmac.begin(CRYS_HASH_SHA256_mode, macKeyB, sizeof(macKeyB));
  hmac.update((uint8_t*)msg, msgLen);
  uint8_t tagCheckLen = hmac.end(tagCheck);
  bool ok = (tagCheckLen == tagLen) && memcmp(tag, tagCheck, tagLen) == 0;
  Serial.print("Verify (good msg): ");
  Serial.println(ok ? "VALID" : "INVALID");

  // Tamper test: verify against a different message, tag should not match.
  const char* badText = "Hello from Mallory, over LoRa!";
  hmac.begin(CRYS_HASH_SHA256_mode, macKeyB, sizeof(macKeyB));
  hmac.update((uint8_t*)badText, strlen(badText));
  hmac.end(tagCheck);
  bool bad = memcmp(tag, tagCheck, tagLen) == 0;
  Serial.print("Verify (tampered msg): ");
  Serial.println(bad ? "VALID (unexpected!)" : "INVALID (expected)");
}

void loop() {}
