// Example: X25519 ECDH key agreement + ChaCha20-Poly1305 AEAD, using the
// CC310 hardware. This is the shape of a typical direct-message scheme:
// two peers each generate an X25519 keypair, exchange public keys, derive
// a shared secret, hash it into a symmetric key (never use a raw ECDH
// output directly as a key), then encrypt/authenticate with that key.

#include <Adafruit_nRFCrypto.h>
#include <hexdump.h>  // https://github.com/Kongduino/hexdump

#if !NRFCRYPTO_WITH_CHACHA
#error "This example needs ChaCha20-Poly1305 support - set NRFCRYPTO_WITH_CHACHA to 1 in nRFCrypto_Config.h (or via a build flag)"
#endif

nRFCrypto_X25519 aliceX, bobX;
nRFCrypto_ChachaPoly cp;
nRFCrypto_Hash hash;

static bool deriveKey(uint8_t key[32], const uint8_t sharedSecret[32]) {
  hash.begin(CRYS_HASH_SHA256_mode);
  hash.update((uint8_t*)sharedSecret, 32);
  return hash.end(key) == 32;
}

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);  // remove if running without a serial monitor
  Serial.println("--- nRFCrypto X25519 + ChaCha20-Poly1305 demo ---");

  nRFCrypto.begin();
  aliceX.begin();
  bobX.begin();
  cp.begin();

  uint8_t alicePub[nRFCrypto_X25519::PUBLIC_KEY_LEN], aliceSecret[nRFCrypto_X25519::SECRET_KEY_LEN];
  uint8_t bobPub[nRFCrypto_X25519::PUBLIC_KEY_LEN], bobSecret[nRFCrypto_X25519::SECRET_KEY_LEN];

  if (!aliceX.keygen(alicePub, aliceSecret) || !bobX.keygen(bobPub, bobSecret)) {
    Serial.println("keygen failed");
    while (1)
      ;
  }
  Serial.println("Alice public key:");
  hexDump(alicePub, sizeof(alicePub));
  Serial.println("Bob public key:");
  hexDump(bobPub, sizeof(bobPub));

  // Each side computes the shared secret from its own private key and the
  // other side's public key - only the public keys ever cross the wire.
  uint8_t sharedA[nRFCrypto_X25519::SHARED_SECRET_LEN];
  uint8_t sharedB[nRFCrypto_X25519::SHARED_SECRET_LEN];
  if (!aliceX.agree(sharedA, aliceSecret, bobPub) || !bobX.agree(sharedB, bobSecret, alicePub)) {
    Serial.println("ECDH agree failed");
    while (1)
      ;
  }
  Serial.print("Shared secrets match: ");
  Serial.println(memcmp(sharedA, sharedB, sizeof(sharedA)) == 0 ? "YES" : "NO (bug!)");

  uint8_t keyA[32], keyB[32];
  deriveKey(keyA, sharedA);
  deriveKey(keyB, sharedB);

  const char* text = "Hello from Alice, over LoRa!";
  uint8_t msg[64];
  size_t msgLen = strlen(text);
  memcpy(msg, text, msgLen);

  uint8_t nonce[nRFCrypto_ChachaPoly::NONCE_LEN];
  nRFCrypto.Random.generate(nonce, sizeof(nonce));
  const uint8_t aad[] = { 0x01 };  // protocol version byte; CC310 requires non-empty AAD
  uint8_t mac[nRFCrypto_ChachaPoly::MAC_LEN];

  // Alice encrypts with her derived key.
  if (cp.encrypt(msg, msgLen, keyA, nonce, aad, sizeof(aad), mac) != CRYS_OK) {
    Serial.println("encrypt failed");
    while (1)
      ;
  }
  Serial.println("Ciphertext:");
  hexDump(msg, msgLen);
  Serial.println("Tag:");
  hexDump(mac, sizeof(mac));

  // Keep the pristine ciphertext around - decrypt() runs in place, and we
  // reuse the ciphertext for the tamper test below.
  uint8_t ciphertext[64];
  memcpy(ciphertext, msg, msgLen);

  // Bob decrypts with his independently-derived key; should match exactly.
  uint8_t out[64];
  memcpy(out, ciphertext, msgLen);
  uint8_t macCheck[nRFCrypto_ChachaPoly::MAC_LEN];
  memcpy(macCheck, mac, sizeof(mac));
  bool ok = cp.decrypt(out, msgLen, keyB, nonce, aad, sizeof(aad), macCheck) == CRYS_OK;
  Serial.print("Decrypt+verify (good tag): ");
  Serial.println(ok ? "VALID" : "INVALID");
  if (ok) {
    out[msgLen] = 0;
    Serial.print("Plaintext: ");
    Serial.println((char*)out);
  }

  // Tamper test: flip a tag bit, decryption should be rejected.
  memcpy(out, ciphertext, msgLen);
  memcpy(macCheck, mac, sizeof(mac));
  macCheck[0] ^= 1;
  bool bad = cp.decrypt(out, msgLen, keyB, nonce, aad, sizeof(aad), macCheck) == CRYS_OK;
  Serial.print("Decrypt+verify (bad tag):  ");
  Serial.println(bad ? "VALID (unexpected!)" : "INVALID (expected)");
}

void loop() {}
