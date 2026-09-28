// Example: ECDSA sign/verify on curve secp256r1 (P-256), using the CC310
// hardware. Unlike RSA, EC key generation is cheap enough to do on-device,
// so this example generates a fresh keypair every run instead of shipping
// a fixed test key.

#include <Adafruit_nRFCrypto.h>
#include <hexdump.h>  // https://github.com/Kongduino/hexdump

nRFCrypto_ECC_PrivateKey privateKey;
nRFCrypto_ECC_PublicKey publicKey;

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);  // remove if running without a serial monitor
  Serial.println("--- nRFCrypto ECDSA demo (secp256r1) ---");

  nRFCrypto.begin();

  if (!privateKey.begin(CRYS_ECPKI_DomainID_secp256r1) || !publicKey.begin(CRYS_ECPKI_DomainID_secp256r1)) {
    Serial.println("Domain init failed");
    while (1)
      ;
  }
  if (!nRFCrypto_ECC::genKeyPair(privateKey, publicKey)) {
    Serial.println("genKeyPair failed");
    while (1)
      ;
  }

  uint8_t pubRaw[68];  // uncompressed point: 1-byte header + 2 * 32-byte coordinate
  uint32_t pubRawLen = publicKey.toRaw(pubRaw, sizeof(pubRaw));
  Serial.println("Public key:");
  hexDump(pubRaw, pubRawLen);

  const char* text = "Hello from Arduino nRF52840!";
  const uint8_t* msg = (const uint8_t*)text;
  size_t msgLen = strlen(text);

  uint8_t sig[64];  // 2 * order size (32 bytes for P-256)
  uint32_t sigLen = nRFCrypto_ECC::sign(privateKey, CRYS_ECPKI_HASH_SHA256_mode, msg, msgLen, sig, sizeof(sig));
  if (sigLen == 0) {
    Serial.println("Sign failed");
    while (1)
      ;
  }
  Serial.println("Signature:");
  hexDump(sig, sigLen);

  Serial.print("Verify (good msg): ");
  Serial.println(nRFCrypto_ECC::verify(publicKey, CRYS_ECPKI_HASH_SHA256_mode, msg, msgLen, sig, sigLen) ? "VALID" : "INVALID");

  // Tamper test: flip one bit, verification should fail.
  uint8_t bad[64];
  memcpy(bad, sig, sigLen);
  bad[0] ^= 1;
  Serial.print("Verify (bad sig):  ");
  Serial.println(nRFCrypto_ECC::verify(publicKey, CRYS_ECPKI_HASH_SHA256_mode, msg, msgLen, bad, sigLen) ? "VALID (unexpected!)" : "INVALID (expected)");
}

void loop() {}
