// Example: using the nRFCrypto_Ed25519 class on a RAK4631.

#include <Adafruit_nRFCrypto.h>
#include <hexdump.h> // https://github.com/Kongduino/hexdump
nRFCrypto_Ed25519 ed25519;

// static void printHex(const uint8_t* buf, size_t len) {
//   for (size_t i = 0; i < len; i++) {
//     if (buf[i] < 0x10) Serial.print('0');
//     Serial.print(buf[i], HEX);
//   }
//   Serial.println();
// }

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);  // remove if running without a serial monitor
  Serial.println("--- nRFCrypto_Ed25519 demo ---");
  if (!ed25519.begin()) {
    Serial.println("begin failed");
    while (1)
      ;
  }

  uint8_t pub[nRFCrypto_Ed25519::PUBLIC_KEY_LEN];
  uint8_t secret[nRFCrypto_Ed25519::SECRET_KEY_LEN];
  uint8_t sig[nRFCrypto_Ed25519::SIGNATURE_LEN];

  const char* text = "Hello from Arduino nRF52840!";
  const uint8_t* msg = (const uint8_t*)text;
  size_t msg_len = strlen(text);

  if (!ed25519.keygen(pub, secret)) {
    Serial.print("keygen failed, err 0x");
    Serial.println(ed25519.lastError(), HEX);
    while (1)
      ;
  }
  Serial.print("Public key:\n");
  hexDump(pub, sizeof(pub));
  // Don't print secret keys in real use.

  if (!ed25519.sign(sig, msg, msg_len, secret)) {
    Serial.print("sign failed, err 0x");
    Serial.println(ed25519.lastError(), HEX);
    while (1)
      ;
  }
  Serial.print("Signature:\n");
  hexDump(sig, sizeof(sig));

  Serial.print("Verify (good msg): ");
  Serial.println(ed25519.verify(sig, msg, msg_len, pub) ? "VALID" : "INVALID");

  // Tamper test: flip one bit, verification should fail
  uint8_t bad[nRFCrypto_Ed25519::SIGNATURE_LEN];
  memcpy(bad, sig, sizeof(bad));
  bad[0] ^= 1;
  Serial.print("Verify (bad sig):  ");
  Serial.println(ed25519.verify(bad, msg, msg_len, pub) ? "VALID (unexpected!)" : "INVALID (expected)");
}

void loop() {}
