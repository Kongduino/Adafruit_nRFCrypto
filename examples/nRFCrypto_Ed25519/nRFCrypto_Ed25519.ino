#include <Adafruit_nRFCrypto.h>
#include "nrf_cc310/include/crys_ec_edw_api.h"  // Directly exposes the CryptoCell EDW functions
#include "nrf_cc310/include/crys_rnd.h"         // Exposes the required random vector functions
#include <hexdump.h>

#define ED25519_KEY_SIZE 32

// CryptoCell requires 4-byte word alignment for buffers processed via DMA
__ALIGN(4)
uint8_t private_key[ED25519_KEY_SIZE * 2];
size_t private_key_len = sizeof(private_key);

__ALIGN(4)
uint8_t public_key[ED25519_KEY_SIZE];
size_t public_key_len = sizeof(public_key);

// Re-usable buffer required by the CryptoCell core functions
__ALIGN(4)
CRYS_ECEDW_TempBuff_t temp_buff;

// Local RND State Blocks allocated globally to ensure persistent word alignment
__ALIGN(4)
CRYS_RND_State_t cc310_rnd_state;
__ALIGN(4)
CRYS_RND_WorkBuff_t cc310_rnd_work_buff;

// Allocate buffers for messages and signatures (must be 4-byte aligned!)
__ALIGN(4)
uint8_t message[] = "Hello from Arduino nRF52840!";
size_t message_len = sizeof(message) - 1;

__ALIGN(4)
uint8_t signature[CRYS_ECEDW_SIGNATURE_BYTES];
size_t signature_len = sizeof(signature);

void setup() {
  Serial.begin(115200);
  while (!Serial) delay(10);
  Serial.println("--- nRF52840 CryptoCell Ed25519 Demo ---");

  // 1. Core peripheral initialization
  nRFCrypto.begin();
  Serial.printf("CC ENABLE = %d\n", NRF_CRYPTOCELL->ENABLE);  // expect 1
  uint8_t seed[32];
  Serial.print("Random.generate: ");
  Serial.println(nRFCrypto.Random.generate(seed, 32) ? "OK" : "FAIL");

  // 2. Safely initialize and hook the isolated CC310 Random Subsystem structures
  Serial.printf("CC ENABLE = %d\n", NRF_CRYPTOCELL->ENABLE);  // expect 1
  Serial.print("Initializing Subsystem TRNG Context... ");
  uint32_t rnd_rc = CRYS_RndInit(&cc310_rnd_state, &cc310_rnd_work_buff);
  if (rnd_rc == CRYS_OK) {
    Serial.println("SUCCESS!");
  } else {
    Serial.printf("FAILED! Code: 0x%08x\n", rnd_rc, HEX);
    while (1)
      ;
  }

  // 3. Generate Ed25519 Key Pair using the fully prepared state pointer
  Serial.print("Generating Key Pair... ");
  uint32_t rc = CRYS_ECEDW_KeyPair(
    private_key,
    &private_key_len,
    public_key,
    &public_key_len,
    (void*)&cc310_rnd_state,
    CRYS_RND_GenerateVector,
    &temp_buff);

  if (rc == CRYS_OK) {
    Serial.println("SUCCESS!");
    Serial.print("Public Key (Hex):\n");
    hexDump(public_key, public_key_len);
    Serial.print("Private Key (Hex):\n");
    hexDump(private_key, private_key_len);
  } else {
    Serial.print(" * FAILED! Error Code: 0x");
    Serial.println(rc, HEX);
    while (1)
      ;
  }

  // 4. Sign the Message
  Serial.print("Signing Message... ");
  rc = CRYS_ECEDW_Sign(
    signature, &signature_len, message, message_len,
    private_key, private_key_len, &temp_buff);
  if (rc == CRYS_OK) {
    Serial.println("SUCCESS!");
    Serial.print("Signature (Hex):\n");
    hexDump(signature, signature_len);
  } else {
    Serial.print(" * FAILED! Error Code: 0x");
    Serial.println(rc, HEX);
  }

  // 5. Verify the Signature
  Serial.print("Verifying Signature...\t");
  rc = CRYS_ECEDW_Verify(
    signature,
    signature_len,
    public_key,
    public_key_len,
    message,
    message_len,
    &temp_buff);

  if (rc == CRYS_OK) {
    Serial.println("VALID! Signature verified successfully.");
  } else {
    Serial.printf("INVALID! Verification failed. Error Code: 0x%08x\n", rc, HEX);
  }

  // 6. Verify a damaged signature
  signature[0] = 255 - signature[0];
  Serial.print("\nVerifying damaged signature...\n");
  hexDump(signature, signature_len);
  rc = CRYS_ECEDW_Verify(
    signature,
    signature_len,
    public_key,
    public_key_len,
    message,
    message_len,
    &temp_buff);

  if (rc == CRYS_OK) {
    Serial.println("VALID! Signature verified successfully.");
  } else {
    Serial.printf("INVALID! Verification failed. Error Code: 0x%08x\n", rc, HEX);
  }
  nRFCrypto.end();  // when done
}

void loop() {
  // Nothing to do here
}
