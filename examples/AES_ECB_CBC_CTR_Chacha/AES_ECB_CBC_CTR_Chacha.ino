#include <Adafruit_nRFCrypto.h>

nRFCrypto_AES aes;

void hexDump(unsigned char *buf, uint16_t len) {
  char alphabet[17] = "0123456789abcdef";
  Serial.print(F("   +------------------------------------------------+ +----------------+\n"));
  Serial.print(F("   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |\n"));
  for (uint16_t i = 0; i < len; i += 16) {
    if (i % 128 == 0)
      Serial.print(F("   +------------------------------------------------+ +----------------+\n"));
    char s[] = "|                                                | |                |\n";
    uint8_t ix = 1, iy = 52;
    for (uint8_t j = 0; j < 16; j++) {
      if (i + j < len) {
        uint8_t c = buf[i + j];
        s[ix++] = alphabet[(c >> 4) & 0x0F];
        s[ix++] = alphabet[c & 0x0F];
        ix++;
        if (c > 31 && c < 128) s[iy++] = c;
        else s[iy++] = '.';
      }
    }
    uint8_t index = i / 16;
    if (i < 256) Serial.write(' ');
    Serial.print(index, HEX); Serial.write('.');
    Serial.print(s);
  }
  Serial.print(F("   +------------------------------------------------+ +----------------+\n"));
}

void setup() {
  Serial.begin(115200);
  time_t timeout = millis();
  while (!Serial) {
    if ((millis() - timeout) < 5000) {
      delay(100);
    } else {
      break;
    }
  }
  delay(1000);
  Serial.println("\nnRF AES test");
  Serial.print(" * begin");
  nRFCrypto.begin();
  aes.begin();
  Serial.println(" done!");
  char *msg = "Hello user! This is a plain text string!";
  // please note dear reader – and you should RTFM – that this string's length isn't a multiple of 16.
  // but I am foolish that way.
  uint8_t msgLen = strlen(msg);
  // A function that calculates the required length. √
  uint8_t myLen = aes.blockLen(msgLen);
  char encBuf[64] = {0}; // Let's make sure we have enough space for the encrypted string
  char decBuf[64] = {0}; // Let's make sure we have enough space for the decrypted string
  Serial.println("Plain text:");
  hexDump((unsigned char *)msg, msgLen);
  uint8_t pKey[16] = {0};
  uint8_t pKeyLen = 16;
  // Might as well make good use of the Random function.
  // Alternate could be via LoRa. But since we're testing the nRFCrypto lib... :-)
  nRFCrypto.Random.generate(pKey, 16);
  Serial.println("pKey:");
  hexDump(pKey, 16);
  uint8_t IV[16] = {1};
  int rslt = aes.Process(msg, msgLen, IV, pKey, pKeyLen, encBuf, aes.encryptFlag, aes.ecbMode);
  Serial.println("ECB Encoded:");
  hexDump((unsigned char *)encBuf, rslt);
  rslt = aes.Process(encBuf, rslt, IV, pKey, pKeyLen, decBuf, aes.decryptFlag, aes.ecbMode);
  Serial.println("ECB Decoded:");
  hexDump((unsigned char *)decBuf, rslt);

  nRFCrypto.Random.generate(IV, 16);
  Serial.println("IV:");
  hexDump(IV, 16);
  rslt = aes.Process(msg, msgLen, IV, pKey, pKeyLen, encBuf, aes.encryptFlag, aes.cbcMode);
  Serial.println("CBC Encoded:");
  hexDump((unsigned char *)encBuf, rslt);
  rslt = aes.Process(encBuf, rslt, IV, pKey, pKeyLen, decBuf, aes.decryptFlag, aes.cbcMode);
  Serial.println("CBC Decoded:");
  hexDump((unsigned char *)decBuf, rslt);

  rslt = aes.Process(msg, msgLen, IV, pKey, pKeyLen, encBuf, aes.encryptFlag, aes.ctrMode);
  Serial.println("CTR Encoded:");
  hexDump((unsigned char *)encBuf, rslt);
  rslt = aes.Process(encBuf, rslt, IV, pKey, pKeyLen, decBuf, aes.decryptFlag, aes.ctrMode);
  Serial.println("CTR Decoded:");
  hexDump((unsigned char *)decBuf, rslt);

  uint8_t orgLen = msgLen;
  msgLen = 64;
  memset(decBuf, 0, msgLen);
  memset(encBuf, 0, msgLen);
  nRFCrypto_Chacha urara; // You need to speak Korean to understand this one ;-)
  urara.begin();
  CRYS_CHACHA_Nonce_t pNonce;
  CRYS_CHACHA_Key_t myKey;
  uint32_t initialCounter = 0;
  pKeyLen = 32;
  // We're going to pass a 44-byte array to the Process function:
  // The first 32 are the key, the next 12 the nonce.
  // The Process functions builds the CRYS_CHACHAUserContext_t, CRYS_CHACHA_Nonce_t and CRYS_CHACHA_Key_t objects itself.
  uint8_t temp[44];
  nRFCrypto.Random.generate(temp, 44);
  Serial.println("myKey:");
  hexDump((uint8_t*)temp, pKeyLen);
  Serial.println("Nonce:");
  hexDump((uint8_t*)temp + 32, 12);

  // orig = our "plaintext"
  uint8_t orig[93];
  // enc = our "plaintext", then encrypted version (in place), then, hopefully the properly decoded version.
  uint8_t enc[93];
  nRFCrypto.Random.generate(orig, 93);

  // First test with a block smaller than the minimum block size (64)
  Serial.println("\nOriginal [32]:");
  memcpy(enc, orig, 32);
  hexDump(enc, 32);
  rslt = urara.Process(enc, 32, temp, urara.encryptFlag);
  Serial.printf(" * rslt = 0x%08x\n", rslt);
  if (rslt != 0) {
    explainError(rslt, msgLen);
    return;
  } else {
    Serial.println("Chacha Encoded:");
    hexDump(enc, 64);
  }
  rslt = urara.Process(enc, 32, temp, urara.decryptFlag);
  Serial.printf(" * rslt = 0x%08x\n", rslt);
  if (rslt != 0) explainError(rslt, msgLen);
  else {
    Serial.println("Chacha Decoded (only the first 32 bytes count):");
    hexDump(enc, 64);
    if (memcmp(orig, enc, 32) == 0) Serial.println("Enc/Dec roud-trip successful!");
    else Serial.println("Enc/Dec roud-trip fail!");
  }

  // Second test with a block longer than the minimum block size (64)
  // and not a multiple of 64
  memcpy(enc, orig, 93);
  Serial.println("\nOriginal [93]:");
  hexDump(enc, 93);
  rslt = urara.Process(enc, 93, temp, urara.encryptFlag);
  Serial.printf(" * rslt = 0x%08x\n", rslt);
  if (rslt != 0) {
    explainError(rslt, msgLen);
    return;
  } else {
    Serial.println("Chacha Encoded:");
    hexDump(enc, 93);
  }
  rslt = urara.Process(enc, 93, temp, urara.decryptFlag);
  Serial.printf(" * rslt = 0x%08x\n", rslt);
  if (rslt != 0) explainError(rslt, msgLen);
  else {
    Serial.println("Chacha Decoded:");
    hexDump(enc, 93);
    if (memcmp(orig, enc, 93) == 0) Serial.println("Enc/Dec roud-trip successful!");
    else Serial.println("Enc/Dec roud-trip fail!");
  }
}

void loop() {
}

void explainError(int rslt, uint8_t msgLen) {
  Serial.print(" * ");
  if (CRYS_CHACHA_INVALID_NONCE_ERROR == rslt) Serial.println("CRYS_CHACHA_INVALID_NONCE_ERROR");
  else if (CRYS_CHACHA_ILLEGAL_KEY_SIZE_ERROR == rslt) Serial.println("CRYS_CHACHA_ILLEGAL_KEY_SIZE_ERROR");
  else if (CRYS_CHACHA_INVALID_KEY_POINTER_ERROR == rslt) Serial.println("CRYS_CHACHA_INVALID_KEY_POINTER_ERROR");
  else if (CRYS_CHACHA_INVALID_ENCRYPT_MODE_ERROR == rslt) Serial.println("CRYS_CHACHA_INVALID_ENCRYPT_MODE_ERROR");
  else if (CRYS_CHACHA_DATA_IN_POINTER_INVALID_ERROR == rslt) Serial.println("CRYS_CHACHA_DATA_IN_POINTER_INVALID_ERROR");
  else if (CRYS_CHACHA_DATA_OUT_POINTER_INVALID_ERROR == rslt) Serial.println("CRYS_CHACHA_DATA_OUT_POINTER_INVALID_ERROR");
  else if (CRYS_CHACHA_INVALID_USER_CONTEXT_POINTER_ERROR == rslt) Serial.println("CRYS_CHACHA_INVALID_USER_CONTEXT_POINTER_ERROR");
  else if (CRYS_CHACHA_CTX_SIZES_ERROR == rslt) Serial.println("CRYS_CHACHA_CTX_SIZES_ERROR");
  else if (CRYS_CHACHA_INVALID_NONCE_PTR_ERROR == rslt) Serial.println("CRYS_CHACHA_INVALID_NONCE_PTR_ERROR");
  else if (CRYS_CHACHA_DATA_IN_SIZE_ILLEGAL == rslt) Serial.printf("CRYS_CHACHA_DATA_IN_SIZE_ILLEGAL: %d vs %d\n", msgLen, CRYS_CHACHA_BLOCK_SIZE_IN_BYTES);
  else if (CRYS_CHACHA_GENERAL_ERROR == rslt) Serial.println("CRYS_CHACHA_GENERAL_ERROR");
  else if (CRYS_CHACHA_IS_NOT_SUPPORTED == rslt) Serial.println("CRYS_CHACHA_IS_NOT_SUPPORTED");
  else Serial.println("No idea...");
}
