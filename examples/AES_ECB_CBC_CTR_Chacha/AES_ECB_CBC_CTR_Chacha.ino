#include <Adafruit_nRFCrypto.h>

nRFCrypto_AES aes;
nRFCrypto_Chacha urara; // You need to speak Korean to understand this one ;-)

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
  // Serial.println("myLen = " + String(myLen));
  char encBuf[myLen] = {0}; // Let's make sure we have enough space for the encrypted string
  char decBuf[myLen] = {0}; // Let's make sure we have enough space for the decrypted string
  Serial.println("Plain text:");
  hexDump((unsigned char *)msg, msgLen);
  uint8_t pKey[16] = {0};
  uint8_t pKeyLen = 16;
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

  CRYS_CHACHA_Nonce_t pNonce;
  CRYS_CHACHA_Key_t myKey;
  nRFCrypto.Random.generate((uint8_t*)myKey, 32);
  Serial.println("myKey:");
  hexDump((uint8_t*)myKey, 32);
  nRFCrypto.Random.generate((uint8_t*)pNonce, 12);
  uint32_t initialCounter = 0;
  Serial.println("Nonce:");
  hexDump((uint8_t*)pNonce, 12);
  rslt = urara.Process((unsigned char *)msg, msgLen, pNonce, myKey, pKeyLen, (unsigned char *)encBuf, urara.encryptFlag, initialCounter);
  Serial.println("Chacha Encoded:");
  hexDump((unsigned char *)encBuf, msgLen);
  rslt = urara.Process((unsigned char *)msg, msgLen, pNonce, myKey, pKeyLen, (unsigned char *)decBuf, urara.decryptFlag, initialCounter);
  Serial.println("Chacha Decoded:");
  hexDump((unsigned char *)decBuf, msgLen);
}

void loop() {
}
