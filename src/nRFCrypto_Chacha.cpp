/*
   The MIT License (MIT)
   Copyright (c) 2021 by Kongduino
   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:
   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
*/

#include "Arduino.h"
#include "nRFCrypto_Chacha.h"
#include "nrf_cc310/include/crys_chacha.h"
#include <cstring>
//--------------------------------------------------------------------+
// MACRO TYPEDEF CONSTANT ENUM DECLARATION
//--------------------------------------------------------------------+

//------------- IMPLEMENTATION -------------//
nRFCrypto_Chacha::nRFCrypto_Chacha(void) {
  _begun = false;
}

bool nRFCrypto_Chacha::begin() {
  if (_begun == true) return true;
  _begun = true;
  return _begun;
}

void nRFCrypto_Chacha::end() {
  _begun = false;
}

CRYSError_t nRFCrypto_Chacha::Process(uint8_t *msg, uint32_t msgLen, uint8_t *myData, CRYS_CHACHA_EncryptMode_t mode) {
  CRYS_CHACHAUserContext_t pContextID;
  CRYS_CHACHA_Nonce_t pNonce;
  CRYS_CHACHA_Key_t myKey;
  uint32_t initialCounter = 0;
  uint8_t finalLen = msgLen;
  if (finalLen < 64) finalLen = 64;
  uint8_t rounds = finalLen / 64;
  uint8_t extra = finalLen % 64;
  if (extra > 0) finalLen = (rounds + 1) * 64;
  uint8_t pDataOut[finalLen];
  uint8_t pDataIn[64];
  // myData: first 32 bytes = key. Next 12 bytes: Nonce.
  for (uint8_t ix = 0; ix < 32; ix++) myKey[ix] = myData[ix];
  for (uint8_t ix = 32; ix < 44; ix++) pNonce[ix - 32] = myData[ix];
  CRYSError_t error = CRYS_CHACHA_Init(&pContextID, pNonce, (CRYS_CHACHA_NonceSize_t) 1, myKey, initialCounter++, mode);
  if (error != 0) return error;
  uint8_t pos = 0;
  for (uint8_t ix = 0; ix < rounds; ix++) {
    Serial.printf("Round #%d: %d..%d / %d\n", (ix+1), (ix*64), (ix*64+63), finalLen);
    memcpy(pDataIn, (msg + pos), 64);
    error = CRYS_CHACHA_Block(&pContextID, pDataIn, 64, pDataOut + pos);
    pos += 64;
    if (error != 0) return error;
  }
  if (extra > 0) {
    Serial.printf("Extra round: %d..%d / %d\n", (rounds*64), (rounds*64+extra-1), msgLen);
    memset(pDataIn + extra, 64 - extra, 64 - extra);
    memcpy(pDataIn, (msg + pos), extra);
    error = CRYS_CHACHA_Block(&pContextID, pDataIn, 64, pDataOut + pos);
    if (error != 0) return error;
  }
  memcpy(msg, pDataOut, msgLen);
  error = CRYS_CHACHA_Finish(&pContextID, NULL, 0, pDataOut);
  if (error != 0) return error;
  return CRYS_CHACHA_Free(&pContextID);
}
