/*
   The MIT License (MIT)
   Copyright (c) 2026 Kongduino
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
#include "nRFCrypto_ChachaPoly.h"
#include <cstring>
//--------------------------------------------------------------------+
// MACRO TYPEDEF CONSTANT ENUM DECLARATION
//--------------------------------------------------------------------+

//------------- IMPLEMENTATION -------------//
nRFCrypto_ChachaPoly::nRFCrypto_ChachaPoly(void) {
  _begun = false;
}

bool nRFCrypto_ChachaPoly::begin() {
  if (_begun == true) return true;
  _begun = true;
  return _begun;
}

void nRFCrypto_ChachaPoly::end() {
  _begun = false;
}

CRYSError_t nRFCrypto_ChachaPoly::process(uint8_t* msg, size_t msgLen,
                                          const uint8_t key[KEY_LEN], const uint8_t nonce[NONCE_LEN],
                                          const uint8_t* aad, size_t aadLen,
                                          uint8_t mac[MAC_LEN], CRYS_CHACHA_EncryptMode_t mode) {
  if (!_begun) return CRYS_CHACHA_POLY_ENC_MODE_INVALID_ERROR;

  CRYS_CHACHA_Key_t chachaKey;
  CRYS_CHACHA_Nonce_t chachaNonce;
  memcpy(chachaKey, key, KEY_LEN);
  memcpy(chachaNonce, nonce, NONCE_LEN);

  // macRes is in/out: encrypt() writes the computed tag here, decrypt()
  // reads the expected tag from here and the hardware verifies it.
  CRYS_POLY_Mac_t macBuf;
  memcpy(macBuf, mac, MAC_LEN);

  CRYSError_t err = CRYS_CHACHA_POLY(chachaNonce, chachaKey, mode,
                                     (uint8_t*) aad, aadLen,
                                     msg, msgLen, msg, macBuf);
  memcpy(mac, macBuf, MAC_LEN);
  return err;
}

CRYSError_t nRFCrypto_ChachaPoly::encrypt(uint8_t* msg, size_t msgLen,
                                          const uint8_t key[KEY_LEN], const uint8_t nonce[NONCE_LEN],
                                          const uint8_t* aad, size_t aadLen,
                                          uint8_t mac[MAC_LEN]) {
  return process(msg, msgLen, key, nonce, aad, aadLen, mac, CRYS_CHACHA_Encrypt);
}

CRYSError_t nRFCrypto_ChachaPoly::decrypt(uint8_t* msg, size_t msgLen,
                                          const uint8_t key[KEY_LEN], const uint8_t nonce[NONCE_LEN],
                                          const uint8_t* aad, size_t aadLen,
                                          uint8_t mac[MAC_LEN]) {
  return process(msg, msgLen, key, nonce, aad, aadLen, mac, CRYS_CHACHA_Decrypt);
}
