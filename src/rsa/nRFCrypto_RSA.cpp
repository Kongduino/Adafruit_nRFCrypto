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

#include "nrf_cc310/include/crys_rsa_schemes.h"

#include "Adafruit_nRFCrypto.h"

//--------------------------------------------------------------------+
// MACRO TYPEDEF CONSTANT ENUM DECLARATION
//--------------------------------------------------------------------+

//--------------------------------------------------------------------+
// RSA
//--------------------------------------------------------------------+

uint16_t nRFCrypto_RSA::sign(nRFCrypto_RSA_PrivateKey& key, CRYS_RSA_HASH_OpMode_t hashMode,
                             const uint8_t* msg, uint32_t msgLen,
                             uint8_t* sig, uint16_t sigBufSize) {
  VERIFY(key._begun, 0);
  VERIFY(sigBufSize >= key._modulusSize, 0);

  CRYS_RSAPrivUserContext_t* ctx = (CRYS_RSAPrivUserContext_t*) rtos_malloc(sizeof(CRYS_RSAPrivUserContext_t));
  VERIFY(ctx, 0);

  uint16_t sigLen = sigBufSize;
  uint32_t err = SaSi_RsaSign(nRFCrypto.Random.getContext(), CRYS_RND_GenerateVector,
                              ctx, &key._key, hashMode, CRYS_PKCS1_NO_MGF, 0,
                              (uint8_t*) msg, msgLen, sig, &sigLen, CRYS_PKCS1_VER15);
  rtos_free(ctx);

  VERIFY_CRYS(err, 0);
  return sigLen;
}

bool nRFCrypto_RSA::verify(nRFCrypto_RSA_PublicKey& key, CRYS_RSA_HASH_OpMode_t hashMode,
                           const uint8_t* msg, uint32_t msgLen,
                           const uint8_t* sig, uint16_t sigLen) {
  VERIFY(key._begun, false);
  VERIFY(sigLen == key._modulusSize, false);

  CRYS_RSAPubUserContext_t* ctx = (CRYS_RSAPubUserContext_t*) rtos_malloc(sizeof(CRYS_RSAPubUserContext_t));
  VERIFY(ctx, false);

  uint32_t err = SaSi_RsaVerify(ctx, &key._key, hashMode, CRYS_PKCS1_NO_MGF, 0,
                                (uint8_t*) msg, msgLen, (uint8_t*) sig, CRYS_PKCS1_VER15);
  rtos_free(ctx);

  VERIFY_CRYS(err, false);
  return true;
}

nRFCrypto_RSA::nRFCrypto_RSA(void) {

}

bool nRFCrypto_RSA::begin(void) {
  return true;
}

void nRFCrypto_RSA::end(void) {

}
