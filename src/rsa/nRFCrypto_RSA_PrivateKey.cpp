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

#include "nrf_cc310/include/crys_rsa_build.h"

#include "Adafruit_nRFCrypto.h"

//--------------------------------------------------------------------+
// MACRO TYPEDEF CONSTANT ENUM DECLARATION
//--------------------------------------------------------------------+


//------------- IMPLEMENTATION -------------//
nRFCrypto_RSA_PrivateKey::nRFCrypto_RSA_PrivateKey(void) {
  _modulusSize = 0;
  _begun = false;
}

bool nRFCrypto_RSA_PrivateKey::begin(const uint8_t* modulus, uint16_t modulusSize,
                                      const uint8_t* privExponent, uint16_t privExponentSize,
                                      const uint8_t* pubExponent, uint16_t pubExponentSize) {
  uint32_t err = CRYS_RSA_Build_PrivKey(&_key,
                                         (uint8_t*) privExponent, privExponentSize,
                                         (uint8_t*) pubExponent, pubExponentSize,
                                         (uint8_t*) modulus, modulusSize);
  VERIFY_CRYS(err, false);

  _modulusSize = modulusSize;
  _begun = true;
  return true;
}

void nRFCrypto_RSA_PrivateKey::end(void) {
  _begun = false;
  _modulusSize = 0;
}
