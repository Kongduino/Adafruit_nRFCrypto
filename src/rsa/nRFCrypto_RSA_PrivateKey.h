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

#ifndef NRFCRYPTO_RSA_PRIVATEKEY_H_
#define NRFCRYPTO_RSA_PRIVATEKEY_H_

#include "../nRFCrypto_Config.h"
#if NRFCRYPTO_WITH_RSA

class nRFCrypto_RSA;

class nRFCrypto_RSA_PrivateKey {
  public:
    nRFCrypto_RSA_PrivateKey(void);

    // Builds the key from a modulus (N), private exponent (D) and public
    // exponent (E), all Big-Endian byte streams. This is the non-CRT form;
    // there is no on-device key generation on this hardware (RSA-2048
    // keygen is impractical on a Cortex-M4) - provision N/D/E from a key
    // generated elsewhere (e.g. openssl).
    bool begin(const uint8_t* modulus, uint16_t modulusSize,
               const uint8_t* privExponent, uint16_t privExponentSize,
               const uint8_t* pubExponent, uint16_t pubExponentSize);
    void end(void);

    // Modulus size in bytes; also the required signature buffer size.
    uint16_t getModulusSize(void) { return _modulusSize; }

  private:
    CRYS_RSAUserPrivKey_t _key;
    uint16_t _modulusSize;
    bool _begun;

    friend class nRFCrypto_RSA;
};

#endif /* NRFCRYPTO_WITH_RSA */
#endif /* NRFCRYPTO_RSA_PRIVATEKEY_H_ */
