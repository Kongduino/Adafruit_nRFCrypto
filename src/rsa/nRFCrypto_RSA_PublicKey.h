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

#ifndef NRFCRYPTO_RSA_PUBLICKEY_H_
#define NRFCRYPTO_RSA_PUBLICKEY_H_

#include "../nRFCrypto_Config.h"
#if NRFCRYPTO_WITH_RSA

class nRFCrypto_RSA;

class nRFCrypto_RSA_PublicKey {
  public:
    nRFCrypto_RSA_PublicKey(void);

    // Builds the key from a modulus (N) and public exponent (E), both
    // Big-Endian byte streams. ModulusSize must be one of 64/128/256 bytes
    // (512/1024/2048 bits) on this hardware.
    bool begin(const uint8_t* modulus, uint16_t modulusSize, const uint8_t* exponent, uint16_t exponentSize);
    void end(void);

    // Modulus size in bytes; also the required signature/ciphertext buffer size.
    uint16_t getModulusSize(void) { return _modulusSize; }

  private:
    CRYS_RSAUserPubKey_t _key;
    uint16_t _modulusSize;
    bool _begun;

    friend class nRFCrypto_RSA;
};

#endif /* NRFCRYPTO_WITH_RSA */
#endif /* NRFCRYPTO_RSA_PUBLICKEY_H_ */
