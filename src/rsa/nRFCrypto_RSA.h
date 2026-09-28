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

// nRFCrypto_RSA: PKCS#1 v1.5 sign/verify on top of the CC310 RSA hardware.
//
// There is deliberately no key generation here: RSA keygen at 2048 bits
// (the max this hardware's PKA supports - see CRYS_RSA_MAX_KEY_GENERATION_HW_SIZE_BITS)
// is impractically slow on a Cortex-M4. Provision N/E (and D for signing)
// from a key generated elsewhere (e.g. openssl) via the PublicKey/PrivateKey
// begin() calls, then sign/verify here.

#ifndef NRFCRYPTO_RSA_H_
#define NRFCRYPTO_RSA_H_

#include "../nRFCrypto_Config.h"
#if NRFCRYPTO_WITH_RSA

#include "nrf_cc310/include/crys_rsa_types.h"
#include "nrf_cc310/include/crys_rsa_error.h"
#include "nrf_cc310/include/crys_rsa_build.h"
#include "nrf_cc310/include/crys_rsa_schemes.h"

#include "nRFCrypto_RSA_PublicKey.h"
#include "nRFCrypto_RSA_PrivateKey.h"

class nRFCrypto_RSA {
  public:
    //------------- Static Members -------------//
    // Signs msg with key, PKCS#1 v1.5. hashMode picks the digest CC310 hashes
    // msg with internally (e.g. CRYS_RSA_HASH_SHA256_mode). sig must be at
    // least key.getModulusSize() bytes. Returns the signature length written
    // (== modulus size), or 0 on failure.
    static uint16_t sign(nRFCrypto_RSA_PrivateKey& key, CRYS_RSA_HASH_OpMode_t hashMode,
                         const uint8_t* msg, uint32_t msgLen,
                         uint8_t* sig, uint16_t sigBufSize);

    // Verifies a PKCS#1 v1.5 signature. sigLen must equal key.getModulusSize().
    static bool verify(nRFCrypto_RSA_PublicKey& key, CRYS_RSA_HASH_OpMode_t hashMode,
                        const uint8_t* msg, uint32_t msgLen,
                        const uint8_t* sig, uint16_t sigLen);

  public:
    nRFCrypto_RSA(void);
    bool begin(void);
    void end(void);
};

#endif /* NRFCRYPTO_WITH_RSA */
#endif /* NRFCRYPTO_RSA_H_ */
