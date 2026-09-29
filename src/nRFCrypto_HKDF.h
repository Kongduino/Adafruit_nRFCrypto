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

#ifndef NRFCRYPTO_HKDF_H_
#define NRFCRYPTO_HKDF_H_

#include "nRFCrypto_Config.h"
#if NRFCRYPTO_WITH_HKDF_HMAC

#include "nrf_cc310/include/crys_hkdf.h"

class nRFCrypto_HKDF {
  public:
    // RFC 5869 HKDF (Extract-and-Expand) in one call. salt/info may be NULL
    // (with saltLen/infoLen 0) - salt doesn't need to be secret, just unique
    // per context. isStrongKey=true skips the extract phase and uses ikm
    // directly as the pseudorandom key; only set it if ikm is already
    // uniformly random (e.g. hashed first) - for a raw ECDH shared secret,
    // leave it false and let HKDF-Extract do that job.
    static bool derive(CRYS_HKDF_HASH_OpMode_t hashMode,
                       const uint8_t* salt, size_t saltLen,
                       const uint8_t* ikm, uint32_t ikmLen,
                       const uint8_t* info, uint32_t infoLen,
                       uint8_t* okm, uint32_t okmLen,
                       bool isStrongKey = false);
};

#endif /* NRFCRYPTO_WITH_HKDF_HMAC */
#endif /* NRFCRYPTO_HKDF_H_ */
