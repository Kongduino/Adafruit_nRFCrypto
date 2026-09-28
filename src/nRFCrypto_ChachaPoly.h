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

#ifndef NRFCRYPTO_CHACHAPOLY_H_
#define NRFCRYPTO_CHACHAPOLY_H_

#include "nrf_cc310/include/crys_chacha_poly_error.h"
#include "nrf_cc310/include/crys_chacha_poly.h"

class nRFCrypto_ChachaPoly {
  public:
    enum : size_t {
      KEY_LEN = 32,
      NONCE_LEN = 12,
      MAC_LEN = 16
    };

    nRFCrypto_ChachaPoly(void);
    bool begin(void);
    void end(void);

    // ChaCha20-Poly1305 AEAD (RFC 8439 layout: 32-byte key, 12-byte nonce,
    // 16-byte tag). Encrypts msg in place and writes the tag to mac.
    // aad must be non-null with aadLen > 0 - the CC310 hardware rejects
    // empty additional data; pass a fixed 1-byte tag if your protocol has
    // none of its own. Returns CRYS_OK on success.
    CRYSError_t encrypt(uint8_t* msg, size_t msgLen,
                        const uint8_t key[KEY_LEN], const uint8_t nonce[NONCE_LEN],
                        const uint8_t* aad, size_t aadLen,
                        uint8_t mac[MAC_LEN]);

    // Decrypts msg in place and verifies it against mac (as produced by
    // encrypt() with the same key/nonce/aad). Returns CRYS_OK only if the
    // tag matches; for any other return value, msg is untrusted - discard it.
    CRYSError_t decrypt(uint8_t* msg, size_t msgLen,
                        const uint8_t key[KEY_LEN], const uint8_t nonce[NONCE_LEN],
                        const uint8_t* aad, size_t aadLen,
                        uint8_t mac[MAC_LEN]);

  private:
    CRYSError_t process(uint8_t* msg, size_t msgLen,
                        const uint8_t key[KEY_LEN], const uint8_t nonce[NONCE_LEN],
                        const uint8_t* aad, size_t aadLen,
                        uint8_t mac[MAC_LEN], CRYS_CHACHA_EncryptMode_t mode);

    bool _begun;
};

#endif /* NRFCRYPTO_CHACHAPOLY_H_ */
