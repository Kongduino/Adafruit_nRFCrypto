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

// nRFCrypto_X25519.h
// X25519 (Curve25519 ECDH) class for nRF52840 (RAK4631) using the CryptoCell CC310.
//
// Companion to nRFCrypto_Ed25519: same field/curve family, but for key
// agreement instead of signing. Byte arrays here are Little-Endian, matching
// RFC 7748 test vectors directly (unlike the Big-Endian RSA/ECDSA classes).
//
// Scalars are clamped and the peer u-coordinate's top bit is masked before
// they reach the CC310, as RFC 7748 section 5 requires, so results match any
// conforming software X25519 whatever the hardware does internally.
//
// Handles: CC310 power bracketing, DMA alignment of buffers. Every operation
// (re)starts nRFCrypto if needed and never calls nRFCrypto.end(), so it is
// safe to use either after a single begin() or between per-call
// nRFCrypto.begin()/end() pairs owned by the caller. A single instance is NOT
// thread-safe; guard with a mutex if used from several FreeRTOS tasks.

#ifndef NRFCRYPTO_X25519_H_
#define NRFCRYPTO_X25519_H_

#include <Arduino.h>
#include "Adafruit_nRFCrypto.h"
#include "nrf_cc310/include/crys_ec_mont_api.h"

class nRFCrypto_X25519 {
public:
  enum : size_t {
    PUBLIC_KEY_LEN = 32,
    SECRET_KEY_LEN = 32,
    SHARED_SECRET_LEN = 32
  };

  nRFCrypto_X25519()
    : _lastErr(0) {}

  bool begin() {
    return nRFCrypto.begin();
  }

  // Error code of the last operation: CRYS_OK, a CryptoCell code, or an
  // NRFCRYPTO_ERR_* code from Adafruit_nRFCrypto.h. Set on every failure,
  // except that agree() returning false with CRYS_OK means an all-zero
  // shared secret.
  uint32_t lastError() const {
    return _lastErr;
  }

  // Generate a random keypair. The secret comes back clamped.
  bool keygen(uint8_t pub[PUBLIC_KEY_LEN], uint8_t secret[SECRET_KEY_LEN]) {
    if (!nRFCrypto.begin()) return fail(NRFCRYPTO_ERR_NOT_STARTED);
    alignas(4) uint8_t pk[PUBLIC_KEY_LEN];
    alignas(4) uint8_t sk[SECRET_KEY_LEN];
    size_t pkLen = sizeof(pk);
    size_t skLen = sizeof(sk);
    bool ok;
    {
      nRFCrypto_PowerScope cc;
      _lastErr = CRYS_ECMONT_KeyPair(
        pk, &pkLen, sk, &skLen,
        (void*)nRFCrypto.Random.getContext(), CRYS_RND_GenerateVector, &_temp);
      if (_lastErr == CRYS_OK && !(pkLen == PUBLIC_KEY_LEN && skLen == SECRET_KEY_LEN)) _lastErr = NRFCRYPTO_ERR_BAD_OUTPUT;
      ok = _lastErr == CRYS_OK;
    }
    if (ok) {
      memcpy(pub, pk, PUBLIC_KEY_LEN);
      memcpy(secret, sk, SECRET_KEY_LEN);
    }
    wipe(sk, sizeof(sk));
    wipe(&_temp, sizeof(_temp));
    return ok;
  }

  // Derives the public key that corresponds to a given secret scalar.
  bool publicKey(uint8_t pub[PUBLIC_KEY_LEN], const uint8_t secret[SECRET_KEY_LEN]) {
    if (!nRFCrypto.begin()) return fail(NRFCRYPTO_ERR_NOT_STARTED);
    alignas(4) uint8_t pk[PUBLIC_KEY_LEN];
    alignas(4) uint8_t sk[SECRET_KEY_LEN];
    memcpy(sk, secret, sizeof(sk));
    clamp(sk);
    size_t pkLen = sizeof(pk);
    bool ok;
    {
      nRFCrypto_PowerScope cc;
      _lastErr = CRYS_ECMONT_ScalarmultBase(pk, &pkLen, sk, sizeof(sk), &_temp);
      if (_lastErr == CRYS_OK && !(pkLen == PUBLIC_KEY_LEN)) _lastErr = NRFCRYPTO_ERR_BAD_OUTPUT;
      ok = _lastErr == CRYS_OK;
    }
    if (ok) memcpy(pub, pk, PUBLIC_KEY_LEN);
    wipe(sk, sizeof(sk));
    wipe(&_temp, sizeof(_temp));
    return ok;
  }

  // ECDH: shared = secret * peerPublic. Fails if the result is all zeros
  // (peer sent a small-order point, RFC 7748 section 6.1). Run the result
  // through a KDF/hash before using it as a symmetric key - a raw X25519
  // output is not uniformly random and must not be used directly as key
  // material.
  bool agree(uint8_t shared[SHARED_SECRET_LEN], const uint8_t secret[SECRET_KEY_LEN], const uint8_t peerPublic[PUBLIC_KEY_LEN]) {
    if (!nRFCrypto.begin()) return fail(NRFCRYPTO_ERR_NOT_STARTED);
    alignas(4) uint8_t sh[SHARED_SECRET_LEN];
    alignas(4) uint8_t sk[SECRET_KEY_LEN];
    alignas(4) uint8_t pk[PUBLIC_KEY_LEN];
    memcpy(sk, secret, sizeof(sk));
    memcpy(pk, peerPublic, sizeof(pk));
    clamp(sk);
    pk[31] &= 0x7F;
    size_t shLen = sizeof(sh);
    bool ok;
    {
      nRFCrypto_PowerScope cc;
      _lastErr = CRYS_ECMONT_Scalarmult(sh, &shLen, sk, sizeof(sk), pk, sizeof(pk), &_temp);
      if (_lastErr == CRYS_OK && !(shLen == SHARED_SECRET_LEN)) _lastErr = NRFCRYPTO_ERR_BAD_OUTPUT;
      ok = _lastErr == CRYS_OK;
    }
    if (ok) {
      uint8_t acc = 0;
      for (size_t i = 0; i < SHARED_SECRET_LEN; i++) acc |= sh[i];
      ok = acc != 0;
    }
    if (ok) memcpy(shared, sh, SHARED_SECRET_LEN);
    wipe(sk, sizeof(sk));
    wipe(sh, sizeof(sh));
    wipe(&_temp, sizeof(_temp));
    return ok;
  }

private:
  // Records why an operation failed before or outside the CC310 call.
  bool fail(uint32_t err) {
    _lastErr = err;
    return false;
  }

  static void clamp(uint8_t k[SECRET_KEY_LEN]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
  }

  static void wipe(void* p, size_t n) {
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) *v++ = 0;
  }

  uint32_t _lastErr;

  // CryptoCell scratch state (4-byte aligned for DMA)
  alignas(4) CRYS_ECMONT_TempBuff_t _temp;
};

#endif /* NRFCRYPTO_X25519_H_ */
