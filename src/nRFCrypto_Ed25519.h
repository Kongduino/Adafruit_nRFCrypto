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

// nRFCrypto_Ed25519.h
// Ed25519 class for nRF52840 (RAK4631) using the CryptoCell CC310.
//
// Handles: CC310 power bracketing, RND init, DMA alignment of buffers.
// Each instance owns its scratch buffers. A single instance is NOT
// thread-safe; guard with a mutex if used from several FreeRTOS tasks.

#ifndef NRFCRYPTO_ED25519_H_
#define NRFCRYPTO_ED25519_H_

#include <Arduino.h>
#include "Adafruit_nRFCrypto.h"
#include "nrf_cc310/include/crys_ec_edw_api.h"
#include "nrf_cc310/include/crys_rnd.h"

class nRFCrypto_Ed25519 {
public:
  enum : size_t {
    PUBLIC_KEY_LEN = 32,
    SECRET_KEY_LEN = 64,  // seed (32) || public key (32), CC310 format
    SIGNATURE_LEN = 64
  };

  nRFCrypto_Ed25519()
    : _begun(false), _lastErr(0) {}

  bool begin() {
    if (_begun) return true;
    _begun = nRFCrypto.begin();
    uint8_t seed[32];
    nRFCrypto.Random.generate(seed, 32);
    delay(10);
    NRF_CRYPTOCELL->ENABLE = 1;
    _lastErr = CRYS_RndInit(&_rndState, &_rndWork);
    delay(10);
    return _begun;
  }
  // Last CryptoCell error code (0 = CRYS_OK).
  uint32_t lastError() const {
    return _lastErr;
  }

  // Generate a keypair.
  //   pub:    32 bytes out
  //   secret: 64 bytes out (seed || pub).
  bool keygen(uint8_t pub[PUBLIC_KEY_LEN], uint8_t secret[SECRET_KEY_LEN]) {
    if (!_begun) return false;
    alignas(4) uint8_t sk[SECRET_KEY_LEN];
    alignas(4) uint8_t pk[PUBLIC_KEY_LEN];
    size_t sk_len = sizeof(sk);
    size_t pk_len = sizeof(pk);
    bool ok = false;
    {
      PowerScope cc;
      if (_lastErr == CRYS_OK) {
        _lastErr = CRYS_ECEDW_KeyPair(
          sk, &sk_len, pk, &pk_len,
          (void*)&_rndState, CRYS_RND_GenerateVector, &_temp);
        ok = (_lastErr == CRYS_OK) && sk_len == SECRET_KEY_LEN && pk_len == PUBLIC_KEY_LEN;
      }
    }
    if (ok) {
      memcpy(secret, sk, SECRET_KEY_LEN);
      memcpy(pub, pk, PUBLIC_KEY_LEN);
    }
    wipe(sk, sizeof(sk));
    wipe(&_temp, sizeof(_temp));
    return ok;
  }

  // Sign msg with a 64-byte secret key. sig is 64 bytes out.
  bool sign(
    uint8_t sig[SIGNATURE_LEN],
    const uint8_t* msg, size_t msg_len,
    const uint8_t secret[SECRET_KEY_LEN]) {
    if (!_begun) return false;
    alignas(4) uint8_t sk[SECRET_KEY_LEN];
    alignas(4) uint8_t sg[SIGNATURE_LEN];
    memcpy(sk, secret, sizeof(sk));
    size_t sg_len = sizeof(sg);
    uint8_t* owned = nullptr;
    const uint8_t* m = alignedView(msg, msg_len, &owned);
    if (!m) {
      wipe(sk, sizeof(sk));
      return false;
    }
    bool ok = false;
    {
      PowerScope cc;
      _lastErr = CRYS_ECEDW_Sign(
        sg, &sg_len, (uint8_t*)m, msg_len,
        sk, sizeof(sk), &_temp);
      ok = (_lastErr == CRYS_OK) && sg_len == SIGNATURE_LEN;
    }
    if (ok) memcpy(sig, sg, SIGNATURE_LEN);
    if (owned) free(owned);
    wipe(sk, sizeof(sk));
    wipe(&_temp, sizeof(_temp));
    return ok;
  }

  // Verify a signature. Returns true only if valid.
  bool verify(
    const uint8_t sig[SIGNATURE_LEN],
    const uint8_t* msg, size_t msg_len,
    const uint8_t pub[PUBLIC_KEY_LEN]) {
    if (!_begun) return false;
    alignas(4) uint8_t sg[SIGNATURE_LEN];
    alignas(4) uint8_t pk[PUBLIC_KEY_LEN];
    memcpy(sg, sig, sizeof(sg));
    memcpy(pk, pub, sizeof(pk));
    uint8_t* owned = nullptr;
    const uint8_t* m = alignedView(msg, msg_len, &owned);
    if (!m) return false;
    {
      PowerScope cc;
      _lastErr = CRYS_ECEDW_Verify(
        sg, sizeof(sg), pk, sizeof(pk),
        (uint8_t*)m, msg_len, &_temp);
    }
    if (owned) free(owned);
    return _lastErr == CRYS_OK;
  }

private:
  // Powers the CC310 on for the lifetime of the object, then restores the
  // previous ENABLE state (so it powers down again if it was off before).
  class PowerScope {
  public:
    PowerScope() {
      _prev = NRF_CRYPTOCELL->ENABLE;
      NRF_CRYPTOCELL->ENABLE = 1;
    }
    ~PowerScope() {
      NRF_CRYPTOCELL->ENABLE = _prev;
    }
  private:
    uint32_t _prev;
  };

  static void wipe(void* p, size_t n) {
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) *v++ = 0;
  }

  // Returns a 4-byte aligned view of the data. Copies into a malloc'd buffer
  // if the input is unaligned; caller must free() *owned if non-null.
  static const uint8_t* alignedView(const uint8_t* in, size_t len, uint8_t** owned) {
    *owned = nullptr;
    if (((uintptr_t)in & 3) == 0 || len == 0) return in;
    uint8_t* copy = (uint8_t*)malloc(len);
    if (!copy) return nullptr;
    memcpy(copy, in, len);
    *owned = copy;
    return copy;
  }

  bool _begun;
  uint32_t _lastErr;

  // CryptoCell scratch state (4-byte aligned for DMA)
  alignas(4) CRYS_RND_State_t _rndState;
  alignas(4) CRYS_RND_WorkBuff_t _rndWork;
  alignas(4) CRYS_ECEDW_TempBuff_t _temp;
};

#endif /* NRFCRYPTO_ED25519_H_ */
