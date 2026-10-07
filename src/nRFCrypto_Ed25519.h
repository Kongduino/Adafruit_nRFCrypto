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
// Handles: CC310 power bracketing, DMA alignment of buffers. Randomness comes
// from the shared nRFCrypto.Random context.
//
// Every operation (re)starts nRFCrypto if needed and never calls
// nRFCrypto.end(), so it is safe to use either after a single begin() or
// between per-call nRFCrypto.begin()/end() pairs owned by the caller.
// A single instance is NOT thread-safe; guard with a mutex if used from
// several FreeRTOS tasks.

#ifndef NRFCRYPTO_ED25519_H_
#define NRFCRYPTO_ED25519_H_

#include <Arduino.h>
#include "Adafruit_nRFCrypto.h"
#include "nrf_cc310/include/crys_ec_edw_api.h"
#include "nrf_cc310/include/crys_rnd.h"
#include "nrf_cc310/include/ssi_pal_mutex.h"

// Internal functions of libnrf_cc310 0.9.13, not in its public headers. The
// signatures and call sequence are taken from that binary's own
// EcEdwSeedKeyPair / EcEdwSign; any other library build may differ.
extern "C" {
extern SaSi_PalMutex sasiAsymCryptoMutex;
SaSiError_t SaSi_PalPowerSaveModeSelect(uint32_t isPowerSaveMode);
CRYSError_t PkaInitPka(uint32_t opSizeInBits, uint32_t regSizeInPkaWords, uint32_t* pRegsCount);
void PkaFinishAndMutexUnlock(uint32_t regsCount);
const void* EcEdwGetDomain25519(void);
CRYSError_t EcEdwScalarMultBase(uint32_t* pX, uint32_t* pY, const uint32_t* pScalar,
                                size_t scalarSizeInWords, const void* pDomain);
}

class nRFCrypto_Ed25519 {
public:
  enum : size_t {
    PUBLIC_KEY_LEN = 32,
    SECRET_KEY_LEN = 64,  // seed (32) || public key (32), CC310 format
    SIGNATURE_LEN = 64
  };

  nRFCrypto_Ed25519()
    : _lastErr(0) {}

  bool begin() {
    return nRFCrypto.begin();
  }

  // Error code of the last operation: CRYS_OK, a CryptoCell code, or an
  // NRFCRYPTO_ERR_* code from Adafruit_nRFCrypto.h. Set on every failure.
  uint32_t lastError() const {
    return _lastErr;
  }

  // Generate a keypair.
  //   pub:    32 bytes out
  //   secret: 64 bytes out (seed || pub).
  bool keygen(uint8_t pub[PUBLIC_KEY_LEN], uint8_t secret[SECRET_KEY_LEN]) {
    if (!nRFCrypto.begin()) return fail(NRFCRYPTO_ERR_NOT_STARTED);
    alignas(4) uint8_t sk[SECRET_KEY_LEN];
    alignas(4) uint8_t pk[PUBLIC_KEY_LEN];
    size_t sk_len = sizeof(sk);
    size_t pk_len = sizeof(pk);
    bool ok;
    {
      nRFCrypto_PowerScope cc;
      _lastErr = CRYS_ECEDW_KeyPair(
        sk, &sk_len, pk, &pk_len,
        (void*)nRFCrypto.Random.getContext(), CRYS_RND_GenerateVector, &_temp);
      if (_lastErr == CRYS_OK && !(sk_len == SECRET_KEY_LEN && pk_len == PUBLIC_KEY_LEN)) _lastErr = NRFCRYPTO_ERR_BAD_OUTPUT;
      ok = _lastErr == CRYS_OK;
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
    if (!nRFCrypto.begin()) return fail(NRFCRYPTO_ERR_NOT_STARTED);
    alignas(4) uint8_t sk[SECRET_KEY_LEN];
    alignas(4) uint8_t sg[SIGNATURE_LEN];
    memcpy(sk, secret, sizeof(sk));
    size_t sg_len = sizeof(sg);
    uint8_t* owned = nullptr;
    const uint8_t* m = alignedView(msg, msg_len, &owned);
    if (!m) {
      wipe(sk, sizeof(sk));
      return fail(NRFCRYPTO_ERR_NO_MEMORY);
    }
    bool ok;
    {
      nRFCrypto_PowerScope cc;
      _lastErr = CRYS_ECEDW_Sign(
        sg, &sg_len, (uint8_t*)m, msg_len,
        sk, sizeof(sk), &_temp);
      if (_lastErr == CRYS_OK && !(sg_len == SIGNATURE_LEN)) _lastErr = NRFCRYPTO_ERR_BAD_OUTPUT;
      ok = _lastErr == CRYS_OK;
    }
    if (ok) memcpy(sig, sg, SIGNATURE_LEN);
    if (owned) free(owned);
    wipe(sk, sizeof(sk));
    wipe(&_temp, sizeof(_temp));
    return ok;
  }

  // Verify a signature. Returns true only if valid.
  // Pass a 4-byte aligned msg in RAM to avoid a heap copy.
  bool verify(
    const uint8_t sig[SIGNATURE_LEN],
    const uint8_t* msg, size_t msg_len,
    const uint8_t pub[PUBLIC_KEY_LEN]) {
    if (!nRFCrypto.begin()) return fail(NRFCRYPTO_ERR_NOT_STARTED);
    alignas(4) uint8_t sg[SIGNATURE_LEN];
    alignas(4) uint8_t pk[PUBLIC_KEY_LEN];
    memcpy(sg, sig, sizeof(sg));
    memcpy(pk, pub, sizeof(pk));
    uint8_t* owned = nullptr;
    const uint8_t* m = alignedView(msg, msg_len, &owned);
    if (!m) return fail(NRFCRYPTO_ERR_NO_MEMORY);
    {
      nRFCrypto_PowerScope cc;
      _lastErr = CRYS_ECEDW_Verify(
        sg, sizeof(sg), pk, sizeof(pk),
        (uint8_t*)m, msg_len, &_temp);
    }
    if (owned) free(owned);
    return _lastErr == CRYS_OK;
  }

  // Encoded Ed25519 point scalar * B (B = base point), for building signatures
  // such as XEdDSA's R = r * B. scalar is 32 bytes little-endian and must be
  // below 2^253 (any value reduced mod q is). The CC310 loop runs once per two
  // bits of the scalar, so q * 4 is added first: every scalar then has exactly
  // 255 bits and the run time does not depend on it.
  bool scalarMultBase(uint8_t point[PUBLIC_KEY_LEN], const uint8_t scalar[32]) {
    static const uint32_t FOUR_Q[8] = {0x73d74fb4, 0x60498c69, 0x8bde7359, 0x537be77a,
                                       0x00000000, 0x00000000, 0x00000000, 0x40000000};
    if (scalar[31] >= 0x20) return fail(NRFCRYPTO_ERR_BAD_INPUT);
    if (!nRFCrypto.begin()) return fail(NRFCRYPTO_ERR_NOT_STARTED);
    uint32_t s[8];
    alignas(4) uint32_t x[8];
    alignas(4) uint32_t y[8];
    memcpy(s, scalar, sizeof(s));
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
      carry += (uint64_t)s[i] + FOUR_Q[i];
      s[i] = (uint32_t)carry;
      carry >>= 32;
    }
    const void* domain = EcEdwGetDomain25519();
    uint32_t regsCount = 30;
    {
      nRFCrypto_PowerScope cc;
      _lastErr = SaSi_PalMutexLock(&sasiAsymCryptoMutex, 0xFFFFFFFF);
      if (_lastErr != CRYS_OK) {
        wipe(s, sizeof(s));
        return false;
      }
      _lastErr = SaSi_PalPowerSaveModeSelect(0);
      if (_lastErr == CRYS_OK)
        _lastErr = PkaInitPka(((const uint32_t*)domain)[8], 0, &regsCount);
      if (_lastErr == CRYS_OK)
        _lastErr = EcEdwScalarMultBase(x, y, s, 8, domain);
      PkaFinishAndMutexUnlock(regsCount);
    }
    wipe(s, sizeof(s));
    if (_lastErr != CRYS_OK) return false;
    y[7] |= x[0] << 31;  // sign of x into the top bit of y (RFC 8032 encoding)
    memcpy(point, y, PUBLIC_KEY_LEN);
    wipe(x, sizeof(x));
    return true;
  }

private:
  // Records why an operation failed before or outside the CC310 call.
  bool fail(uint32_t err) {
    _lastErr = err;
    return false;
  }

  static void wipe(void* p, size_t n) {
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) *v++ = 0;
  }

  // Returns a 4-byte aligned, RAM-resident view of the data (CC310 DMA cannot
  // read flash). Copies into a malloc'd buffer if the input is unaligned or
  // not in RAM; caller must free() *owned if non-null.
  static const uint8_t* alignedView(const uint8_t* in, size_t len, uint8_t** owned) {
    *owned = nullptr;
    if (len == 0) return in;
    if (((uintptr_t)in & 3) == 0 && (uintptr_t)in >= 0x20000000) return in;
    uint8_t* copy = (uint8_t*)malloc(len);
    if (!copy) return nullptr;
    memcpy(copy, in, len);
    *owned = copy;
    return copy;
  }

  uint32_t _lastErr;

  // CryptoCell scratch state (4-byte aligned for DMA)
  alignas(4) CRYS_ECEDW_TempBuff_t _temp;
};

#endif /* NRFCRYPTO_ED25519_H_ */
