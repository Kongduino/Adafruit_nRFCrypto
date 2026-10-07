/*
   The MIT License (MIT)
   Copyright (c) 2020 Ha Thach (tinyusb.org) for Adafruit Industries
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

#ifndef ADAFRUIT_NRFCRYPTO_H_
#define ADAFRUIT_NRFCRYPTO_H_

#include "common_inc.h"
#include "rtos.h"
#include "nRFCrypto_Config.h"
#include "nRFCrypto_Random.h"
#include "nRFCrypto_Hash.h"

#if NRFCRYPTO_WITH_HKDF_HMAC
#include "nRFCrypto_HMAC.h"
#include "nRFCrypto_HKDF.h"
#endif

#include "nRFCrypto_AES.h"

#if NRFCRYPTO_WITH_CHACHA
#include "nRFCrypto_Chacha.h"
#include "nRFCrypto_ChachaPoly.h"
#endif

#include "ecc/nRFCrypto_ECC.h"

#if NRFCRYPTO_WITH_RSA
#include "rsa/nRFCrypto_RSA.h"
#endif

class Adafruit_nRFCrypto {
  public:
    Adafruit_nRFCrypto(void);
    bool begin(void);
    void end(void);
    nRFCrypto_Random Random;
  private:
    bool _begun;
};

extern Adafruit_nRFCrypto nRFCrypto;

// lastError() codes for failures outside the CC310 (its own codes are 0x00Fxxxxx).
#define NRFCRYPTO_ERR_NOT_STARTED 0xFFFF0001UL  // nRFCrypto.begin() failed
#define NRFCRYPTO_ERR_NO_MEMORY   0xFFFF0002UL  // could not copy the message to RAM
#define NRFCRYPTO_ERR_BAD_INPUT   0xFFFF0003UL  // input outside the documented range
#define NRFCRYPTO_ERR_BAD_OUTPUT  0xFFFF0004UL  // CC310 succeeded but returned an unexpected size

// Powers the CC310 on for the lifetime of the object, then restores the
// previous ENABLE state (so it powers down again if it was off before).
class nRFCrypto_PowerScope {
  public:
    nRFCrypto_PowerScope() {
      _prev = NRF_CRYPTOCELL->ENABLE;
      NRF_CRYPTOCELL->ENABLE = 1;
    }
    ~nRFCrypto_PowerScope() {
      NRF_CRYPTOCELL->ENABLE = _prev;
    }
  private:
    uint32_t _prev;
};

#include "nRFCrypto_Ed25519.h"
#include "nRFCrypto_X25519.h"

#if !CFG_DEBUG
#define VERIFY_CRYS VERIFY_ERROR
#else
#define VERIFY_CRYS(...) _GET_3RD_ARG(__VA_ARGS__, VERIFY_ERR_2ARGS, VERIFY_ERR_1ARGS)(__VA_ARGS__, dbg_strerr_crys)
const char* dbg_strerr_crys(int32_t err);
#endif

#endif /* ADAFRUIT_NRFCRYPTO_H_ */ 
