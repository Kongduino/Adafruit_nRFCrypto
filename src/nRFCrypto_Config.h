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

// Feature switches for optional, heavier modules. Each flag defaults to
// enabled (matching prior releases) unless already defined - either edit
// the default below, or leave this file alone and pass e.g.
// -DNRFCRYPTO_WITH_RSA=0 as a compiler build flag (works with PlatformIO's
// build_flags, or Arduino IDE via boards.txt build.extra_flags).

#ifndef NRFCRYPTO_CONFIG_H_
#define NRFCRYPTO_CONFIG_H_

// RSA (nRFCrypto_RSA / _PublicKey / _PrivateKey). Its key/context structs
// are the biggest scratch buffers in this library (several KB) - set to 0
// if you don't need RSA to skip compiling it entirely and save flash.
#ifndef NRFCRYPTO_WITH_RSA
#define NRFCRYPTO_WITH_RSA 1
#endif

// HKDF + HMAC (nRFCrypto_HKDF / nRFCrypto_HMAC) - set to 0 if you don't need
// key derivation / message authentication to skip compiling them entirely
// and save flash.
#ifndef NRFCRYPTO_WITH_HKDF_HMAC
#define NRFCRYPTO_WITH_HKDF_HMAC 1
#endif

// ChaCha20 + ChaCha20-Poly1305 (nRFCrypto_Chacha / nRFCrypto_ChachaPoly) -
// set to 0 if you don't need the ChaCha stream cipher / AEAD to skip
// compiling them entirely and save flash.
#ifndef NRFCRYPTO_WITH_CHACHA
#define NRFCRYPTO_WITH_CHACHA 1
#endif

#endif /* NRFCRYPTO_CONFIG_H_ */
