/*
   The MIT License (MIT)
   Copyright (c) 2021 by Kongduino
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

#include "nRFCrypto_Chacha.h"
#include "nrf_cc310/include/crys_chacha.h"
#include <cstring>
//--------------------------------------------------------------------+
// MACRO TYPEDEF CONSTANT ENUM DECLARATION
//--------------------------------------------------------------------+

//------------- IMPLEMENTATION -------------//
nRFCrypto_Chacha::nRFCrypto_Chacha(void) {
  _begun = false;
}

bool nRFCrypto_Chacha::begin() {
  if (_begun == true) return true;
  _begun = true;
  return _begun;
}

void nRFCrypto_Chacha::end() {
  _begun = false;
}

int nRFCrypto_Chacha::Process(
      uint8_t *pDataIn,  /*!< [in] A pointer to the buffer of the input data to the CHACHA.
      The pointer does not need to be aligned. must not be null. */
      uint32_t dataInSize, /* must not be 0 */
      CRYS_CHACHA_Nonce_t pNonce,
      CRYS_CHACHA_Key_t pKey,
      uint32_t keyLen, /* must not be 0 */
      uint8_t *pDataOut, /*!< [out] A pointer to the buffer of the output data from the CHACHA.
      The pointer does not need to be aligned. must not be null. */
      CRYS_CHACHA_EncryptMode_t modeFlag,
      uint32_t initialCounter
      ) {
  /*
    pDataIn:  the message you want to en/decrypt. needs to be a multiple of 32 bytes.
    msgLen:   its length
    pNonce:    the IV (12 bytes)
    pKey:     the key (max size 32 bytes)
    pKeyLen:  its length
    pDataOut: the return buffer.
    modeFlag: encryptFlag / decryptFlag
  */
  if (!_begun) return -1;
  CRYS_CHACHAUserContext_t pContext;
  CRYSError_t error = CRYS_CHACHA(
    pNonce, (CRYS_CHACHA_NonceSize_t) 96, pKey, initialCounter,
    modeFlag, pDataIn, dataInSize, pDataOut
  );
}
