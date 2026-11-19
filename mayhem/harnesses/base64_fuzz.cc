// Fuzzes the strict RFC 4648 base64 codec in hwy/contrib/base64/base64-inl.h
// (hwy::HWY_NAMESPACE::Base64Decode / Base64Encode, static target).
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vector>

#include "hwy/base.h"
#include "hwy/highway.h"
#include "hwy/contrib/base64/base64-inl.h"

namespace hn = hwy::HWY_NAMESPACE;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Decode: exact-size heap copies so ASan sees any over-read or over-write.
  {
    char* in = new char[size ? size : 1];
    if (size) memcpy(in, data, size);
    // base64-inl.h: "output must have room for input_size / 4 * 3 bytes".
    const size_t cap = size / 4 * 3;
    uint8_t* out = new uint8_t[cap ? cap : 1];
    size_t out_size = 0;
    if (hn::Base64Decode(in, size, out, &out_size)) {
      HWY_ASSERT(out_size <= cap);
      // Strict decoding only accepts canonical input, so re-encoding must
      // reproduce it exactly.
      const size_t enc_size = hn::Base64EncodedSize(out_size);
      HWY_ASSERT(enc_size == size);
      std::vector<char> enc(enc_size + 1);
      HWY_ASSERT(hn::Base64Encode(out, out_size, enc.data()) == enc_size);
      HWY_ASSERT(memcmp(enc.data(), data, size) == 0);
    }
    delete[] out;
    delete[] in;
  }
  // Encode then decode the raw bytes.
  {
    const size_t enc_size = hn::Base64EncodedSize(size);
    char* enc = new char[enc_size ? enc_size : 1];
    HWY_ASSERT(hn::Base64Encode(data, size, enc) == enc_size);
    const size_t cap = enc_size / 4 * 3;
    uint8_t* dec = new uint8_t[cap ? cap : 1];
    size_t dec_size = 0;
    HWY_ASSERT(hn::Base64Decode(enc, enc_size, dec, &dec_size));
    HWY_ASSERT(dec_size == size);
    HWY_ASSERT(size == 0 || memcmp(dec, data, size) == 0);
    delete[] dec;
    delete[] enc;
  }
  return 0;
}
