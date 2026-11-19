// Fuzzes Iguana's standalone ANS32 entropy stage: the serialized frequency
// table parser (hwy::iguana::DeserializeAnsTable) and the scalar and SIMD
// payload decoders (Ans32DecodeScalar, Ans32DecodePayloadScalar and
// hwy::iguana_ans::HWY_NAMESPACE::Ans32Decode, static target).
//   bytes [0, 2)  little-endian decoded size (the caller's container
//                 normally supplies it; ans.h: "dst.size() is the
//                 decompressed length")
//   bytes [2, ..) a complete ANS32 block: payload followed by the table
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vector>

#include "hwy/aligned_allocator.h"
#include "hwy/base.h"
#include "hwy/highway.h"
#include "hwy/contrib/iguana/ans.h"
#include "hwy/contrib/iguana/ans-inl.h"

namespace hi = hwy::iguana;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) return -1;
  const size_t orig_size =
      static_cast<size_t>(data[0]) | (static_cast<size_t>(data[1]) << 8);
  const size_t blk_size = size - 2;
  // Exact-size heap copy so ASan sees reads past either end of the block.
  uint8_t* blk = new uint8_t[blk_size ? blk_size : 1];
  if (blk_size) memcpy(blk, data + 2, blk_size);
  const hwy::Span<const uint8_t> src(blk, blk_size);

  std::vector<uint8_t> out_a(orig_size), out_b(orig_size), out_c(orig_size);
  const bool ok_a =
      hi::Ans32DecodeScalar(src, hwy::Span<uint8_t>(out_a.data(), orig_size));
  const bool ok_b = hwy::iguana_ans::HWY_NAMESPACE::Ans32Decode(
      src, hwy::Span<uint8_t>(out_b.data(), orig_size));
  // ans.h: "The SIMD decoder (ans-inl.h) produces identical output."
  if (ok_a && ok_b) HWY_ASSERT(out_a == out_b);

  HWY_ALIGN hi::AnsDenseTable table;
  const size_t payload = hi::DeserializeAnsTable(table, blk, blk_size);
  if (payload != SIZE_MAX) {
    HWY_ASSERT(payload <= blk_size);
    const bool ok_c = hi::Ans32DecodePayloadScalar(
        src.first(payload), table, hwy::Span<uint8_t>(out_c.data(), orig_size));
    if (ok_c && ok_a) HWY_ASSERT(out_c == out_a);
  }
  delete[] blk;

  // Round trip the block bytes through the encoder.
  std::vector<uint8_t> scratch(hi::Ans32EncodeScratchSize(blk_size));
  const hwy::Span<const uint8_t> enc = hi::Ans32Encode(
      data + 2, blk_size, hwy::Span<uint8_t>(scratch.data(), scratch.size()));
  if (enc.size() != 0) {
    std::vector<uint8_t> dec(blk_size);
    HWY_ASSERT(hi::Ans32DecodeScalar(
        enc, hwy::Span<uint8_t>(dec.data(), dec.size())));
    HWY_ASSERT(blk_size == 0 || memcmp(dec.data(), data + 2, blk_size) == 0);
  }
  return 0;
}
