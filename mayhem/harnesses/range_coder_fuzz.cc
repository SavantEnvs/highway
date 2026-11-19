// Fuzzes the interleaved range-coder decoders: hwy::DecodeInterleavedScalar
// (range_coder.h) and the SIMD hwy::HWY_NAMESPACE::range_coder::
// DecodeInterleaved (range_coder-inl.h, static target). The probability model
// is not part of the bitstream, so the harness derives it from the input:
//   bytes [0, 256)   per-symbol frequency counts
//   bytes [256, 258) little-endian decoded size
//   bytes [258, ...) the compressed stream
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vector>

#include "hwy/base.h"
#include "hwy/highway.h"
#include "hwy/contrib/coder/range_coder.h"
#include "hwy/contrib/coder/range_coder-inl.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  constexpr size_t kHeader = hwy::kRangeMaxSyms + 2;
  if (size < kHeader) return -1;

  std::vector<uint32_t> freq(data, data + hwy::kRangeMaxSyms);
  const size_t orig_size =
      static_cast<size_t>(data[256]) | (static_cast<size_t>(data[257]) << 8);
  std::vector<uint32_t> cum;
  // range_coder.h: "Returns false if the model is degenerate."
  if (!hwy::CreateCumulativeProbs(cum, freq)) return -1;
  std::vector<uint32_t> table;
  hwy::BuildDecodeTable(hwy::kRangeMaxSyms, cum, table);

  // Exact-size heap copy of the stream so ASan sees any over-read.
  const size_t comp_size = size - kHeader;
  uint8_t* comp = new uint8_t[comp_size ? comp_size : 1];
  if (comp_size) memcpy(comp, data + kHeader, comp_size);

  std::vector<uint8_t> out_scalar(orig_size);
  std::vector<uint8_t> out_simd(orig_size);
  // Arbitrary streams: memory safety only. On a corrupt stream the two
  // decoders may both "succeed" with different bytes (the scalar one masks an
  // out-of-interval quotient "for safety against corrupted input"; the SIMD
  // one derives it differently), so their outputs are only compared on the
  // well-formed streams of the round trip below.
  (void)hwy::DecodeInterleavedScalar(comp, comp_size, out_scalar.data(),
                                     orig_size, table.data());
  (void)hwy::HWY_NAMESPACE::range_coder::DecodeInterleaved(
      comp, comp_size, out_simd.data(), orig_size, table.data());
  delete[] comp;

  // Round trip the stream bytes through the encoder with the same model.
  std::vector<uint8_t> plain(data + kHeader, data + size);
  bool all_coded = true;
  for (uint8_t b : plain) all_coded &= (cum[b + 1] > cum[b]);
  if (all_coded) {
    std::vector<uint8_t> enc;
    hwy::EncodeInterleaved(plain, enc, cum);
    std::vector<uint8_t> dec(plain.size());
    HWY_ASSERT(hwy::DecodeInterleavedScalar(enc.data(), enc.size(), dec.data(),
                                            dec.size(), table.data()));
    HWY_ASSERT(dec == plain);
    // range_coder.h: "The SIMD version produces identical output."
    std::vector<uint8_t> dec_simd(plain.size());
    HWY_ASSERT(hwy::HWY_NAMESPACE::range_coder::DecodeInterleaved(
        enc.data(), enc.size(), dec_simd.data(), dec_simd.size(),
        table.data()));
    HWY_ASSERT(dec_simd == plain);
  }
  return 0;
}
