// Fuzzes the Iguana block decoder (LZ77 container + ANS32 entropy stage) through
// its public API: hwy::iguana::DecompressedSize, Decompress (SIMD) and
// DecompressScalar. Also round-trips the raw input through Compress so the
// encoder and the decoder's well-formed path are exercised on every input.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hwy/aligned_allocator.h"
#include "hwy/base.h"
#include "hwy/contrib/iguana/iguana.h"
#include "hwy/contrib/thread_pool/thread_pool.h"

namespace hi = hwy::iguana;

// The header declares an uncompressed size of up to 1 GiB, and the caller has
// to allocate dst of at least that size (iguana.h: "dst ... must have size >=
// the block's DecompressedSize"). Bound that caller-side allocation.
static constexpr size_t kMaxDecodedSize = size_t{16} << 20;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // A pool with no worker threads: decoding runs on the calling thread.
  // ThreadPool holds no per-input state.
  static hwy::ThreadPool pool(0);
  hi::IguanaWorkspace ws;  // per input, so no buffer contents carry over

  // Exact-size heap copy so ASan sees any read past the end of the block.
  hwy::AlignedVector<uint8_t> src(data, data + size);
  const hwy::Span<const uint8_t> in(src.data(), size);

  size_t len = 0;
  if (hi::DecompressedSize(in, &len) && len <= kMaxDecodedSize) {
    hwy::AlignedVector<uint8_t> out_simd(len);
    hwy::AlignedVector<uint8_t> out_scalar(len);
    const size_t n_simd = hi::Decompress(
        in, hwy::Span<uint8_t>(out_simd.data(), len), ws, pool);
    const size_t n_scalar = hi::DecompressScalar(
        in, hwy::Span<uint8_t>(out_scalar.data(), len), ws, pool);
    if (n_simd != hi::kDecompressFailed && n_scalar != hi::kDecompressFailed) {
      // iguana.h: "the two produce identical output".
      HWY_ASSERT(n_simd == n_scalar);
      HWY_ASSERT(n_simd <= len);
      HWY_ASSERT(n_simd == 0 ||
                 memcmp(out_simd.data(), out_scalar.data(), n_simd) == 0);
    }
  }

  // Round trip: Compress(data) must decompress back to data.
  const size_t max_comp = hi::MaxCompressedSize(size);
  if (max_comp == 0) return 0;
  hwy::AlignedVector<uint8_t> comp(max_comp);
  const size_t comp_size =
      hi::Compress(in, hwy::Span<uint8_t>(comp.data(), max_comp), ws, pool);
  HWY_ASSERT(comp_size != 0);
  hwy::AlignedVector<uint8_t> block(comp.data(), comp.data() + comp_size);
  const hwy::Span<const uint8_t> bspan(block.data(), comp_size);
  size_t rt_len = 0;
  HWY_ASSERT(hi::DecompressedSize(bspan, &rt_len) && rt_len == size);
  hwy::AlignedVector<uint8_t> rt(size + 1);
  const size_t n = hi::Decompress(bspan, hwy::Span<uint8_t>(rt.data(), size),
                                  ws, pool);
  HWY_ASSERT(n == size);
  HWY_ASSERT(size == 0 || memcmp(rt.data(), data, size) == 0);
  return 0;
}
