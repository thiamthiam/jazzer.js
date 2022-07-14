#include "callbacks.h"

#include <algorithm>
#include <cstdint>

#include <napi.h>

// We expect these symbols to exist in the current plugin, provided either by
// libfuzzer or by the native agent.
extern "C" {
void __sanitizer_weak_hook_strcmp(void *called_pc, const char *s1,
                                  const char *s2, int result);
void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *end);
void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                              const uintptr_t *pcs_end);
}

namespace {

// Used by libfuzzer to keep track of program addresses corresponding to
// coverage counters. The flags determine whether the corresponding counter is a
// the beginning of a function; we don't currently use it.
struct PCTableEntry {
  uintptr_t PC, PCFlags;
} __attribute__((packed));

// The maximum number of coverage counters that we allow. Fixing this number
// allows us to allocate the counters statically, simplifying the code.
constexpr size_t kMaxNumCoverageCounters = 1 << 20;

// The number of active coverage counters.
size_t gNumCoverageCounters = 0;

// The next coverage counter to use when instrumenting code; always less than
// gNumCoverageCounters.
size_t gNextCoverageCounter = 0;

// The coverage counters. We allocate an array of maximum size statically to
// simplify the code; only the first gNextCoverageCounter are in actual use, and
// the first gNumCoverageCounters are known to the fuzzer.
std::array<uint8_t, kMaxNumCoverageCounters> gCoverageCounters;

// The array of supplementary information for coverage counters. Each entry
// corresponds to an entry in gCoverageCounters; since we don't know the actual
// addresses of our counters in JS land, we fill this table with fake
// information.
std::array<PCTableEntry, kMaxNumCoverageCounters> gPCTable;

} // namespace

void InitCoverageCounters(Napi::Env env) {
  if (gNumCoverageCounters != 0 || gNextCoverageCounter != 0) {
    throw Napi::Error::New(
        env, "Coverage counters have been used already; can't reinitialize");
  }

  std::fill(gCoverageCounters.begin(), gCoverageCounters.end(), 0);

  // Fill the PC table with fake entries. The only requirement is that the fake
  // addresses must not collide with the locations of real counters (e.g., from
  // instrumented C++ code). Therefore, we just use the address of the counter
  // itself - it's in a statically allocated memory region under our control.
  std::generate(gPCTable.begin(), gPCTable.end(), [n = 0]() mutable {
    auto fake_pc = reinterpret_cast<uintptr_t>(&gCoverageCounters[n++]);
    return PCTableEntry{fake_pc, 0};
  });
}

Napi::Value RequestCoverageCounter(const Napi::CallbackInfo &info) {
  if (info.Length() != 0) {
    throw Napi::Error::New(info.Env(), "Function doesn't take arguments");
  }

  if (gNextCoverageCounter > gNumCoverageCounters) {
    throw Napi::Error::New(info.Env(),
                           "Using inactive coverage counters; this is a bug");
  }

  // Do we need to activate more counters?
  if (gNextCoverageCounter >= gNumCoverageCounters) {
    if (gNumCoverageCounters > kMaxNumCoverageCounters / 2) {
      throw Napi::Error::New(info.Env(),
                             "Maximum number of coverage counters exceeded");
    }

    // Double the number of active counters and register the new portion of the
    // counter array.
    gNumCoverageCounters <<= 1;
    __sanitizer_cov_8bit_counters_init(
        gCoverageCounters.data() + gNextCoverageCounter,
        gCoverageCounters.data() + gNumCoverageCounters);
    __sanitizer_cov_pcs_init(reinterpret_cast<const uintptr_t *>(
                                 gPCTable.data() + gNextCoverageCounter),
                             reinterpret_cast<const uintptr_t *>(
                                 gPCTable.data() + gNumCoverageCounters));
  }

  return Napi::Value::From(info.Env(), gNextCoverageCounter++);
}

// Record a comparison between two strings in the target that returned unequal.
void TraceUnequalStrings(const Napi::CallbackInfo &info) {
  if (info.Length() != 3) {
    throw Napi::Error::New(info.Env(),
                           "Need three arguments: the trace ID and the two "
                           "compared strings");
  }

  auto id = info[0].As<Napi::Number>().Int64Value();
  auto s1 = info[1].As<Napi::String>().Utf8Value();
  auto s2 = info[2].As<Napi::String>().Utf8Value();

  // strcmp returns zero on equality, and libfuzzer doesn't care about the
  // result beyond whether or not it's zero.
  __sanitizer_weak_hook_strcmp((void *)id, s1.c_str(), s2.c_str(), 1);
}

void RegisterCallbackExports(Napi::Env env, Napi::Object exports) {
  InitCoverageCounters(env);
  exports["coverageCounters"] = Napi::Buffer<uint8_t>::New(
      env, gCoverageCounters.data(), gCoverageCounters.size());
  exports["requestCoverageCounter"] =
      Napi::Function::New<RequestCoverageCounter>(env);
  exports["traceUnequalStrings"] =
      Napi::Function::New<TraceUnequalStrings>(env);
  return;
}
