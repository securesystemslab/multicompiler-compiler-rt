#include <cstdio>
#include <cstdint>
#include <unistd.h>
#include <cerrno>
#include <execinfo.h>
extern "C" {
#include <rbuff.h>
#include <mvee.h>
}

#define DEBUG 0
#define DEBUG_BACKTRACE 0
#define CROSSCHECK_INTERVAL 500

#ifndef MULTICOMPILER_PERIODIC_CROSSCHECKS
#define MULTICOMPILER_PERIODIC_CROSSCHECKS 0
#endif


#if MULTICOMPILER_OPTIMIZE_CROSSCHECKS

__attribute__((constructor))
static void init() {
  rb_init();
}

static void do_crosscheck(uint64_t val) {
  int e = errno;
  rb_push_back(val);
  errno = e;
}

#else // MULTICOMPILER_OPTIMIZE_CROSSCHECKS

static void do_crosscheck(uint64_t val) {
  int e = errno;

  /* This SHOULD crosscheck both the pointer and the size as 64-bit int
   * values. It doesn't. It turns out that ESC_XCHECK_VALUES_ONLY is identical
   * to ESC_XCHECK, so if you pass the value to cross-check as the pointer, it
   * just decides that's an invalid pointer and since all variants passed
   * invalid pointers, the cross check succeeds. */
  write(ESC_XCHECK_VALUES_ONLY, 0, static_cast<size_t>(val));
  errno = e;
}

#endif // MULTICOMPILER_OPTIMIZE_CROSSCHECKS


#if DEBUG

static FILE *null_fp = NULL;

__attribute__((constructor))
static void init_debug() {
  null_fp = fopen("/dev/null", "w");
}

#if DEBUG_BACKTRACE
#define BT_BUF_SIZE 100
static void *buffer[BT_BUF_SIZE];

#define debug_backtrace()                                   \
  do {                                                      \
  int nptrs = backtrace(buffer, BT_BUF_SIZE);               \
    if (buffer) {                                           \
      char **strings = backtrace_symbols(buffer, nptrs);    \
      int i;                                                \
      for (i = 0; i < nptrs; ++i)                           \
        fprintf(null_fp, "  %s\n", strings[i]);             \
    }                                                       \
  } while (0)
#else
#define debug_backtrace()
#endif

#define debug()                                 \
  do {                                          \
  int e = errno;                                \
  fprintf(null_fp, "xcheck: %lu\n", val);       \
  debug_backtrace();                            \
  fflush(null_fp);                              \
  errno = e;                                    \
  } while (0)

#else // DEBUG
#define debug()
#endif // DEBUG


#if MULTICOMPILER_PERIODIC_CROSSCHECKS

#define OLD_DEBUG DEBUG
#undef DEBUG
extern "C" {
#include <siphash.c>
}

// The second element of crosscheck_buffer will actually the next input being
// hashed with the first element back into the first element.
static thread_local uint64_t crosscheck_buffer[2];
static thread_local uint64_t crosscheck_count;

static uint8_t siphash_key[16] = {0};

static void crosscheck_impl(uint64_t val) {
  if (crosscheck_count == CROSSCHECK_INTERVAL) {
    do_crosscheck(crosscheck_buffer[0]);
    crosscheck_count = 0;
  }

  // crosscheck_buffer[0] = siphash(crosscheck_buffer[0] || val)
  // (where || is concatenation) 
  crosscheck_buffer[1] = val;
  siphash(reinterpret_cast<uint8_t*>(&crosscheck_buffer), 16, siphash_key,
          reinterpret_cast<uint8_t*>(&crosscheck_buffer), 8);
  ++crosscheck_count;
}

// Flush hash on exit to catch any final divergence
extern "C"
void __crosscheck_flush() {
  do_crosscheck(crosscheck_buffer[0]);
}

#else // MULTICOMPILER_PERIODIC_CROSSCHECKS

static void crosscheck_impl(uint64_t val) {
  do_crosscheck(val);
}

#endif


extern "C"
void __crosscheck(uint64_t val) {
  if (val == 0) return;
  debug();
  crosscheck_impl(val);
}


// Log-based debugging support
static __thread bool debug_initialized = false;
static FILE *debug_fp = NULL;
static __thread uint64_t rb_tid = 0;

static void initialize_debug() {
  rb_tid = syscall(186); // gettid
  if (debug_fp == NULL) {
    debug_fp = fopen("/tmp/crosschecks.log", "w");
  }
  debug_initialized = true;
}

extern "C"
void __crosscheckDebug(const char *caller, const char *file, int32_t line, int32_t col, uint64_t val) {
  if (!debug_initialized)
    initialize_debug();
  int ce = errno;
  fprintf(debug_fp, "%08x: %s: %s: %d: %d: %08x\n",
          rb_tid, caller, file, line, col, val);
  fflush(debug_fp);
  errno = ce;
  __crosscheck(val);
}
