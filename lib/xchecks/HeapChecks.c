#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <execinfo.h>
#include <rbuff.h>
#include <mvee.h>
#include <pthread.h>
#include "md5.h"

__attribute__((constructor))
static void init_ringbuffer() {
  rb_init();
}

static __thread bool initialized = false;
static __thread MD5_CTX heapContext;
static __thread bool heapDirty = false;

static __thread bool debug_initialized = false;
static FILE *debug_fp = NULL;
static __thread uint64_t rb_tid = 0;

void thread_reset(void) {
  rb_tid = 0;
  initialized = false;
  heapDirty = false;
  debug_initialized = false;
}

__attribute__((constructor))
static void register_atfork() {
  pthread_atfork(NULL, NULL, thread_reset);
}

extern uint64_t malloc_get_id(void *);

void __crosscheckObject(void *ptr) {
  uint64_t id = malloc_get_id(ptr);
  if (id != 0) {
    rb_push_back(id);
  }
}

void __crosscheckHashObject(void *ptr) {
  uint64_t id = malloc_get_id(ptr);
  if (id != 0) {
    if (!initialized) {
      MD5_Init(&heapContext);
      initialized = true;
    }
    heapDirty = true;
    MD5_Update(&heapContext, &id, sizeof(uint64_t));
  }
}

void __crosscheckHash() {
  if (heapDirty) {
    uint64_t heapHash[2];
    MD5_Final((unsigned char *)heapHash, &heapContext);
    rb_push_back(heapHash[0]);
    rb_push_back(heapHash[1]);
    MD5_Init(&heapContext);
    heapDirty = false;
  }
}

void initialize_debug() {
  rb_tid = syscall(186); // gettid
  if (debug_fp == NULL) {
    debug_fp = fopen("/tmp/heapcrosschecks.log", "w");
  }
  debug_initialized = true;
}

void __crosscheckObjectDebug(const char *caller, const char *file, int32_t line, int32_t col, void *ptr) {
  uint64_t id = malloc_get_id(ptr);
  if (id != 0) {
    if (!debug_initialized)
      initialize_debug();
    int ce = errno;
    fprintf(debug_fp, "%08x: %s: %s: %d: %d: %08x\n",
	    rb_tid, caller, file, line, col, id);
    fflush(debug_fp);
    errno = ce;
    rb_push_back(id);
  }
}

void __crosscheckHashObjectDebug(const char *caller, const char *file, int32_t line, int32_t col, void *ptr) {
  uint64_t id = malloc_get_id(ptr);
  if (id != 0) {
    if (!debug_initialized)
      initialize_debug();
    int ce = errno;
    fprintf(debug_fp, "%08x: %s: %s: %d: %d: %08x\n",
	    rb_tid, caller, file, line, col, id);
    fflush(debug_fp);
    errno = ce;

    if (!initialized) {
      MD5_Init(&heapContext);
      initialized = true;
    }
    heapDirty = true;
    MD5_Update(&heapContext, &id, sizeof(uint64_t));
  }
}

#define TOP(x) ((x >> 32) & 0xffffffff)
#define BOT(x) (x & 0xffffffff)

void __crosscheckHashDebug(const char *caller, const char *callee) {
  if (heapDirty) {
    uint64_t heapHash[2];
    MD5_Final((unsigned char *)heapHash, &heapContext);

    if (!debug_initialized)
      initialize_debug();
    int ce = errno;
    fprintf(debug_fp, "%08x: %s -> %s: %08x %08x %08x %08x\n",
	    rb_tid, caller, callee,
	    TOP(heapHash[0]), BOT(heapHash[0]),
	    TOP(heapHash[1]), BOT(heapHash[1]));
    fflush(debug_fp);
    errno = ce;

    rb_push_back(heapHash[0]);
    rb_push_back(heapHash[1]);
    MD5_Init(&heapContext);
    heapDirty = false;
  }
}

void __crosscheckEnterDebug(const char *fun) {
  if (!debug_initialized)
    initialize_debug();
  int ce = errno;
  fprintf(debug_fp, "%08x: --> %s\n", rb_tid, fun);
  fflush(debug_fp);
  errno = ce;
}
