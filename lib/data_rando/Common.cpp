/* Functions that are useful for writing wrappers */

#include "Common.h"
#include "llvm/ADT/DenseMap.h"

#include <stdlib.h>
#include <stddef.h>

using namespace drrt;

void drrt::encrypt_string(char *s, mask_t mask) {
  if (mask == 0)
    return;
  for(; *s; s++) {
    *s = xor_byte(s, mask);
  }
  /* encrypt null byte after looping */
  *s = xor_byte(s, mask);
}

void drrt::decrypt_string(char *s, mask_t mask) {
  if (mask == 0)
    return;
  size_t sz = drrt_strlen(s, mask);
  drrt_xor_mem(s, mask, sz+1);        /* decrypt null byte */
}

/* preface with drrt_ since calls to this functions are inserted by the
   DataRando pass */
void drrt_xor_mem(void *p, mask_t mask, size_t size) {
  uint8_t *ptr = (uint8_t*)p;
  uint64_t *ptr_64 = (uint64_t*)p;
  size_t i = 0;
  unsigned align = (uintptr_t)p % 8;
  // Get to 8 byte alignment.
  for (; align && (align < 8) && (i < size); ++i, ++align, ++ptr) {
    *ptr = xor_byte(ptr, mask);
  }
  // Do aligned xor 8 bytes at a time.
  for (ptr_64 = (uint64_t*)ptr; i + 8 < size; i += 8, ++ptr_64) {
    *ptr_64 = *ptr_64 ^ mask;
  }
  // Finish up any remaining bytes
  for(ptr = (uint8_t*)ptr_64; i < size; ++i, ++ptr) {
    *ptr = xor_byte(ptr, mask);
  }
}

void drrt::encrypt_to(void *dest, const void *src, mask_t mask, size_t n) {
  memmove(dest, src, n);
  /* This will use the alignment of dest to encrypt. */
  drrt_xor_mem(dest, mask, n);
}

void drrt::decrypt_to(void *dest, const void *src, mask_t mask, size_t n) {
  /* Determine the mask to decrypt with based on the alignment of src and
     dest. */
  unsigned src_alignment = (uintptr_t)src % sizeof(mask_t);
  unsigned dest_alignment = (uintptr_t)dest % sizeof(mask_t);
  mask_t effective_mask = rotr(mask, (src_alignment - dest_alignment) * 8);

  memmove(dest, src, n);
  drrt_xor_mem(dest, effective_mask, n);
}

/* get the length of an encrypted string */
size_t drrt_strlen(const char *s, mask_t mask) {
  const char *i;
  /* find encrypted null byte */
  for(i = s; xor_byte(i, mask); ++i) {
    /* no body */
  }
  return i-s;
}

size_t drrt_strnlen(const char *s, size_t maxlen, mask_t mask) {
  const char *i;
  size_t len;
  /* find encrypted null byte, up to maxlen */
  for(i = s, len = 0; xor_byte(i, mask) && len < maxlen; ++i, len++) {
    /* no body */
  }
  return len;
}

const char *drrt::encrypt_const_string(const char* s, mask_t m)  {
  // A thread local map of decrypted string constants that were returned by
  // library functions.
  static thread_local llvm::DenseMap<std::pair<const char*, mask_t>, char*> ConstStringMap;

  auto key = std::make_pair(s, m);
  auto i = ConstStringMap.find(key);
  if (i == ConstStringMap.end()) {
    size_t l = strlen(s) + 1;
    char *encrypt = (char*)malloc(l);
    encrypt_to(encrypt, s, m, l);
    ConstStringMap.insert(std::make_pair(key, encrypt));
    return encrypt;
  }
  return i->second;
}
