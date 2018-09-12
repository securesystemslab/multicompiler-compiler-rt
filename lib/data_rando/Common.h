// -*- mode: c++; -*-
#ifndef LLVM_DATARANDO_RUNTIME_COMMON_H
#define LLVM_DATARANDO_RUNTIME_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <alloca.h>
#include <limits.h>
#include "llvm/DataRando/Runtime/DataRandoTypes.h"


// Copy and then xor into stack allocated memory
// DEST: local pointer variable to assign location copied to
// SRC: pointer to memory
// MASK: mask to use to xor the memory contents
// SIZE: size of memory location

// note: DEST and SIZE will be evaluated more than once, the order that
//       arguments will be evaluated is not the same as they are passed
#define DECRYPT_ON_STACK(DEST, SRC, MASK, SIZE) \
  do {                                          \
    (DEST) = (decltype(DEST))alloca(SIZE);      \
    decrypt_to((DEST), (SRC), (MASK), (SIZE));  \
  } while (0)

// Decrypt string into stack allocated memory
// DEST: local pointer variable to assign location copied to
// SRC: pointer to encrypted string
// MASK: mask to use to decrypt the string
// S: symbol name safe to use within the body of the macro

// note: DEST, SRC, and MASK will be evaluated more than once and a variable
//       with the name S will be bound within the body of this macro.
#define DECRYPT_STR_ON_STACK_S(DEST, SRC, MASK, S)      \
  do {                                                  \
    size_t S = drrt_strlen((SRC), (MASK)) + 1;          \
    DECRYPT_ON_STACK(DEST, SRC, MASK, S);               \
  } while (0)

// Same as DECRYPT_STR_ON_STACK_S, except doesn't require a symbol name, but
// will declare a symbol named size_
#define DECRYPT_STR_ON_STACK(DEST, SRC, MASK) DECRYPT_STR_ON_STACK_S(DEST, SRC, MASK, size_)

// Common functions which may be included into generated programs are extern C
// and prefixed with drrt_.
extern "C" {
  // Xor memory in place. The alignment of p will be taken into account when
  // performing the xor operations.
  void drrt_xor_mem(void *p, mask_t mask, size_t size);

  size_t drrt_strlen(const char *s, mask_t mask);

  size_t drrt_strnlen(const char *s, size_t maxlen, mask_t mask);

  void *drrt_decrypt_new_string(const char* s, mask_t mask);
}

// Common functions which are internal to wrapper implementation are in
// namespace drrt.
namespace drrt {

void encrypt_string(char *s, mask_t mask);

void decrypt_string(char *s, mask_t mask);

// Write n bytes from src to dest and encrypt. src must point to plaintext,
// and it will be encrypted according to the alignment of dest.
void encrypt_to(void *dest, const void *src, mask_t mask, size_t n);

// Write n bytes from src to dest and decrypt. src must point to xor encrypted
// data, and the alignment of src will be used to decrypt.
void decrypt_to(void *dest, const void *src, mask_t mask, size_t n);

// Rotate a mask right by c bits from
// stackoverflow.com/questions/776508/best-practices-for-circular-shift-rotate-operations-in-c
inline mask_t rotr(mask_t n, unsigned int c) {
  const unsigned int max_width = (CHAR_BIT * sizeof(mask_t)) - 1;
  c &= max_width;
  return (n>>c) | (n<<( (-c) & max_width));
}

inline uint8_t xor_byte(const void *b, mask_t m) {
  uint8_t mask_byte = (m >> ((((uintptr_t)b) % sizeof(mask_t)) * 8)) & 0xff;
  return *(const uint8_t*)b ^ mask_byte;
}

inline void write_masked_byte(uint8_t value, void *b, mask_t m) {
  uint8_t mask_byte = (m >> ((((uintptr_t)b) % sizeof(mask_t)) * 8)) & 0xff;
  *((uint8_t*)b) = value ^ mask_byte;
}

// This function will encrypt a constant string returned from a library
// function. It is not reentrant since it may allocate memory, so it must not be
// called in wrappers of reentrant functions.
const char *encrypt_const_string(const char* s, mask_t m);

}


#endif // LLVM_DATARANDO_RUNTIME_COMMON_H
