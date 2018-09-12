// Wrappers for functions from pcre

#include "WrapperDeclarations.h"
#include <cassert>

using namespace drrt;

pcre *drrt_pcre_compile2(const char *pattern, int options, int *errorcodeptr,
                         const char **errptr, int *erroffset, const unsigned char *tableptr,
                         mask_t pattern_m, mask_t errorcodeptr_m, mask_t errptr_m,
                         mask_t star_errptr_m, mask_t erroffset_m, mask_t tableptr_m) {
  char * plain_pattern;
  DECRYPT_STR_ON_STACK(plain_pattern, pattern, pattern_m);
  if (tableptr) {
    // TODO: how to decrypt the table?
    assert(!tableptr_m && "Don't know how to decrypt table");
  }
  pcre *r = pcre_compile2(plain_pattern, options, errorcodeptr, errptr, erroffset, tableptr);

  if (!r) {
    drrt_xor_mem(errorcodeptr, errorcodeptr_m, sizeof(*errorcodeptr));
    *errptr = encrypt_const_string(*errptr, star_errptr_m);
    drrt_xor_mem(errptr, errptr_m, sizeof(*errptr));
    drrt_xor_mem(erroffset, erroffset_m, sizeof(*erroffset));
  }

  return r;
}
