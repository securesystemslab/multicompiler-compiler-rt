//===- CallPrintf.h - Support for printf type functions ---------*- C++ -*-===//

#ifndef LIB_DATARANDO_RUNTIME_CALLPRINTF_H
#define LIB_DATARANDO_RUNTIME_CALLPRINTF_H

#include "llvm/DataRando/Runtime/DataRandoTypes.h"
#include "Common.h"

#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>

#include <vector>

namespace drrt {

// Base class for all sorts of string format types.
class FormatHandler {

  // Possible types of the va_arg parameters to printf style functions.
  enum parameter_type {
    INT,
    LONG_INT,
    LONG_LONG_INT,
    DOUBLE,
    LONG_DOUBLE,
    POINTER
  };

  union parameter_value {
    int i;
    long int li;
    long long int lli;
    double d;
    long double ld;
    void *p;
  };

  // Tagged union type to store argument values after extracting them from the
  // va_list.
  struct parameter {
    parameter_type type;
    parameter_value value;
  };

public:
  FormatHandler()
  {}

  // Handle the encrypted format string and the encrypted args. The result of
  // the format will be assembled in buffer, which is then passed to do_output
  // for the specific type of output required by the actual format function
  // being called.
  int handle_format(const char *format, va_list ap, mask_t format_m);

protected:
  // Perform the actual output of the assembled string based on the type of
  // formatting function being used. The arguments do do_output are the
  // resulting null-terminated string after all format arguments have been
  // processed and strlen(string).
  virtual int do_output(const char *string, size_t num) = 0;

private:
  // Call snprintf with the format string fmt and arguments, outputting to
  // buffer. Buffer will be resized if it does not have sufficient space to hold
  // the result.
  int call_snprintf_with(std::vector<char> &buffer, const char *fmt, std::vector<parameter> &arguments);
};

class FprintfHandler : public FormatHandler {
  FILE *stream;
public:
  explicit FprintfHandler(FILE *f)
      : stream(f)
  {}
protected:
  int do_output(const char *s, size_t n) override {
    int r = fputs(s, stream);
    if (r < 0) {
      return r;
    }
    return n;
  }
};

class SprintfHandler : public FormatHandler {
  char *str;
  mask_t str_mask;
public:
  SprintfHandler(char *s, mask_t s_m)
      : str(s), str_mask(s_m)
  {}
protected:
  int do_output(const char *s, size_t n) override {
    // Add 1 to n for null byte.
    encrypt_to(str, s, str_mask, n + 1);
    return n;
  }
};

class SnprintfHandler : public FormatHandler {
  char *str;
  size_t size;
  mask_t str_mask;
public:
  SnprintfHandler(char *s, size_t n, mask_t mask)
      : str(s), size(n), str_mask(mask)
  {}
protected:
  int do_output(const char *s, size_t n) override {
    if (n < size) {
      // Add 1 for null byte. Since n is strictly less than size, copying one
      // more byte for the null terminator is safe.
      encrypt_to(str, s, str_mask, n + 1);
    } else {
      // Truncate
      memmove(str, s, size);
      // write null byte
      str[size - 1] = '\0';
      drrt_xor_mem(str, str_mask, size);
    }
    return n;
  }
};

class SyslogHandler : public FormatHandler {
  int priority;
public:
  explicit SyslogHandler(int priority)
      : priority(priority)
  {}
protected:
  int do_output(const char *s, size_t n) override {
    syslog(priority, "%s", s);
    return n;
  }
};

} // namespace drrt

#endif /* LIB_DATARANDO_RUNTIME_CALLPRINTF_H */
