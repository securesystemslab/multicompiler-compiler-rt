/* Wrappers for library functions */

#include "WrapperDeclarations.h"
#include "CallPrintf.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <alloca.h>
#include <syslog.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <grp.h>
#include <pwd.h>
#include <printf.h>

#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>

#include <vector>
#include <memory>
#include <algorithm>

using namespace drrt;

namespace {
// Threshold above which to use mmap for allocating temporary buffers.
// Set to 128k because this is the default threshold for malloc to use mmap.
enum { mmap_threshold = 128 * 1024 };
}

static inline size_t min(size_t x, size_t y) {
  return x < y ? x : y;
}

// Default definition of __crosscheck_flush if we are not linking against the
// clang_rt.xchecks library.
extern "C"
void __attribute__((weak)) __crosscheck_flush() {
}

/*
 * The type of a wrapper is based on the type of the function it is wrapping.
 * The function's signature is the original arguments, followed by the masks of
 * the arguments in depth first order based on the order the arguments are
 * declared, starting with the return value. For example for a function like
 * char **foo(char **arg), the wrapper would be
 * char **drrt_foo(char **arg, mask_t ret_mask, mask_t star_ret_mask, mask_t arg_mask, mask_t star_arg_mask)
 *
 */

char *drrt_strcpy(char *dest, const char *src, mask_t ret_m, mask_t dest_m, mask_t src_m) {
  size_t len = drrt_strlen(src, src_m) + 1;
  decrypt_to(dest, src, src_m, len);
  drrt_xor_mem(dest, dest_m, len);
  return dest;
}

char *drrt_strncpy(char *dest, const char *src, size_t n, mask_t ret_m, mask_t dest_m, mask_t src_m) {
  // We don't need to worry about copying the terminating null byte since if the
  // string is less than n bytes long we will write null bytes so that a total
  // of n bytes are written.
  size_t sz = drrt_strnlen(src, n, src_m);
  decrypt_to(dest, src, src_m, sz);
  memset(dest + sz, 0, n - sz);
  drrt_xor_mem(dest, dest_m, n);
  return dest;
}

char *drrt_strrchr(const char *s, int c, mask_t ret_m, mask_t mask) {
  char *plaintext;
  char *location;
  char *s_nonconst = const_cast<char*>(s);
  DECRYPT_STR_ON_STACK(plaintext, s, mask);
  location = strrchr(plaintext, c);
  // Cast to char* to suppress a warning, the return value of strrchr is
  // non-const.
  return const_cast<char*>(location ? s_nonconst + (location - plaintext) : nullptr);
}

char *drrt_strchr(const char *s, int c, mask_t ret_m, mask_t mask) {
  char *plaintext;
  char *location;
  char *s_nonconst = const_cast<char*>(s);
  DECRYPT_STR_ON_STACK(plaintext, s, mask);
  location = strchr(plaintext, c);
  return const_cast<char*>(location ? s_nonconst + (location - plaintext) : nullptr);
}

char *drrt_strpbrk(const char *s, const char *accept, mask_t ret_m, mask_t s_m, mask_t accept_m) {
  char *plain_s, *plain_accept, *r;
  char *s_nonconst = const_cast<char*>(s);
  DECRYPT_STR_ON_STACK(plain_s, s, s_m);
  DECRYPT_STR_ON_STACK(plain_accept, accept, accept_m);
  r = strpbrk(plain_s, plain_accept);
  return const_cast<char*>(r ? s_nonconst + (r - plain_s) : nullptr);
}

size_t drrt_strspn(const char *s, const char *accept, mask_t s_m, mask_t accept_m) {
  char *plain_s, *plain_accept;
  DECRYPT_STR_ON_STACK(plain_s, s, s_m);
  DECRYPT_STR_ON_STACK(plain_accept, accept, accept_m);
  return strspn(plain_s, plain_accept);
}

int drrt_strcasecmp(const char *s1, const char *s2, mask_t s1_m, mask_t s2_m) {
  char *plain_s1, *plain_s2;
  DECRYPT_STR_ON_STACK(plain_s1, s1, s1_m);
  DECRYPT_STR_ON_STACK(plain_s2, s2, s2_m);
  return strcasecmp(plain_s1, plain_s2);
}

int drrt_strncasecmp(const char *s1, const char *s2, size_t n, mask_t s1_m, mask_t s2_m) {
  char *plain_s1, *plain_s2;
  size_t s1_sz = min(drrt_strnlen(s1, n, s1_m) + 1, n);
  DECRYPT_ON_STACK(plain_s1, s1, s1_m, s1_sz);
  DECRYPT_STR_ON_STACK(plain_s2, s2, s2_m);
  return strncasecmp(plain_s1, plain_s2, n);
}

// TODO: Maybe it is better to leave this function unwrapped
void drrt_openlog(const char *ident, int option, int facility, mask_t mask) {
  size_t sz = drrt_strlen(ident, mask) + 1; // add 1 for null byte
  // Allocate a string on the heap since it will be referenced antytime syslog
  // is called. This causes a slight memory leak, and if the ident string is
  // modifed after calling openlog, our copy won't be updated.
  char *plaintext = (char *)malloc(sz);
  decrypt_to(plaintext, ident, mask, sz);
  openlog(plaintext, option, facility);
}

int drrt_strcmp(const char *s1, const char *s2, mask_t s1_m, mask_t s2_m) {
  char *plain1, *plain2;
  DECRYPT_STR_ON_STACK(plain1, s1, s1_m);
  DECRYPT_STR_ON_STACK(plain2, s2, s2_m);
  return strcmp(plain1, plain2);
}

int drrt_strncmp(const char *s1, const char *s2, size_t n, mask_t s1_m, mask_t s2_m) {
  char *plain1;
  char *plain2;
  size_t s1_sz, s2_sz;
  s1_sz = min(drrt_strnlen(s1, n, s1_m) + 1, n);
  s2_sz = min(drrt_strnlen(s2, n, s2_m) + 1, n);
  DECRYPT_ON_STACK(plain1, s1, s1_m, s1_sz);
  DECRYPT_ON_STACK(plain2, s2, s2_m, s2_sz);
  return strncmp(plain1, plain2, n);
}

// Generic handling of printf style string formatting functions. Extracts the
// arguments from the va_list and stores them in a vector of tagged unions to
// allow construction of a platform specific argument list to call the va_arg
// functions.
int FormatHandler::handle_format(const char *format, va_list ap, mask_t format_m) {
  // the arguments to printf
  std::vector<parameter> parameters;
  // vector of string arguments for raii
  std::vector<std::unique_ptr<char>> string_args;
  // int pointer args to encrypt after call
  std::vector<std::pair<int*, mask_t> > int_ptr_args;
  char *plain_format;
  DECRYPT_STR_ON_STACK(plain_format, format, format_m);

  // get the argtypes
  std::vector<int> argtypes(16);
  size_t num_args = parse_printf_format(plain_format, argtypes.size(), argtypes.data());

  // If there are more args, resize and call again
  if (num_args > argtypes.size()) {
    argtypes.resize(num_args);
    parse_printf_format(plain_format, argtypes.size(), argtypes.data());
  }

  for (unsigned int index = 0; index < num_args; index++) {
    switch (argtypes[index]) {
    case PA_INT:
    case PA_CHAR:
    case PA_INT | PA_FLAG_SHORT:
      {
        int i = va_arg(ap, int);
        va_arg(ap, mask_t);
        parameters.emplace_back();
        parameter &p = parameters.back();
        p.type = INT;
        p.value.i = i;
      }
      break;
    case PA_STRING:
      {
        char *s = va_arg(ap, char*);
        mask_t string_m = va_arg(ap, mask_t);
        char *s_plain;
        if (s) {
          size_t len = drrt_strlen(s, string_m) + 1;
          string_args.emplace_back(new char[len]);
          s_plain = string_args.back().get();
          decrypt_to(s_plain, s, string_m, len);
        } else {
          s_plain = nullptr;
        }
        parameters.emplace_back();
        parameter &p = parameters.back();
        p.type = POINTER;
        p.value.p = s_plain;
      }
      break;
    case PA_FLOAT:
    case PA_DOUBLE:
      {
        double d = va_arg(ap, double);
        va_arg(ap, mask_t);
        parameters.emplace_back();
        parameter &p = parameters.back();
        p.type = DOUBLE;
        p.value.d = d;
      }
      break;
    case PA_DOUBLE | PA_FLAG_LONG_DOUBLE:
      {
        long double d = va_arg(ap, long double);
        va_arg(ap, mask_t);
        parameters.emplace_back();
        parameter &p = parameters.back();
        p.type = LONG_DOUBLE;
        p.value.ld = d;
      }
      break;
    case PA_INT | PA_FLAG_LONG:
      {
        long int i = va_arg(ap, long int);
        va_arg(ap, mask_t);
        parameters.emplace_back();
        parameter &p = parameters.back();
        p.type = LONG_INT;
        p.value.li = i;
      }
      break;
    case PA_INT | PA_FLAG_LONG_LONG:
      {
        long long int i = va_arg(ap, long long int);
        va_arg(ap, mask_t);
        parameters.emplace_back();
        parameter &p = parameters.back();
        p.type = LONG_LONG_INT;
        p.value.lli = i;
      }
      break;

      // The result of "%n" format string.
    case PA_INT | PA_FLAG_PTR:
    case PA_CHAR | PA_FLAG_PTR:
    case PA_INT | PA_FLAG_SHORT | PA_FLAG_PTR:
      {
        int * n_ptr = va_arg(ap, int*);
        mask_t ptr_m = va_arg(ap, mask_t);
        int_ptr_args.push_back(std::make_pair(n_ptr, ptr_m));
        parameters.emplace_back();
        parameter &p = parameters.back();
        p.type = POINTER;
        p.value.p = n_ptr;
      }
      break;

      // Other pointer types
    case PA_POINTER:
    case PA_FLOAT | PA_FLAG_PTR:
    case PA_DOUBLE | PA_FLAG_PTR:
    case PA_DOUBLE | PA_FLAG_LONG_DOUBLE | PA_FLAG_PTR:
    case PA_INT | PA_FLAG_LONG | PA_FLAG_PTR:
    case PA_INT | PA_FLAG_LONG_LONG | PA_FLAG_PTR:
      {
        void* v = va_arg(ap, void*);
        va_arg(ap, mask_t);
        parameters.emplace_back();
        parameter &p = parameters.back();
        p.type = POINTER;
        p.value.p = v;
      }
      break;
    default:
      assert(false && "Unknown arg type");
      break;
    }
  }

  // Buffer for output
  std::vector<char> buffer(32);

  // Do the printf call
  int r = call_snprintf_with(buffer, plain_format, parameters);

  // Error case
  if (r < 0) {
    return r;
  }

  // Encrypt the result of %n arguments
  for (auto &i : int_ptr_args) {
    drrt_xor_mem(i.first, i.second, sizeof(int));
  }

  return do_output(&buffer[0], r);
}

// Wrappers for printf style functions

extern "C"
int drrt_printf(const char *format, mask_t mask, ...) {
  __crosscheck_flush();

  va_list ap;
  va_start(ap, mask);
  FprintfHandler ph(stdout);
  return ph.handle_format(format, ap, mask);
}

extern "C"
int drrt_fprintf(FILE *stream, const char *format, mask_t format_m, ...) {
  __crosscheck_flush();

  va_list ap;
  va_start(ap, format_m);
  FprintfHandler ph(stream);
  return ph.handle_format(format, ap, format_m);
}

extern "C"
int drrt_sprintf(char *str, const char *format, mask_t str_m, mask_t format_m, ...) {
  va_list ap;
  va_start(ap, format_m);
  SprintfHandler sh(str, str_m);
  return sh.handle_format(format, ap, format_m);
}

extern "C"
int drrt_snprintf(char *str, size_t size, const char *format, mask_t str_m, mask_t format_m, ...) {
  va_list ap;
  va_start(ap, format_m);
  SnprintfHandler sh(str, size, str_m);
  return sh.handle_format(format, ap, format_m);
}

extern "C"
void drrt_syslog(int priority, const char *format, mask_t mask, ...) {
  __crosscheck_flush();

  va_list ap;
  va_start (ap, mask);
  SyslogHandler sh(priority);
  sh.handle_format(format, ap, mask);
}


int drrt_puts(const char *s, mask_t mask) {
  __crosscheck_flush();

  char *plain;
  DECRYPT_STR_ON_STACK(plain, s, mask);
  return puts(plain);
}

/* I am assuming that the FILE pointed to by stream is not encrypted. This
   wrapper causes problems because the global pointer variables like stdout
   become encrypted and then they are used by functions outside of our
   control. */
int drrt_fputs(const char *s, FILE *stream, mask_t s_m) {
  __crosscheck_flush();

  char *plain;
  int r;
  DECRYPT_STR_ON_STACK(plain, s, s_m);
  r = fputs(plain, stream);
  return r;
}

int drrt_atoi(const char *nptr, mask_t mask) {
  char *plain;
  DECRYPT_STR_ON_STACK(plain, nptr, mask);
  return atoi(plain);
}

long int drrt_strtol(const char *nptr, char **endptr, int base, mask_t nptr_m, mask_t endptr_m, mask_t star_endptr_m) {
  char *s;
  long int r;
  DECRYPT_STR_ON_STACK(s, nptr, nptr_m);
  r = strtol(s, endptr, base);
  if (endptr) {
    assert(nptr_m == star_endptr_m && "strtol aliasing incorrect");
    // determine the real endpointer relative to nptr
    *endptr = const_cast<char*>(nptr + (*endptr - s));
    // encrypt endptr
    drrt_xor_mem(endptr, endptr_m, sizeof(*endptr));
  }
  return r;
}

/* Identical to strtol wrapper, except call strtoll instead. Duplicate the code so that strtol or
   strtoll can set errno as required for each of those functions. */
long long int drrt_strtoll(const char *nptr, char **endptr, int base, mask_t nptr_m, mask_t endptr_m, mask_t star_endptr_m) {
  char *s;
  long long int r;
  DECRYPT_STR_ON_STACK(s, nptr, nptr_m);
  r = strtoll(s, endptr, base);
  if (endptr) {
    assert(nptr_m == star_endptr_m && "strtol aliasing incorrect");
    // determine the real endpointer relative to nptr
    *endptr = const_cast<char*>(nptr + (*endptr - s));
    // encrypt endptr
    drrt_xor_mem(endptr, endptr_m, sizeof(*endptr));
  }
  return r;
}

extern "C"
double drrt_strtod(const char *nptr, char **endptr, mask_t nptr_m, mask_t endptr_m, mask_t star_endptr_m) {
  char *s;
  double r;
  DECRYPT_STR_ON_STACK(s, nptr, nptr_m);
  r = strtod(s, endptr);
  if (endptr) {
    assert(nptr_m == star_endptr_m && "strtol aliasing incorrect");
    // determine the real endpointer relative to nptr
    *endptr = const_cast<char*>(nptr + (*endptr - s));
    // encrypt endptr
    drrt_xor_mem(endptr, endptr_m, sizeof(*endptr));
  }
  return r;
}

/* struct addrinfo { */
/*   int              ai_flags; */
/*   int              ai_family; */
/*   int              ai_socktype; */
/*   int              ai_protocol; */
/*   socklen_t        ai_addrlen; */
/*   struct sockaddr *ai_addr; */
/*   char            *ai_canonname; */
/*   struct addrinfo *ai_next; */
/* }; */
int drrt_getaddrinfo(const char *node, const char *service,
                     const struct addrinfo *hints,
                     struct addrinfo **res, mask_t node_m, mask_t service_m,
                     mask_t hints_m, mask_t hints_ai_addr_m, mask_t hints_canonnam_m,
                     mask_t res_m, mask_t star_res_m, mask_t star_res_ai_addr_m, mask_t star_res_canonname_m) {
  int r;
  char *plain_node, *plain_service;
  struct addrinfo *plain_hints;
  if (node) {
    DECRYPT_STR_ON_STACK(plain_node, node, node_m);
  } else {
    plain_node = nullptr;
  }
  if (service) {
    DECRYPT_STR_ON_STACK(plain_service, service, service_m);
  } else {
    plain_service = nullptr;
  }
  plain_hints = nullptr;

  /* decrypt hints into stack allocated memory */
  {
    const struct addrinfo *src = hints;
    while (src) {
      struct addrinfo *info = (struct addrinfo *)alloca(sizeof(struct addrinfo));
      if (!plain_hints) {
        plain_hints = info;
      }

      /* decrypt struct */
      decrypt_to(info, src, hints_m, sizeof(struct addrinfo));

      /* decrypt ai_addr */
      if (info->ai_addr) {
        struct sockaddr *t = (struct sockaddr*)alloca(info->ai_addrlen);
        decrypt_to(t, info->ai_addr, hints_ai_addr_m, info->ai_addrlen);
        info->ai_addr = t;
      }

      /* decrypt ai_canonname */
      if (info->ai_canonname) {
        char *cannonname = info->ai_canonname;
        DECRYPT_STR_ON_STACK(info->ai_canonname, cannonname, hints_canonnam_m);
      }

      /* loop on next element in linked list */
      src = info->ai_next;
    }
  }

  r = getaddrinfo(plain_node, plain_service, plain_hints, res);

  /* encrypt linked list returned in res in place */
  if (r == 0) {
    struct addrinfo *next;
    struct addrinfo *info = *res;

    while (info) {
      /* encrypt ai_addr */
      if (info->ai_addr) {
        drrt_xor_mem(info->ai_addr, star_res_ai_addr_m, info->ai_addrlen);
      }

      /* encrypt ai_canonname */
      if (info->ai_canonname) {
        encrypt_string(info->ai_canonname, star_res_canonname_m);
      }

      /* get next element */
      next = info->ai_next;

      /* encrypt info */
      drrt_xor_mem(info, star_res_m, sizeof(struct addrinfo));

      info = next;
    }
  }

  /* encrypt pointer value stored in res */
  drrt_xor_mem(res, res_m, sizeof(*res));
  return r;
}

void drrt_freeaddrinfo(struct addrinfo *res, mask_t res_m, mask_t res_ai_addr_m, mask_t res_ai_canonname_m) {
  struct addrinfo *info = res;

  /* decrypt linked list in place */
  while (info) {
    struct addrinfo *next;

    /* decrypt info */
    drrt_xor_mem(info, res_m, sizeof(struct addrinfo));

    /* decrypt ai_addr */
    if (info->ai_addr) {
      drrt_xor_mem(info->ai_addr, res_ai_addr_m, info->ai_addrlen);
    }

    /* decrypt ai_canonname */
    if (info->ai_canonname) {
      decrypt_string(info->ai_canonname, res_ai_canonname_m);
    }

    /* get next element */
    next = info->ai_next;

    info = next;
  }

  freeaddrinfo(res);

}

int drrt_chdir(const char *path, mask_t mask) {
  char *plain_path;
  DECRYPT_STR_ON_STACK(plain_path, path, mask);
  return chdir(plain_path);
}

char *drrt_getcwd(char *buf, size_t size, mask_t ret_m, mask_t mask) {
  char *r = getcwd(buf, size);
  drrt_xor_mem(buf, mask, size);
  return r;
}

char *drrt_strcat(char *dest, const char *src, mask_t ret_m, mask_t dest_m, mask_t src_m) {
  size_t dest_len = drrt_strlen(dest, dest_m);
  size_t src_len = drrt_strlen(src, src_m);
  size_t copy_len = src_len + 1; /* copy the null byte at the end of src */
  char *dest_end = dest + dest_len;
  decrypt_to(dest_end, src, src_m, copy_len);
  drrt_xor_mem(dest_end, dest_m, copy_len);
  return dest;
}

char *drrt_strncat(char *dest, const char *src, size_t n, mask_t ret_mask, mask_t dest_mask, mask_t src_mask) {
  size_t dest_len = drrt_strlen(dest, dest_mask);
  size_t src_len = drrt_strnlen(src, n, src_mask);
  char *dest_end = dest + dest_len;
  decrypt_to(dest_end, src, src_mask, src_len);
  // Write terminating null byte.
  dest_end[src_len] = '\0';
  // The size is src_len+1 to accommodate the null byte.
  drrt_xor_mem(dest_end, dest_mask, src_len + 1);
  return dest;
}

int drrt_getrlimit(int resource, struct rlimit *rlim, mask_t mask) {
  int r = getrlimit(resource, rlim);
  drrt_xor_mem(rlim, mask, sizeof(*rlim));
  return r;
}

int drrt_setrlimit(int resource, const struct rlimit *rlim, mask_t rlim_m) {
  struct rlimit *rlim_plain;
  DECRYPT_ON_STACK(rlim_plain, rlim, rlim_m, sizeof(*rlim));
  return setrlimit(resource, rlim_plain);
}

int drrt_gethostname(char *name, size_t len, mask_t mask) {
  int r = gethostname(name, len);
  drrt_xor_mem(name, mask, len);
  return r;
}

char *drrt_strdup(const char *s, mask_t ret_m, mask_t s_m) {
  size_t sz = drrt_strlen(s, s_m) + 1; /* add 1 for null byte */
  char *r = (char *)malloc(sz);
  decrypt_to(r, s, s_m, sz);
  drrt_xor_mem(r, ret_m, sz);
  return r;
}

int drrt_setsockopt(int sockfd, int level, int optname,
                    const void *optval, socklen_t optlen, mask_t mask) {
  void *plain_optval;
  DECRYPT_ON_STACK(plain_optval, optval, mask, optlen);
  return setsockopt(sockfd, level, optname, plain_optval, optlen);
}

int drrt_getsockopt(int sockfd, int level, int optname,
                    void *optval, socklen_t *optlen, mask_t optval_m, mask_t optlen_m) {
  // decrypt optlen
  drrt_xor_mem(optlen, optlen_m, sizeof(socklen_t));
  int r = getsockopt(sockfd, level, optname, optval, optlen);
  drrt_xor_mem(optval, optval_m, *optlen);
  drrt_xor_mem(optlen, optlen_m, sizeof(socklen_t));
  return r;
}

int drrt_bind(int sockfd, const struct sockaddr *addr,
              socklen_t addrlen, mask_t addr_m) {
  struct sockaddr* plain_addr;
  DECRYPT_ON_STACK(plain_addr, addr, addr_m, addrlen);
  return bind(sockfd, plain_addr, addrlen);
}

int drrt_gettimeofday(struct timeval *tv, struct timezone *tz, mask_t tv_m, mask_t tz_m) {
  int r = gettimeofday(tv, tz);
  if (tv) {
    drrt_xor_mem(tv, tv_m, sizeof(*tv));
  }
  if (tz) {
    drrt_xor_mem(tz, tv_m, sizeof(*tz));
  }
  return r;
}

/* TODO: There is a signal handler in thttpd that accesses the memory pointed to
   by fds, if the signal is received during a poll call, it will read
   unencrypted data. This is solved by copying the data instead of
   decryption in place, but I am not sure if that is the best way to
   handle concurrent access, since if the value is not const, it should be
   assumed that is can possibly be modified. However if the program breaks
   because of what it does, something needs to change. */
int drrt_poll(struct pollfd *fds, nfds_t nfds, int timeout, mask_t mask) {
  int r;
  struct pollfd *plain_fds;
  DECRYPT_ON_STACK(plain_fds, fds, mask, (nfds * sizeof(struct pollfd)));
  r = poll(plain_fds, nfds, timeout);
  encrypt_to(fds, plain_fds, mask, nfds * sizeof(struct pollfd));
  return r;
}

int drrt_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen, mask_t addr_m, mask_t addrlen_m) {
  int r;
  if (addrlen) {
    drrt_xor_mem(addrlen, addrlen_m, sizeof(socklen_t));
  }
  r = accept(sockfd, addr, addrlen);
  if (addr) {
    drrt_xor_mem(addr, addr_m, *addrlen);
  }
  if (addrlen) {
    drrt_xor_mem(addrlen, addrlen_m, sizeof(socklen_t));
  }
  return r;
}

ssize_t drrt_read(int fd, void *buf, size_t count, mask_t mask) {
  __crosscheck_flush();

  ssize_t sz = read(fd, buf, count);
  if (sz > 0) {
    drrt_xor_mem(buf, mask, sz);
  }
  return sz;
}

ssize_t drrt_write(int fd, void *buf, size_t count, mask_t mask) {
  // Workaround suggested by Jonathan Burket at Apogee Research. If fd is less
  // than 0 it is one of their special psuedo syscalls. Leave all arguments
  // unchanged unless fd is -42 (ESC_XCHECKS_OFF). It appears that
  // ESC_XCHECKS_OFF is the only one that takes a legitimate pointer as an
  // argument.
  if (fd < 0 && fd != -42 && fd != -14 && fd != -1) {
    return write(fd, buf, count);
  }

  __crosscheck_flush();

  // ESC_GET_PRIMARY stores a tag in the upper 32 bits of count. We should be
  // sure not to allocate that large of a buffer.
  size_t size = count;
  if (fd == -14)
    size = (uint32_t) size;

  // Use mmap to allocate the buffer if it exceeds the threshold size, otherwise
  // allocate on the stack. We do not use malloc because write is
  // async-signal-safe and we want the wrapper to preserve this property.
  bool use_mmap = size >= mmap_threshold;
  void *plain_buf;
  if (use_mmap) {
    plain_buf = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (plain_buf == MAP_FAILED) {
      return -1;
    }
  } else {
    plain_buf = alloca(size);
  }

  decrypt_to(plain_buf, buf, mask, size);
  ssize_t r = write(fd, plain_buf, count);

  // ESC_GET_PRIMARY may write to the buf parameter, so we need to copy it back
  // out.
  if (fd == -14)
    encrypt_to(buf, plain_buf, mask, size);

  if (use_mmap) {
    munmap(plain_buf, size);
  }
  return r;
}

/* struct iovec { */
/*   void  *iov_base;    /\* Starting address *\/ */
/*   size_t iov_len;     /\* Number of bytes to transfer *\/ */
/* }; */
ssize_t drrt_writev(int fd, const struct iovec *iov, int iovcnt, mask_t iov_m, mask_t iov_base_m) {
  __crosscheck_flush();

  int i;
  struct iovec *plainiov = (struct iovec *)alloca(sizeof(struct iovec) * iovcnt);
  decrypt_to(plainiov, iov, iov_m, sizeof(struct iovec) * iovcnt);

  for (i = 0; i < iovcnt; i++) {
    struct iovec *iov_i = plainiov + i;

    void *plain_base;
    bool use_mmap = iov_i->iov_len >= mmap_threshold;
    if (use_mmap) {
      plain_base = mmap(nullptr, iov_i->iov_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (plain_base == MAP_FAILED) {
        return -1;
      }
    } else {
      plain_base = alloca(iov_i->iov_len);
    }

    decrypt_to(plain_base, iov_i->iov_base, iov_base_m, iov_i->iov_len);
    iov_i->iov_base = plain_base;
  }

  ssize_t result = writev(fd, plainiov, iovcnt);

  for (i = 0; i < iovcnt; i++) {
    struct iovec *iov_i = plainiov + i;
    bool use_mmap = iov_i->iov_len >= mmap_threshold;
    if (use_mmap)
      munmap(iov_i->iov_base, iov_i->iov_len);
  }

  return result;
}

ssize_t drrt_readlink(const char *path, char *buf, size_t bufsiz, mask_t path_m, mask_t buf_m) {
  char *plain_path;
  ssize_t r;
  DECRYPT_STR_ON_STACK(plain_path, path, path_m);
  r = readlink(plain_path, buf, bufsiz);
  if (r > 0) {
    drrt_xor_mem(buf, buf_m, r);
  }
  return r;
}

/* struct tm { */
/*   int tm_sec;         /\* seconds *\/ */
/*   int tm_min;         /\* minutes *\/ */
/*   int tm_hour;        /\* hours *\/ */
/*   int tm_mday;        /\* day of the month *\/ */
/*   int tm_mon;         /\* month *\/ */
/*   int tm_year;        /\* year *\/ */
/*   int tm_wday;        /\* day of the week *\/ */
/*   int tm_yday;        /\* day in the year *\/ */
/*   int tm_isdst;       /\* daylight saving time *\/ */
/*   long tm_gmtoff;           /\* Seconds east of UTC *\/ */
/*   const char *tm_zone;      /\* Timezone abbreviation *\/ */
/* }; */
size_t drrt_strftime(char *s, size_t max, const char *format, const struct tm *tm, mask_t s_m, mask_t format_m, mask_t tm_m, mask_t tm_zone_m) {
  char *plain_format;
  const char *zone;
  char *temp_zone;
  struct tm plain_tm;
  size_t r;
  DECRYPT_STR_ON_STACK(plain_format, format, format_m);
  decrypt_to(&plain_tm, tm, tm_m, sizeof(plain_tm));
  zone = plain_tm.tm_zone;
  if (zone) {
    DECRYPT_STR_ON_STACK(temp_zone, zone, tm_zone_m);
    plain_tm.tm_zone = temp_zone;
  }
  r = strftime(s, max, plain_format, &plain_tm);
  if (r > 0) {
    drrt_xor_mem(s, s_m, r + 1);     /* doesn't include null byte */
  }
  return r;
}

struct tm *drrt_gmtime(const time_t *timep, mask_t ret_mask, mask_t ret_zone_mask, mask_t mask) {
  time_t plain_time;
  decrypt_to(&plain_time, timep, mask, sizeof(plain_time));
  struct tm *r = gmtime(&plain_time);
  if (r) {
    if (r->tm_zone) {
      r->tm_zone = encrypt_const_string(r->tm_zone, ret_zone_mask);
    }
    drrt_xor_mem(r, ret_mask, sizeof(struct tm));
  }
  return r;
}

struct tm *drrt_gmtime_r(const time_t *timep, struct tm *result, mask_t ret_mask, mask_t ret_zone_mask, mask_t timep_mask, mask_t result_mask, mask_t result_zone_mask) {
  time_t plain_time;
  decrypt_to(&plain_time, timep, timep_mask, sizeof(plain_time));
  struct tm *r = gmtime_r(&plain_time, result);
  if (r) {
    if (result->tm_zone && result_zone_mask) {
      // This is an error, but we won't do anything about it.

      // We can't call encrypt_const_string here since it may allocate, and this
      // wrapper needs to be reentrant since the function being wrapped is. To
      // allow for this, the analysis should mark this equivalence class as
      // unencrypted.
    }
    drrt_xor_mem(result, result_mask, sizeof(struct tm));
  }
  return r;
}


struct tm *drrt_localtime(const time_t *timep, mask_t ret_mask, mask_t ret_zone_mask, mask_t mask) {
  time_t plain_time;
  decrypt_to(&plain_time, timep, mask, sizeof(plain_time));
  struct tm *r = localtime(&plain_time);
  if (r) {
    if (r->tm_zone) {
      r->tm_zone = encrypt_const_string(r->tm_zone, ret_zone_mask);
    }
    drrt_xor_mem(r, ret_mask, sizeof(struct tm));
  }
  return r;
}

struct tm *drrt_localtime_r(const time_t *timep, struct tm *result, mask_t ret_mask, mask_t ret_zone_mask, mask_t timep_mask, mask_t result_mask, mask_t result_zone_mask) {
  time_t plain_time;
  decrypt_to(&plain_time, timep, timep_mask, sizeof(plain_time));
  struct tm *r = localtime_r(&plain_time, result);
  if (r) {
    if (result->tm_zone && result_zone_mask) {
      // This is an error, but we won't do anything about it.

      // We can't call encrypt_const_string here since it may allocate, and this
      // wrapper needs to be reentrant since the function being wrapped is. To
      // allow for this, the analysis should mark this equivalence class as
      // unencrypted.
    }
    drrt_xor_mem(result, result_mask, sizeof(struct tm));
  }
  return r;
}

char *drrt_strstr(const char *haystack, const char *needle, mask_t ret_m, mask_t haystack_m, mask_t needle_m) {
  char *plain_haystack, *plain_needle, *r;
  char *haystack_nonconst = const_cast<char*>(haystack);
  DECRYPT_STR_ON_STACK(plain_haystack, haystack, haystack_m);
  DECRYPT_STR_ON_STACK(plain_needle, needle, needle_m);
  r = strstr(plain_haystack, plain_needle);
  return (char *)(r ? haystack_nonconst + (r - plain_haystack) : nullptr);
}

int drrt_stat(const char *path, struct stat *buf, mask_t path_m, mask_t buf_m) {
  char *plain_path;
  int r;
  DECRYPT_STR_ON_STACK(plain_path, path, path_m);
  r = stat(plain_path, buf);
  drrt_xor_mem(buf, buf_m, sizeof(struct stat));
  return r;
}

int drrt__xstat(int ver, const char * path, struct stat * stat_buf, mask_t path_m, mask_t stat_buf_m) {
  char *plain_path;
  int r;
  DECRYPT_STR_ON_STACK(plain_path, path, path_m);
  r = __xstat(ver, plain_path, stat_buf);
  drrt_xor_mem(stat_buf, stat_buf_m, sizeof(struct stat));
  return r;
}

int drrt_open(const char *path, int flags, mask_t mask, mask_t va_args_m, ...) {
  __crosscheck_flush();

  char *plain_path;
  va_list args;
  va_start(args, va_args_m);
  DECRYPT_STR_ON_STACK(plain_path, path, mask);
  if (flags & O_CREAT) {
    return open(plain_path, flags, va_arg(args, mode_t));
  }
  return open(plain_path, flags);
}

extern "C"
int drrt_fcntl(int fd, int cmd, mask_t va_arg_mask, ...) {
  __crosscheck_flush();

  va_list args;
  va_start(args, va_arg_mask);
  switch (cmd) {
  case F_SETFD:
  case F_SETFL:
  case F_SETOWN:
  case F_SETSIG:
  case F_SETLEASE:
  case F_NOTIFY:
  case F_SETPIPE_SZ:
    {
      int arg = va_arg(args, int);
      return fcntl(fd, cmd, arg);
    }
  case F_SETLK:
  case F_SETLKW:
  case F_GETLK:
    {
      struct flock plain_arg;
      struct flock *arg = va_arg(args, struct flock*);
      decrypt_to(&plain_arg, arg, va_arg_mask, sizeof(struct flock));
      return fcntl(fd, cmd, &plain_arg);
    }
  case F_GETOWN_EX:
    {
      struct f_owner_ex *arg;
      arg = va_arg(args, struct f_owner_ex*);
      int r = fcntl(fd, cmd, arg);
      drrt_xor_mem(arg, va_arg_mask, sizeof(struct f_owner_ex));
      return r;
    }
  case F_SETOWN_EX:
    {
      struct f_owner_ex plain_arg;
      struct f_owner_ex *arg;
      arg = va_arg(args, struct f_owner_ex*);
      decrypt_to(&plain_arg, arg, va_arg_mask, sizeof(struct f_owner_ex));
      return fcntl(fd, cmd, &plain_arg);
    }
  default:
    return fcntl(fd, cmd);
  }
}

/* This isn't used to wrap main, but a call to this is inserted at the beginning
   of main to encrypt the command line arguments */
int drrt_main(int argc, char **argv, mask_t argv_m, mask_t argvp_m) {
  // encrypt all strings pointed to by members of argv
  int i;
  for (i = 0; i < argc; ++i) {
    char** p = argv + i;
    encrypt_string(*p, argvp_m);
  }
  // encrypt argv
  drrt_xor_mem(argv, argv_m, sizeof(char*) * (argc + 1));
  return 0;
}

FILE *drrt_fopen(const char *path, const char *mode, mask_t path_m, mask_t mode_m) {
  __crosscheck_flush();

  char *plain_path;
  char *plain_mode;
  DECRYPT_STR_ON_STACK(plain_path, path, path_m);
  DECRYPT_STR_ON_STACK(plain_mode, mode, mode_m);
  return fopen(plain_path, plain_mode);
}

void *drrt_memchr(const void *s, int c, size_t n, mask_t ret_m, mask_t s_mask) {
  uint8_t *plain_s;
  uint8_t *result;
  ptrdiff_t diff;
  void *s_nonconst = const_cast<void*>(s);
  DECRYPT_ON_STACK(plain_s, s, s_mask, n);
  result = (uint8_t*)memchr(plain_s, c, n);
  if (result == nullptr) { return nullptr; }
  diff = result - plain_s;
  return (uint8_t*)s_nonconst + diff;
}

FILE *drrt_fdopen(int fd, const char *mode, mask_t mode_m) {
  __crosscheck_flush();

  char *plain_mode;
  DECRYPT_STR_ON_STACK(plain_mode, mode, mode_m);
  return fdopen(fd, plain_mode);
}

int drrt_initgroups(const char *user, gid_t group, mask_t user_m) {
  char *plain_user;
  DECRYPT_STR_ON_STACK(plain_user, user, user_m);
  return initgroups(plain_user, group);
}

size_t drrt_fread(void *ptr, size_t size, size_t nmemb, FILE *stream, mask_t ptr_m) {
  __crosscheck_flush();

  size_t r = fread(ptr, size, nmemb, stream);
  drrt_xor_mem(ptr, ptr_m, r * size);
  return r;
}

size_t drrt_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream, mask_t ptr_m) {
  __crosscheck_flush();

  void *ptr_plain;
  DECRYPT_ON_STACK(ptr_plain, ptr, ptr_m, (size*nmemb));
  return fwrite(ptr_plain, size, nmemb, stream);
}

void drrt_perror(const char *s, mask_t s_mask) {
  char *s_plain;
  if (s) {
    DECRYPT_STR_ON_STACK(s_plain, s, s_mask);
    perror(s_plain);
  } else {
    /* s is null */
    perror(nullptr);
  }
}

char *drrt_fgets(char *s, int size, FILE *stream, mask_t ret_m, mask_t s_m) {
  __crosscheck_flush();

  char *r = fgets(s, size, stream);
  if (r) {
    drrt_xor_mem(s, s_m, size);
  }
  return r;
}

int drrt_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen, mask_t addr_m, mask_t addrlen_m) {
  int r;
  drrt_xor_mem(addrlen, addrlen_m, sizeof(socklen_t));
  r = getsockname(sockfd, addr, addrlen);
  drrt_xor_mem(addr, addr_m, *addrlen);
  drrt_xor_mem(addrlen, addrlen_m, sizeof(socklen_t));
  return r;
}

char *drrt_ctime(const time_t *timep, mask_t ret_m, mask_t timep_m) {
  time_t timep_plain;
  decrypt_to(&timep_plain, timep, timep_m, sizeof(time_t));
  char *r = ctime(&timep_plain);
  encrypt_string(r, ret_m);
  return r;
}

int drrt_chroot(const char *path, mask_t path_m) {
  char *path_plain;
  DECRYPT_STR_ON_STACK(path_plain, path, path_m);
  return chroot(path_plain);
}

int drrt_pipe(int *pipefd, mask_t pipefd_m) {
  int r = pipe(pipefd);
  drrt_xor_mem(pipefd, pipefd_m, 2 * sizeof(int));
  return r;
}

pid_t drrt_waitpid(pid_t pid, int *status, int options, mask_t status_m) {
  pid_t r = waitpid(pid, status, options);
  if (status) {
    drrt_xor_mem(status, status_m, sizeof(int));
  }
  return r;
}

size_t drrt_strcspn(const char *s, const char *reject, mask_t s_m, mask_t reject_m) {
  char *plain_s;
  char *plain_reject;
  DECRYPT_STR_ON_STACK(plain_s, s, s_m);
  DECRYPT_STR_ON_STACK(plain_reject, s, reject_m);
  return strcspn(plain_s, plain_reject);
}

int drrt_getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, socklen_t hostlen, char *serv, socklen_t servlen,
                     int flags, mask_t sa_m, mask_t host_m, mask_t serv_m) {
  struct sockaddr *plain_sa;
  int r;
  DECRYPT_ON_STACK(plain_sa, sa, sa_m, salen);
  r = getnameinfo(plain_sa, salen, host, hostlen, serv, servlen, flags);
  if (host) {
    drrt_xor_mem(host, host_m, hostlen);
  }
  if (serv) {
    drrt_xor_mem(serv, serv_m, servlen);
  }
  return r;
}

struct passwd *drrt_getpwnam(const char *name, mask_t ret_m, mask_t pw_name_m, mask_t pw_passwd_m, mask_t pw_gecos_m,
                             mask_t pw_dir_m, mask_t pw_shell_m, mask_t name_m) {
  char *plain_name;
  struct passwd *r;
  DECRYPT_STR_ON_STACK(plain_name, name, name_m);
  r = getpwnam(plain_name);
  if (r) {
    if (r->pw_name) {
      encrypt_string(r->pw_name, pw_name_m);
    }
    if (r->pw_passwd) {
      encrypt_string(r->pw_passwd, pw_passwd_m);
    }
    if (r->pw_gecos) {
      encrypt_string(r->pw_gecos, pw_gecos_m);
    }
    if (r->pw_dir) {
      encrypt_string(r->pw_dir, pw_dir_m);
    }
    if (r->pw_shell) {
      encrypt_string(r->pw_shell, pw_shell_m);
    }

    drrt_xor_mem(r, ret_m, sizeof(*r));
  }

  return r;
}

int drrt_getpwnam_r(const char *name, struct passwd *pwd,
                    char *buf, size_t buflen, struct passwd **result,
                    mask_t name_mask, mask_t pwd_mask, mask_t pwd_name_m, mask_t pwd_passwd_m,
                    mask_t pwd_gecos_m, mask_t pwd_dir_m, mask_t pwd_shell_m,
                    mask_t buf_mask, mask_t result_mask, mask_t star_result_mask,
                    mask_t star_result_name_m, mask_t star_result_passwd_m,
                    mask_t star_result_gecos_m, mask_t star_result_dir_m,
                    mask_t star_result_shell_m) {
  char * plain_name;
  DECRYPT_STR_ON_STACK(plain_name, name, name_mask);
  int r = getpwnam_r(plain_name, pwd, buf, buflen, result);
  // We don't go through each field since we know how the data is stored. The
  // passwd is stored in pwd, all strings are stored in buf, and a pointer to
  // the result or null is stored in result.
  drrt_xor_mem(pwd, pwd_mask, sizeof(struct passwd));
  drrt_xor_mem(buf, buf_mask, buflen);
  drrt_xor_mem(result, result_mask, sizeof(*result));
  return r;
}

int drrt_execve(const char *filename, char *const argv[], char *const envp[], mask_t filename_m,
                mask_t argv_m, mask_t star_argv_m, mask_t envp_m, mask_t star_envp_m) {
  __crosscheck_flush();

  char *plain_filename;
  char **plain_argv;
  char **plain_envp;
  intptr_t iptr;
  size_t i, n, sz;
  DECRYPT_STR_ON_STACK(plain_filename, filename, filename_m);

  /* decrypt argv */
  i = n = sz = 0;
  /* find length of argv */
  decrypt_to(&iptr, argv, argv_m, sizeof(*argv));
  while (iptr) {
    i++;
    decrypt_to(&iptr, argv + i, argv_m, sizeof(*argv));
  }
  n = i+1;
  sz = n*sizeof(*argv);
  DECRYPT_ON_STACK(plain_argv, argv, argv_m, sz);

  for (i = 0; plain_argv[i]; i++) {
    decrypt_string(plain_argv[i], star_argv_m);
  }

  /* decrypt envp */
  i = n = sz = 0;
  /* find length of envp */
  decrypt_to(&iptr, envp, envp_m, sizeof(*envp));
  while (iptr) {
    i++;
    decrypt_to(&iptr, envp + i, envp_m, sizeof(*envp));
  }
  n = i+1;
  sz = n*sizeof(*envp);
  DECRYPT_ON_STACK(plain_envp, envp, envp_m, sz);

  for (i = 0; plain_envp[i]; i++) {
    decrypt_string(plain_envp[i], star_envp_m);
  }

  return execve(plain_filename, plain_argv, plain_envp);
}

int drrt___lxstat(int version, const char *file, struct stat *buf, mask_t file_m, mask_t buf_m) {
  char *plain_file;
  int r;
  DECRYPT_STR_ON_STACK(plain_file, file, file_m);
  r = __lxstat(version, plain_file, buf);
  drrt_xor_mem(buf, buf_m, sizeof(*buf));
  return r;
}

int drrt_setenv(const char *name, const char *value, int overwrite, mask_t name_m, mask_t value_m) {
  char *plain_name, *plain_value;
  int r;
  DECRYPT_STR_ON_STACK(plain_name, name, name_m);
  DECRYPT_STR_ON_STACK(plain_value, value, value_m);
  r = setenv(plain_name, plain_value, overwrite);
  return r;
}

int drrt_unsetenv(const char *name, mask_t name_m) {
  char *plain_name;
  int r;
  DECRYPT_STR_ON_STACK(plain_name, name, name_m);
  r = unsetenv(plain_name);
  return r;
}

int drrt_memcmp(const void *s1, const void *s2, size_t n, mask_t s1_m, mask_t s2_m) {
  void *plain_s1, *plain_s2;
  DECRYPT_ON_STACK(plain_s1, s1, s1_m, n);
  DECRYPT_ON_STACK(plain_s2, s2, s2_m, n);
  return memcmp(plain_s1, plain_s2, n);
}

/* TODO: The parameters aren't really documented for this function, it seems
   like one of them contains a pointer since llvm complains that the
   signature of this wrapper isn't what is expected. For now we will not
   use this wrapper. */
int drrt_pthread_cond_init(pthread_cond_t *cond, pthread_condattr_t *cond_attr, mask_t cond_m, mask_t cond_attr_m) {
  pthread_cond_t *plain_cond;
  pthread_condattr_t *plain_cond_attr;
  DECRYPT_ON_STACK(plain_cond, cond, cond_m, (sizeof(pthread_cond_t))); /* $TODO$ what if its an array or Null */
  DECRYPT_ON_STACK(plain_cond_attr, cond_attr, cond_attr_m, (sizeof(pthread_condattr_t))); /* $TODO$ what if its an array or Null */
  return pthread_cond_init(plain_cond, plain_cond_attr);
}

void *drrt_memmove(void *dest, const void *src, size_t n, mask_t ret_m, mask_t dest_m, mask_t src_m) {
  if ((uintptr_t)dest % sizeof(mask_t) == (uintptr_t)src % sizeof(mask_t)) {
    // Alignment is the same, the analysis will always put dest and source in
    // the same class, so we can do a normal memmove.
    memmove(dest, src, n);
    return dest;
  }

  decrypt_to(dest, src, src_m, n);
  drrt_xor_mem(dest, dest_m, n);
  return dest;
}

// TODO: it might be possible to decrypt the fd_sets in place
int drrt_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                struct timeval *timeout, mask_t readfds_mask, mask_t writefds_mask,
                mask_t exceptfds_mask, mask_t timeout_mask) {
  __crosscheck_flush();

  fd_set plain_readfds, plain_writefds, plain_exceptfds;
  fd_set *readfds_ptr, *writefds_ptr, *exceptfds_ptr;
  readfds_ptr = writefds_ptr = exceptfds_ptr = nullptr;
  struct timeval plain_timeout;
  struct timeval *timeout_ptr = nullptr;
  if (readfds) {
    readfds_ptr = &plain_readfds;
    decrypt_to(readfds_ptr, readfds, readfds_mask, sizeof(fd_set));
  }
  if (writefds) {
    writefds_ptr = &plain_writefds;
    decrypt_to(writefds_ptr, writefds, writefds_mask, sizeof(fd_set));
  }
  if (exceptfds) {
    exceptfds_ptr = &plain_exceptfds;
    decrypt_to(exceptfds_ptr, exceptfds, exceptfds_mask, sizeof(fd_set));
  }
  if (timeout) {
    timeout_ptr = &plain_timeout;
    decrypt_to(timeout_ptr, timeout, timeout_mask, sizeof(struct timeval));
  }
  int r = select(nfds, readfds_ptr, writefds_ptr, exceptfds_ptr, timeout_ptr);
  if (readfds) {
    encrypt_to(readfds, &plain_readfds, readfds_mask, sizeof(fd_set));
  }
  if (writefds) {
    encrypt_to(writefds, &plain_writefds, writefds_mask, sizeof(fd_set));
  }
  if (exceptfds) {
    encrypt_to(exceptfds, &plain_exceptfds, exceptfds_mask, sizeof(fd_set));
  }
  if (timeout) {
    // select may update timeout, copy plain_timeout back to timeout
    encrypt_to(timeout, &plain_timeout, timeout_mask, sizeof(struct timeval));
  }
  return r;
}

int drrt_sigemptyset(sigset_t *set, mask_t sigset_mask) {
  sigset_t plain_set;
  decrypt_to(&plain_set, set, sigset_mask, sizeof(sigset_t));
  int r = sigemptyset(&plain_set);
  encrypt_to(set, &plain_set, sigset_mask, sizeof(sigset_t));
  return r;
}

int drrt_sigaction(int signum, const struct sigaction *act,
                   struct sigaction *oldact, mask_t act_mask, mask_t oldact_mask) {
  struct sigaction plain_act;
  struct sigaction *act_ptr = nullptr;
  if (act) {
    decrypt_to(&plain_act, act, act_mask, sizeof(struct sigaction));
    act_ptr = &plain_act;
  }
  int r = sigaction(signum, act_ptr, oldact);
  if (oldact) {
    drrt_xor_mem(oldact, oldact_mask, sizeof(struct sigaction));
  }
  return r;
}

void *drrt_calloc(size_t nmemb, size_t size, mask_t ret_mask) {
  void *r = calloc(nmemb, size);
  size_t total_size = nmemb * size;
  if (r && ret_mask) {
    drrt_xor_mem(r, ret_mask, total_size);
  }
  return r;
}

void *drrt_realloc(void *ptr, size_t size, mask_t ret_mask, mask_t ptr_mask) {
  void *realloc_ptr = realloc(ptr, size);

  /* Determine the mask to decrypt with based on the alignment of src and
     dest. This is essentially the same thing we do in drrt::decrypt_to*/
  unsigned src_alignment = (uintptr_t)ptr % sizeof(mask_t);
  unsigned dest_alignment = (uintptr_t)realloc_ptr % sizeof(mask_t);

  // If the alignment and the mask is the same we don't need to do anything.
  if (src_alignment == dest_alignment && ret_mask == ptr_mask) {
    return realloc_ptr;
  }
  mask_t effective_mask = rotr(ptr_mask, (src_alignment - dest_alignment) * 8);

  // TODO: We can do this in a single xor, but I need to be careful I get the
  // alignment right. This should do the right thing.
  drrt_xor_mem(realloc_ptr, effective_mask, size);
  drrt_xor_mem(realloc_ptr, ret_mask, size);

  return realloc_ptr;
}

int drrt_getrusage(int who, struct rusage *usage, mask_t usage_mask) {
  int r = getrusage(who, usage);
  drrt_xor_mem(usage, usage_mask, sizeof(struct rusage));
  return r;
}

clock_t drrt_times(struct tms *buf, mask_t buf_mask) {
  clock_t r = times(buf);
  drrt_xor_mem(buf, buf_mask, sizeof(struct tms));
  return r;
}

time_t drrt_time(time_t *t, mask_t t_mask) {
  time_t r = time(t);
  if (t) {
    drrt_xor_mem(t, t_mask, sizeof(time_t));
  }
  return r;
}

char *drrt_ttyname(int fd, mask_t mask) {
  char *r = ttyname(fd);
  if (r) {
    // The return value may be in static data area.
    return const_cast<char*>(encrypt_const_string(r, mask));
  }
  // ttyname returned null.
  return nullptr;
}

char *drrt_strtok(char *str, const char *delim, mask_t ret_mask, mask_t str_mask, mask_t delim_mask) {
  // Maintain a pointer to the str to be tokenized. The normal implementation of
  // strtok is not thread-safe, and this is not either.
  static mask_t saved_str_mask;
  static char *saved_str_loc;
  if (str) {
    saved_str_loc = str;
    saved_str_mask = str_mask;
  }

  // Decrypt the delimiters, these can change between successive calls.
  size_t delim_len = drrt_strlen(delim, delim_mask);
  char *plain_delim = (char *)alloca(delim_len + 1);
  decrypt_to(plain_delim, delim, delim_mask, delim_len + 1);
  char *plain_delim_end = plain_delim + delim_len;

  // find the first non-delimiter to start a token
  char *tok_start = nullptr;
  while (char c = xor_byte(saved_str_loc, saved_str_mask)) {
    if (std::find(plain_delim, plain_delim_end, c) == plain_delim_end) {
      tok_start = saved_str_loc;
      break;
    }
    saved_str_loc++;
  }

  // We reached the end of the string without finding a character to start the
  // token.
  if (!tok_start) {
    return nullptr;           // Return null if no token is found.
  }

  while (char c = xor_byte(saved_str_loc, saved_str_mask)) {
    // If we find a delimiter we end the token.
    if (std::find(plain_delim, plain_delim_end, c) != plain_delim_end) {
      // Write a null byte to saved_str_loc which points to a delimiter at the
      // end of the token.
      *saved_str_loc = 0;
      *saved_str_loc = xor_byte(saved_str_loc, saved_str_mask);
      // Save the location of 1 past the delimiter to continue the search on the next call.
      saved_str_loc++;
      break;
    }
    saved_str_loc++;
  }
  return tok_start;
}

void *drrt_memset(void *s, int c, size_t length, mask_t ret_m, mask_t s_m) {
  // This is based on the freebsd version of memset. Do word-sized stores if the
  // length is > 3 words, otherwise fill in bytes. We are assuming that the
  // register size is always 64 bits, and x86_64, but for other architectures
  // this implementation will be less than ideal.
  //
  // TODO: Optimize handling other word sizes
  const unsigned int wsize = 8;
  uint8_t *dst = (uint8_t*) s;
  if (length < 3 * wsize) {
    while (length != 0) {
      write_masked_byte(c, dst, ret_m);
      ++dst;
      --length;
    }
    return s;
  }

  // Fill 64-bit integer
  uint64_t c64;
  if ((c64 = (unsigned char)c) != 0) {
    c64 = (c64 << 8)  | c64;
    c64 = (c64 << 16) | c64;
    c64 = (c64 << 32) | c64;
  }

  // Get to 8-byte alignment
  if (unsigned int align = (uintptr_t)dst % wsize) {
    unsigned int n = wsize - align;
    length -= n;
    do {
      write_masked_byte(c, dst, ret_m);
      dst++;
    } while (--n != 0);
  }

  // Do masked stores 8 bytes at a time
  unsigned int n = length / wsize;
  uint64_t c64_masked = c64 ^ ret_m;
  do {
    *(uint64_t*)dst = c64_masked;
    dst += wsize;
  } while (--n != 0);

  // Finish up any remaining bytes
  unsigned int remaining = length % wsize;
  if (remaining != 0) {
    do {
      write_masked_byte(c, dst, ret_m);
      dst++;
    } while (--remaining != 0);
  }

  return s;
}

int drrt_posix_memalign(void **memptr, size_t alignment, size_t size, mask_t memptr_m, mask_t star_memptr_m) {
  int r = posix_memalign(memptr, alignment, size);
  drrt_xor_mem(memptr, memptr_m, sizeof(*memptr));
  return r;
}

namespace {
enum type_modifier {
  mod_none = 0,
  mod_short,
  mod_char,
  mod_intmax,
  mod_long,
  mod_long_long,
  mod_ptrdif,
  mod_size
};

void handle_scanf_format(const char *plain_format, int successful, va_list ap, mask_t MASK_0) {
  if (successful < 0) {
    // scanf will return EOF on input failure.
    return;
  }
  // Find the elements of the format that will result in writing data out, and
  // encrypt the results. The %n$ form is not supported.
  const char *ptr = plain_format;
  while ((ptr = strchr(ptr, '%'))) {
    // ptr initially points to the '%' at the start of a conversion specifier
    ptr++;
    type_modifier modifier = mod_none;
    bool allocate = false;
    int field_width = 0;

    // perform no matching
    if (*ptr == '*' || *ptr == '%') {
      ptr++;
      continue;
    }

    if (*ptr == 'n') {
      int *arg = va_arg(ap, int*);
      drrt_xor_mem(arg, MASK_0, sizeof(int));
      continue;
    }

    if (successful <= 0) {
      // There has been no more successful matches.
      return;
    }

    if (*ptr == 'm') {
      allocate = true;
    }

    // read the possible field width
    {
      char *end;
      int r = strtol(ptr, &end, 10);
      if (ptr != end) {
        field_width = r;
        ptr = end;
      }
    }

    // read possible type modifiers
    switch (*ptr) {
    case 'h':
      ptr++;
      if (*ptr == 'h') {
        modifier = mod_char;
        ptr++;
      } else {
        modifier = mod_short;
      }
      break;
    case 'j':
      ptr++;
      modifier = mod_intmax;
      break;
    case 'l':
      ptr++;
      modifier = mod_long;
      break;
    case 'q':
    case 'L':
      ptr++;
      modifier = mod_long_long;
      break;
    case 't':
      ptr++;
      modifier = mod_ptrdif;
      break;
    case 'z':
      ptr++;
      modifier = mod_size;
      break;
    }

    // read the conversion specifier
    switch (*ptr) {
    case 'd':
    case 'i':
    case 'o':
    case 'u':
    case 'x':
    case 'X':
      {
        size_t sz;
        void *arg = va_arg(ap, void*);
        switch (modifier) {
        default:
          sz = sizeof(int);
          break;

        case mod_short:
          sz = sizeof(short);
          break;
        case mod_char:
          sz = sizeof(char);
          break;
        case mod_intmax:
          sz = sizeof(intmax_t);
          break;
        case mod_long:
          sz = sizeof(long);
          break;
        case mod_long_long:
          sz = sizeof(long long);
          break;
        case mod_ptrdif:
          sz = sizeof(ptrdiff_t);
          break;
        case mod_size:
          sz = sizeof(size_t);
          break;
        }
        drrt_xor_mem(arg, MASK_0, sz);
        // successful matching
        ptr++;
        successful--;
        continue;
      }

    case 'f':
    case 'e':
    case 'g':
    case 'E':
    case 'a':
      {
        size_t sz;
        void *arg = va_arg(ap, void*);
        switch (modifier) {
        default:
          sz = sizeof(float);
          break;

        case mod_long:
          sz = sizeof(double);
          break;
        case mod_long_long:
          sz = sizeof(long double);
          break;
        }
        drrt_xor_mem(arg, MASK_0, sz);
        // successful matching
        ptr++;
        successful--;
        continue;
      }
      break;

    case '[':
      // find the end of the bracketed list
      {
        ptr++;
        // The character ] at the beginning does not end the list;
        if (*ptr == ']') {
          ptr++;
        } else if (*ptr == '^') {
          ptr++;
          if (*ptr == ']') {
            ptr++;
          }
        }
        ptr = strchr(ptr, ']');
      }
    case 's':
      {
        char *arg;
        if (allocate) {
          char **p = va_arg(ap, char**);
          arg = *p;
          drrt_xor_mem(p, MASK_0, sizeof(char*));
        } else {
          arg = va_arg(ap, char*);
        }
        if (field_width) {
          size_t l = strnlen(arg, field_width) + 1;
          drrt_xor_mem(arg, MASK_0, l);
        } else {
          encrypt_string(arg, MASK_0);
        }
        // successful matching
        ptr++;
        successful--;
        continue;
      }
    case 'c':
      {
        // default length of 1.
        int length = field_width ? field_width : 1;
        char *arg;
        if (allocate) {
          char **p = va_arg(ap, char**);
          arg = *p;
          drrt_xor_mem(p, MASK_0, sizeof(char*));
        } else {
          arg = va_arg(ap, char*);
        }
        drrt_xor_mem(arg,MASK_0, length);
        // successful matching
        ptr++;
        successful--;
        continue;
      }
      break;
    case 'p':
      {
        void **arg = va_arg(ap, void**);
        drrt_xor_mem(arg, MASK_0, sizeof(void*));
        // successful matching
        ptr++;
        successful--;
        continue;
      }
      break;
    default:
      assert(false && "Unknown conversion specifier encountered");
      return;
    }
  }
  return;
}
}
// MASK_0 -> str
// MASK_1 -> format
// MASK_2 -> va_args
extern "C"
int drrt_sscanf(const char *str, const char *format, mask_t MASK_0, mask_t MASK_1, mask_t MASK_2, ...) {
  va_list ap, ap_copy;
  va_start(ap, MASK_2);
  va_copy(ap_copy, ap);
  char *plain_str, *plain_format;
  DECRYPT_STR_ON_STACK(plain_str, str, MASK_0);
  DECRYPT_STR_ON_STACK(plain_format, format, MASK_1);
  int r = vsscanf(plain_str, plain_format, ap);
  // Handle the format and encrypt the output values
  handle_scanf_format(plain_format, r, ap_copy, MASK_2);
  return r;
}

// MASK_0 -> format
// MASK_1 -> va_args
extern "C"
int drrt_fscanf(FILE *f, const char *format, mask_t MASK_0, mask_t MASK_1, ...) {
  __crosscheck_flush();

  va_list ap, ap_copy;
  va_start(ap, MASK_1);
  va_copy(ap_copy, ap);
  char *plain_format;
  DECRYPT_STR_ON_STACK(plain_format, format, MASK_0);
  int r = vfscanf(f, plain_format, ap);
  handle_scanf_format(plain_format, r, ap_copy, MASK_1);
  return r;
}

// MASK_0 -> format
// MASK_1 -> va_args
extern "C"
int drrt_scanf(const char *format, mask_t MASK_0, mask_t MASK_1, ...) {
  __crosscheck_flush();

  va_list ap, ap_copy;
  va_start(ap, MASK_1);
  va_copy(ap_copy, ap);
  char *plain_format;
  DECRYPT_STR_ON_STACK(plain_format, format, MASK_0);
  int r = vscanf(plain_format, ap);
  handle_scanf_format(plain_format, r, ap_copy,  MASK_1);
  return r;
}

extern "C"
const char *drrt_getenv(const char *name, mask_t ret_m, mask_t name_m) {
  char *plain_name;
  DECRYPT_STR_ON_STACK(plain_name, name, name_m);
  const char *r = getenv(plain_name);
  if (r == nullptr) {
    return r;
  }
  return encrypt_const_string(r, ret_m);
}

extern "C"
ssize_t drrt_recv(int sockfd, void *buf, size_t len, int flags, mask_t buf_m) {
  ssize_t return_value = recv(sockfd, buf, len, flags);
  if (return_value < 0) {
    return return_value;
  }

  ssize_t buffer_data_size = std::min(len, (size_t)return_value);
  drrt_xor_mem(buf, buf_m, buffer_data_size);
  return return_value;
}
