//===- CallPrintf.cpp - Support for printf type functions for x86 ---------===//

#include "CallPrintf.h"
#include "assert.h"

using namespace drrt;

extern "C"
int drrt_call_snprintf_with(const void *stack_arguments, size_t stack_size);

int FormatHandler::call_snprintf_with(std::vector<char> &buffer, const char *format, std::vector<parameter> &arguments) {
  typedef uint32_t fourbyte;

  union x86_parameter {
    parameter_value value;
    size_t size_value;
    fourbyte fb;
    fourbyte ar[sizeof(parameter_value) / sizeof(fourbyte)];
  };

  std::vector<fourbyte> stack;

  x86_parameter BuffParam;
  x86_parameter SizeParam;
  x86_parameter FormatParam;

  BuffParam.value.p = &buffer[0];
  SizeParam.size_value = buffer.size();
  FormatParam.value.p = const_cast<char*>(format);

  stack.push_back(BuffParam.fb);
  stack.push_back(SizeParam.fb);
  stack.push_back(FormatParam.fb);

  for (parameter &p : arguments) {
    x86_parameter x86p;
    x86p.value = p.value;
    size_t s = 0;
    switch (p.type) {
    case INT:
      s = sizeof(int);
      break;
    case LONG_INT:
      s = sizeof(long int);
      break;
    case LONG_LONG_INT:
      s = sizeof(long long int);
      break;
    case DOUBLE:
      s = sizeof(double);
      break;
    case LONG_DOUBLE:
      s = sizeof(long double);
      break;
    case POINTER:
      s = sizeof(void*);
      break;
    }
    size_t NumFourBytes = s / sizeof(fourbyte);

    // align the stack to the size of the argument.
    if (size_t align = stack.size() % NumFourBytes) {
      stack.insert(stack.end(), NumFourBytes - align, 0);
    }

    for (unsigned i = 0; i < NumFourBytes; i++) {
      stack.push_back(x86p.ar[i]);
    }
  }

  // Make sure stack will be 16 byte aligned
  if (size_t align = stack.size() % 4) {
    stack.insert(stack.end(), 4 - align, 0);
  }
  size_t stack_size_bytes = stack.size() * sizeof(fourbyte);
  assert(stack_size_bytes % 16 == 0 && "Stack alignment incorrect");

  int r = drrt_call_snprintf_with(&stack[0], stack_size_bytes);

  if (r < 0) {
    // An error occurred.
    return r;
  }

  // If truncation of the output occurred, resize the buffer and call again.
  if ((unsigned)r >= buffer.size()) {
    buffer.resize(r + 1);
    BuffParam.value.p = &buffer[0];
    SizeParam.size_value = buffer.size();
    stack[0] = BuffParam.fb;
    stack[1] = SizeParam.fb;
    r = drrt_call_snprintf_with(&stack[0], stack_size_bytes);
  }

  return r;
}
