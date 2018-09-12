//===- CallPrintf.cpp - Support for printf type functions for x86_64 ------===//

#include "CallPrintf.h"
#include "assert.h"

using namespace drrt;

// This function is implemented in assembly to create a call to snprintf
// following the x64 calling conventions.
extern "C"
int drrt_call_snprintf_with(void *buffer, size_t size, const void *fmt,
                            const void *int_registers, const void *stack_arguments, size_t size_stack_arguments,
                            void *sse_registers);

// This is specific to x86_64 and uses a function implemented in assembly
// to move the arguments, other platforms will use different implementations.
int FormatHandler::call_snprintf_with(std::vector<char> &buffer, const char *format, std::vector<parameter> &arguments) {
  typedef uint64_t eightbyte;
  struct long_double {
    eightbyte low, high;
  };

  union x64_parameter {
    parameter_value value;
    eightbyte eb;
    long_double ld;
  };

  // There are only 3 int registers left for snprintf.
  const int num_int_registers = 3;
  int int_register_index = 0;
  eightbyte int_registers[num_int_registers];

  // SSE registers are used for passing double arguments.
  const int num_sse_registers = 8;
  int sse_register_index = 0;
  eightbyte sse_registers[num_sse_registers];

  std::vector<eightbyte> stack;

  // Classify the arguments depending on how they will be passed to snprintf
  for (parameter &p : arguments) {
    x64_parameter param;
    param.value = p.value;
    switch (p.type) {
    case INT:
    case LONG_INT:
    case LONG_LONG_INT:
    case POINTER:
      {
        eightbyte int_value = param.eb;
        if (int_register_index < num_int_registers) {
          int_registers[int_register_index] = int_value;
          int_register_index++;
        } else {
          stack.push_back(int_value);
        }
      }
      break;
    case DOUBLE:
      {
        eightbyte double_value = param.eb;
        if (sse_register_index < num_sse_registers) {
          sse_registers[sse_register_index] = double_value;
          sse_register_index++;
        } else {
          stack.push_back(double_value);
        }
      }
      break;
    case LONG_DOUBLE:
      {
        stack.push_back(param.ld.low);
        stack.push_back(param.ld.low);
      }
      break;
    }
  }

  // Make sure the stack arguments will be 16 byte aligned
  if (stack.size() % 2) {
    stack.push_back(0);
  }

  size_t stack_size_bytes = stack.size() * sizeof(eightbyte);
  assert(stack_size_bytes % 16 == 0 && "Stack alignment incorrect");

  // Do the call to snprintf using a function written in assembly to move the
  // arguments to their correct locations.
  int r = drrt_call_snprintf_with(&buffer[0], buffer.size(), format, int_registers, &stack[0], stack_size_bytes, sse_registers);

  if (r < 0) {
    // An error occurred.
    return r;
  }

  // If truncation of the output occurred, resize the buffer and call again.
  if ((unsigned)r >= buffer.size()) {
    buffer.resize(r + 1);
    r = drrt_call_snprintf_with(&buffer[0], buffer.size(), format, int_registers, &stack[0], stack_size_bytes, sse_registers);
  }

  return r;
}
