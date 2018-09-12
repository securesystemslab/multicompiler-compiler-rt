// -*- mode: c++; -*-

// Declarations of library function wrappers. We pre-declare the wrapper
// functions to catch type mismatches.

#ifndef LIB_DATARANDO_RUNTIME_WRAPPERDECLARATIONS_H
#define LIB_DATARANDO_RUNTIME_WRAPPERDECLARATIONS_H

#include "llvm/DataRando/Runtime/Wrapper.h"
#include "Common.h"

#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <poll.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include <pcre.h>

extern "C" {

#define DR_WR(O, W, RT, PL) RT W PL;
  DRRT_WRAPPERS
#undef DR_WR

}

#endif // LIB_DATARANDO_RUNTIME_WRAPPERDECLARATIONS_H
