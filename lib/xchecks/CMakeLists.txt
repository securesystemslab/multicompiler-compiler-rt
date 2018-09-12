add_custom_target(xchecks)

option(MULTICOMPILER_PERIODIC_CROSSCHECKS "Use optimized hashed periodic RAVEN ring-buffer cross checks" ON)

set(MULTICOMPILER_RAVEN_SRCDIR "" CACHE PATH
  "PATH to raven source directory containing rbuff/rbuff.h and include/mvee.h for multicompiler cross checks.")

set(MULTICOMPILER_RAVEN_OUTDIR "" CACHE PATH
  "PATH to raven build directory containing rbuff/librbuff.so for multicompiler cross checks.")

include_directories( ${MULTICOMPILER_RAVEN_SRCDIR}/include ${MULTICOMPILER_RAVEN_SRCDIR}/rbuff )

if (NOT MULTICOMPILER_RAVEN_OUTDIR)
  message(FATAL_ERROR
    "Multicompiler cross-checking support requires MULTICOMPILER_RAVEN_OUTDIR to be set to the Raven build output directory.")
endif()

link_directories( ${MULTICOMPILER_RAVEN_OUTDIR}/rbuff )


set(crosscheck_sources
  CrossChecks.cpp)

set(crosscheck_libs
  rbuff
  pthread)


set(heapcheck_sources
  HeapChecks.c
  md5.c)

set(heapcheck_libs
  rbuff)


set(XCHECKS_CFLAGS
  ${SANITIZER_COMMON_CFLAGS})


set(XCHECK_DEFINITIONS
  MULTICOMPILER_OPTIMIZE_CROSSCHECKS=1)

if (MULTICOMPILER_PERIODIC_CROSSCHECKS)
  list(APPEND XCHECK_DEFINITIONS
    MULTICOMPILER_PERIODIC_CROSSCHECKS=1)
endif()

set(XCHECK_DEBUG_DEFINITIONS
  MULTICOMPILER_OPTIMIZE_CROSSCHECKS=0)

foreach(arch ${XCHECKS_SUPPORTED_ARCH})
  add_compiler_rt_runtime(clang_rt.xchecks
    STATIC
    ARCHS ${arch}
    SOURCES ${crosscheck_sources}
    CFLAGS ${XCHECKS_CFLAGS}
    LINK_LIBS ${crosscheck_libs}
    PARENT_TARGET xchecks
    DEFS ${XCHECK_DEFINITIONS})

  add_compiler_rt_runtime(clang_rt.xchecks_debug
    STATIC
    ARCHS ${arch}
    SOURCES ${crosscheck_sources}
    CFLAGS ${XCHECKS_CFLAGS}
    LINK_LIBS ${crosscheck_libs}
    PARENT_TARGET xchecks
    DEFS ${XCHECK_DEBUG_DEFINITIONS})

  add_compiler_rt_runtime(clang_rt.heap_checks
    STATIC
    ARCHS ${arch}
    SOURCES ${heapcheck_sources}
    CFLAGS ${XCHECKS_CFLAGS}
    LINK_LIBS ${heapcheck_libs}
    PARENT_TARGET xchecks)
endforeach()

add_dependencies(compiler-rt xchecks)
