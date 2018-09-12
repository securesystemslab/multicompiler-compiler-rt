add_custom_target(vtable_rando)

set(VTABLE_RANDO_SOURCES vtable_rando.cpp hde64.c)

include_directories(..)

set(VTABLE_RANDO_CFLAGS
  ${SANITIZER_COMMON_CFLAGS}
)

if (VTABLERANDO_DEBUG)
  add_definitions(-DVTABLERANDO_DEBUG=${VTABLERANDO_DEBUG})
endif()

foreach(arch ${VTABLE_RANDO_SUPPORTED_ARCH})
  add_compiler_rt_runtime(clang_rt.vtable_rando
    SHARED
    ARCHS ${arch}
    SOURCES ${VTABLE_RANDO_SOURCES}
    CFLAGS ${VTABLE_RANDO_CFLAGS}
    LINK_LIBS dl
    PARENT_TARGET vtable_rando)
  add_compiler_rt_runtime(clang_rt.vtable_rando_hook
    STATIC
    ARCHS ${arch}
    SOURCES register_module.c
    CFLAGS ${VTABLE_RANDO_CFLAGS}
    PARENT_TARGET vtable_rando)
  add_compiler_rt_runtime(clang_rt.vtable_rando_start
    STATIC
    ARCHS ${arch}
    SOURCES vtable_rando_start.c
    CFLAGS ${VTABLE_RANDO_CFLAGS}
    PARENT_TARGET vtable_rando)
endforeach()

add_dependencies(compiler-rt vtable_rando)
