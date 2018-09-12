add_custom_target(plt_rando)

set(PLT_RANDO_SOURCES plt_rando.cpp hde64.c)

include_directories(..)

set(PLT_RANDO_CFLAGS
  ${SANITIZER_COMMON_CFLAGS}
)

foreach(arch ${PLT_RANDO_SUPPORTED_ARCH})
  add_compiler_rt_runtime(clang_rt.plt_rando
    SHARED
    ARCHS ${arch}
    SOURCES ${PLT_RANDO_SOURCES}
    CFLAGS ${PLT_RANDO_CFLAGS}
    LINK_LIBS dl
    PARENT_TARGET plt_rando)
  add_compiler_rt_runtime(clang_rt.plt_rando_hook
    STATIC
    ARCHS ${arch}
    SOURCES register_module.c
    CFLAGS ${PLT_RANDO_CFLAGS}
    PARENT_TARGET plt_rando)
  add_compiler_rt_runtime(clang_rt.plt_rando_start
    STATIC
    ARCHS ${arch}
    SOURCES plt_rando_start.c
    CFLAGS ${PLT_RANDO_CFLAGS}
    PARENT_TARGET plt_rando)
endforeach()

add_dependencies(compiler-rt plt_rando)
