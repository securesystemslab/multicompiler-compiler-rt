add_custom_target(data_rando)

set(DATA_RANDO_CFLAGS
  ${SANITIZER_COMMON_CFLAGS}
)

set(datarando_common_sources
  Common.cpp
  Wrappers.cpp
  pcre/pcreWrappers.cpp
)

set(datarando_libs
  pcre)

foreach(arch ${DATA_RANDO_SUPPORTED_ARCH})
  if(arch STREQUAL "x86_64")
    set(datarando_arch_sources
      x86_64/CallPrintf.cpp
      x86_64/CallPrintf.S )
    set_source_files_properties(x86_64/CallPrintf.S PROPERTIES LANGUAGE C)
  elseif(arch MATCHES "i386|i686")
    set(datarando_arch_sources
      x86/CallPrintf.cpp
      x86/CallPrintf.S )
    set_source_files_properties(x86/CallPrintf.S PROPERTIES LANGUAGE C)
  endif()

  add_compiler_rt_runtime(clang_rt.data_rando
    STATIC
    ARCHS ${arch}
    SOURCES ${datarando_common_sources} ${datarando_arch_sources}
    CFLAGS ${DATA_RANDO_CFLAGS}
    LINK_LIBS ${datarando_libs}
    PARENT_TARGET data_rando)
endforeach()

add_dependencies(compiler-rt data_rando)
