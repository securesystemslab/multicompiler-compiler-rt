#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* declared in vtable_rando.cpp (libvtablerando.so) */
extern void vtablerando_randomize();

static void __attribute__((constructor(1))) init() {
  vtablerando_randomize();
}
