#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* declared in plt_rando.cpp (libpltrando.so) */
extern void pltrando_randomize();

static void __attribute__((constructor)) init() {
  pltrando_randomize();
}
