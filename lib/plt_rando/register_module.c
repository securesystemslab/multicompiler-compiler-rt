extern char __ehdr_start;
extern void pltrando_register_module(void* elf);

static void __attribute__((constructor)) init() {
  pltrando_register_module(&__ehdr_start);
}
