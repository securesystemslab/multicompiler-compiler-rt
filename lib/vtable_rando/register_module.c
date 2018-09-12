extern char __ehdr_start;
extern char __rando_textrap_start;
extern char __rando_textrap_end;
extern void vtablerando_register_module(void* elf, void* textrap_start, void* textrap_end);

static void __attribute__((constructor(0))) init() {
  vtablerando_register_module(&__ehdr_start,
                              &__rando_textrap_start, &__rando_textrap_end);
}
