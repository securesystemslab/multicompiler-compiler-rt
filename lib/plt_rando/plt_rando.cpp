#include "hde64.h"
#include "plt_rando.h"
#include <elf.h>
#include <cstring>
#include <cstdio>
#include <map>
#include <vector>
#include <set>
#include <deque>
#include <cassert>
#include <cstdlib>
#include <cstdarg>
#include <unistd.h>
#include <cxxabi.h>
#include <dlfcn.h>
#include <string>
#include <algorithm>
#include <ctime>
#include <sys/mman.h>

/*-----------------------------------------------------------------------------
	Macros
-----------------------------------------------------------------------------*/
// These can now be specified on the build command line for debug builds
#ifndef PLTRANDO_DEBUG
#define PLTRANDO_DEBUG 0
#endif

#define PAGE_SIZE 4096
#define ROUND_DOWN(x, multiple) ( (((long)(x)))  & (~(multiple-1)) )
#define ROUND_UP(x, multiple)   ( (((long)(x)) + multiple-1)  & (~(multiple-1)) )

inline void PLTDBG(int level, const char *format, ...)
{
#if PLTRANDO_DEBUG > 0
  va_list args;
  va_start(args, format);
  if(PLTRANDO_DEBUG >= level)
    vfprintf(stdout, format, args);
  va_end(args);
#endif
}

/*-----------------------------------------------------------------------------
	Globals
-----------------------------------------------------------------------------*/
//
// Shared variables
//
static bool initialized = false;
static std::vector<module_info*> modules;

//
// pltrando variables
//
static std::map<unsigned long, code_ptr> got_to_plt;
static std::map<code_ptr, std::vector<code_ptr> > plt_call_sites;
static std::map<code_ptr, code_ptr> plt_targets;
#if PLTRANDO_DEBUG > 0
static std::map<code_ptr, std::string> plt_sym_names;
#endif

/*-----------------------------------------------------------------------------
  Debugging aid
-----------------------------------------------------------------------------*/
static inline unsigned long check_size(unsigned long size)
{
	assert((size >> (8 * sizeof(unsigned long) - 1)) == 0);
	return size;
}

/*-----------------------------------------------------------------------------
    init_rng
-----------------------------------------------------------------------------*/
static void init_rng()
{
	char *seedstr, *end;
	seedstr = getenv("PLT_RANDO_SEED");
	if (seedstr != NULL)
	{
		PLTDBG(1, "The plt rando seed string is %s\n", seedstr);
		unsigned long seedlu = std::strtoul(seedstr, &end, 10);
		if (errno == ERANGE)
		{
			fprintf(stderr, "init_rng: Range error while parsing plt rando seed.\n");
			exit(-1);
		}
		else if(seedstr == end)
		{
			fprintf(stderr, "init_rng: Failed to convert plt rando seed to ulong.\n");
			exit(-1);
		}
		PLTDBG(1, "The plt rando seed integer is %lu\n", seedlu);
		std::srand(seedlu);
	}
	else
	{
		std::srand(std::time(0));
	}
}

/*-----------------------------------------------------------------------------
    parse_elf - We only need this for PLT rando!
-----------------------------------------------------------------------------*/
static void parse_elf(module_info* module)
{
	Elf64_Ehdr* elf = module->elf;

	PLTDBG(1, "Parsing ELF header for module @ %016lx\n", (unsigned long)elf);

	// find the PT_DYNAMIC segment
	Elf64_Phdr* phdr = (Elf64_Phdr*)((unsigned long)elf + elf->e_phoff);
	Elf64_Dyn* dyn = NULL;
	int dyn_sz;

	for (int i = 0; i < elf->e_phnum; ++i)
	{
		if (phdr[i].p_type == PT_DYNAMIC)
		{
			PLTDBG(1, "> found PT_DYNAMIC segment: %d\n", i);
			dyn = (Elf64_Dyn*)(phdr[i].p_vaddr + *module->module_base_offset);
			dyn_sz = phdr[i].p_memsz / sizeof(Elf64_Dyn);
			break;
		}
	}

	// This should never fail on dynamically linked modules unless they are really screwed up...
	assert(dyn);

	for (int i = 0; i < dyn_sz; ++i)
	{
		switch(dyn[i].d_tag)
		{
			case DT_PLTREL:
				module->module_jmprel_type = (unsigned char)dyn[i].d_un.d_val;
				break;
			case DT_JMPREL:
				module->module_jmprel_base = dyn[i].d_un.d_ptr;
				break;
			case DT_PLTRELSZ:
				module->module_jmprel_size = dyn[i].d_un.d_val;
				break;
			case DT_PLTGOT:
				module->module_pltgot_base = dyn[i].d_un.d_ptr;
				break;
			case DT_SYMTAB:
				module->module_symtab_base = dyn[i].d_un.d_ptr;
				break;
			case DT_STRTAB:
				module->module_strtab_base = dyn[i].d_un.d_ptr;
				break;
		}
	}

	// check for missing symbol or string tables
	assert(*module->module_symtab_base && *module->module_strtab_base);

	// Support linking without our version of gold by looking for the PLT manually.
	// Unfortunately, there is no section header table when an ELF file is loaded into memory.
	// We therefore have to resort to some stupid heuristics to identify the PLT
	//
	// Look for a sequence of the following pattern at the start of a segment:
	//
	// jmpq indirect relative (opcode 0xFF)
	// pushq (opcode 0x68)
	// jmpq direct relative (opcode 0xE9)
	phdr = (Elf64_Phdr*)((unsigned long)elf + elf->e_phoff);

	// disassemble all executable segments
	for (int i = 0; i < elf->e_phnum; ++i)
	{
		if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X))
		{
			hde64s ins;
			unsigned long base = phdr[i].p_vaddr + *module->module_base_offset;
			unsigned long addr = base;
			unsigned char seen_got_address_jmp = 0, seen_got_offset_push = 0;
			unsigned int expected_offset = 0;

			PLTDBG(1, "found executable segment: %d\n", i);

			while (addr < phdr[i].p_memsz + base)
			{
				hde64_disasm((const void*)addr, &ins);

				if (ins.opcode == 0xFF)
				{
					PLTDBG(1, "possible got address jmp at address %p\n", addr);
					seen_got_address_jmp = 1;
					if (!*module->module_plt_start)
						expected_offset = 0;
				}
				else if (ins.opcode == 0x68)
				{
					PLTDBG(1, "possible got offset push at address %p\n", addr);
					if (ins.imm.imm32 == expected_offset++)
					{
						seen_got_offset_push = 1;
						PLTDBG(1, "saw expected offset\n");
					}
				}
				else if (ins.opcode == 0xE9)
				{
					PLTDBG(1, "possible got direct jmp at address %p\n", addr);
							
					if (seen_got_address_jmp &&
						seen_got_offset_push)
					{
						module->module_plt_start = addr + 5 + (int)ins.imm.imm32;
						PLTDBG(1, "discovered PLT start @ %p\n", *module->module_plt_start);
					}								
				}
				else if (ins.opcode != 0x90)
				{
					if (*module->module_plt_start)
					{
						PLTDBG(1, "discovered PLT end @ %p\n", addr);
						module->module_plt_end = addr;
						return;
					}
				}						

				addr += ins.len;
			}
		}
	}

	assert(*module->module_plt_start && *module->module_plt_end);

	PLTDBG(1, "PT_DYNAMIC read\n");
}

/*-----------------------------------------------------------------------------
  pltrando_calculate_targets
-----------------------------------------------------------------------------*/
static void pltrando_calculate_targets(module_info* module)
{
	int plt_entries = module->module_jmprel_size / ((module->module_jmprel_type == DT_RELA) ? sizeof(Elf64_Rela) : sizeof(Elf64_Rel));

	// build the got to plt mapping
	hde64s ins;
	unsigned long addr = *module->module_plt_start;
	int entry = -1;
	while (addr < *module->module_plt_end)
	{
		hde64_disasm((const void*)addr, &ins);

		// look for near jumps
		if (ins.opcode == 0xFF && ins.modrm_reg == 4)
		{
			PLTDBG(1, "Found plt entry at %016lx - got: %016lx\n", addr, addr + ins.disp.disp32 + 6);

			if (entry >= 0)
				got_to_plt.insert(std::pair<unsigned long, unsigned long>(addr + ins.disp.disp32 + 6, addr));

			entry++;
		}

		addr += ins.len;
	}

	if (module->module_jmprel_type == DT_RELA)
	{
		PLTDBG(1, "PLT entries: %d - jmprel_size: %lu\n", plt_entries, module->module_jmprel_size);

		for (int i = 0; i < plt_entries; ++i)
		{
			Elf64_Rela* rel = (Elf64_Rela*)(module->module_jmprel_base + sizeof(Elf64_Rela) * i);

			if (ELF64_R_TYPE(rel->r_info) == R_X86_64_JUMP_SLOT)
			{
				int sym_idx = ELF64_R_SYM(rel->r_info);

				Elf64_Sym* sym = (Elf64_Sym*)(module->module_symtab_base + sym_idx * sizeof(Elf64_Sym));
				char* symname = (char*)(module->module_strtab_base + sym->st_name);
				unsigned long got_entry = rel->r_offset + *module->module_base_offset;

				auto it = got_to_plt.find(got_entry);

				if (it != got_to_plt.end())
				{
					PLTDBG(1, "GOT: %016lx - sym: %s => PLT: %016lx\n", rel->r_offset, symname, *it->second);
#if PLTRANDO_DEBUG > 0
					plt_sym_names.insert(std::pair<code_ptr, std::string>(it->second, std::string(symname)));
#endif
					plt_targets.insert(std::pair<code_ptr, unsigned long>(it->second, (unsigned long)dlsym(RTLD_NEXT, symname)));
				}
			}
		}
	}
	else
	{
		fprintf(stderr, "pltrando_calculate_targets: jmprel type is not DT_RELA. We don't have support for DT_REL yet! FIXME!\n");
		exit(-1);
	}
}

/*-----------------------------------------------------------------------------
  pltrando_gather_call_sites - this will be much faster with texttrap!
-----------------------------------------------------------------------------*/
static void pltrando_gather_call_sites(module_info* module)
{
	Elf64_Ehdr* elf = module->elf;
	Elf64_Phdr* phdr = (Elf64_Phdr*)((unsigned long)elf + elf->e_phoff);

	// disassemble all executable segments
	for (int i = 0; i < elf->e_phnum; ++i)
	{
		if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X))
		{
			hde64s ins;
			unsigned long base = phdr[i].p_vaddr + *module->module_base_offset;
			unsigned long addr = base;

			PLTDBG(1, "found executable segment: %d\n", i);

			while (addr < phdr[i].p_memsz + base)
			{
				hde64_disasm((const void*)addr, &ins);

				// look for relative calls or jumps
				if (ins.opcode == 0xE8
					|| ins.opcode == 0xE9)
				{
					// 1-byte opcode + 4-byte rel32 displacement = 5 bytes
					unsigned long target = addr + 5 + (int)ins.imm.imm32;

					if (addr < *module->module_plt_start || addr > *module->module_plt_end)
						PLTDBG(1, "%016lx: found relative jump or call to: %016lx - plt: %016lx-%016lx - \n", addr, target,
							*module->module_plt_start, *module->module_plt_end);

					if ((target >= *module->module_plt_start && target < *module->module_plt_end)
						&& (addr < *module->module_plt_start || addr > *module->module_plt_end))
					{
						const char* name = "<unknown>";
#if PLTRANDO_DEBUG > 0
						auto it = plt_sym_names.find((code_ptr)target);

						if (it != plt_sym_names.end())
							name = it->second.c_str();
#endif

						PLTDBG(1, "found PLT call or jmp at addr: 0x%016lx - target: 0x%016lx (%s)\n",
							addr, target, name);

						auto call_sites_it = plt_call_sites.find((code_ptr)target);
						if (call_sites_it == plt_call_sites.end())
						{
							std::vector<code_ptr> sites;
							sites.push_back((code_ptr)addr);
							plt_call_sites.insert(std::pair<code_ptr, std::vector<code_ptr> >(target, sites));
						}
						else
						{
							call_sites_it->second.push_back((code_ptr)addr);
						}
					}
				}

				addr += ins.len;
			}
		}
	}
}

/*-----------------------------------------------------------------------------
  pltrando_randomize_plt
-----------------------------------------------------------------------------*/
static void pltrando_randomize_plt(module_info* module)
{
	std::vector<code_ptr> plt_entries;
	unsigned long addr;

	char* reverse = getenv("PLT_RANDO_REVERSE");

	//printf("shuffling PLT entries\n");

	for (auto it = plt_targets.begin(); it != plt_targets.end(); ++it)
		plt_entries.push_back((code_ptr)it->first);

	std::random_shuffle(plt_entries.begin(), plt_entries.end());

	if(reverse != NULL) {
		std::reverse(plt_entries.begin(), plt_entries.end());	
	}

	// The actual rewriting is a bit tricky. We have to make sure that we do not use the PLT while we rewrite it!
	for (unsigned i = 0; i < plt_entries.size(); ++i)
	{
		auto it = plt_targets.find(plt_entries[i]);
		auto sites_it = plt_call_sites.find(plt_entries[i]);

		if (it == plt_targets.end())
		{
			fprintf(stderr, "pltrando_randomize_plt: something went wrong. Couldn't find PLT entry\n");
			exit(-1);
		}

		addr = module->module_plt_start + 16 * (i + 1);

		// We want to assemble an absolute direct jump with a 64-bit displacement but unfortunately, that is not possible.
		// Instead, we will assemble
		//
		// mov rax, target
		// jmp qword ptr[rax]
		//
		// REX for mov rax is 01001000 = 0x48
#if PLTRANDO_DEBUG > 0
		// We can't printf here without causing a SEGV :(
		/*const char* name = "<unknown>";
		auto sym_it = plt_sym_names.find(addr);
		if (sym_it != plt_sym_names.end())
			name = sym_it->second.c_str();

		printf("rewriting %d call sites for PLT: %s\n",
			(sites_it != plt_call_sites.end()) ? sites_it->second.size() : 0, name);*/
#endif

		*(unsigned char*)addr		 = 0x48;
		*(unsigned char*)(addr +	1) = 0xB8;
		*(unsigned long*)(addr +	2) = *it->second;
		*(unsigned char*)(addr + 10) = 0xFF;
		*(unsigned char*)(addr + 11) = 0xE0;
		*(unsigned int*) (addr + 12) = 0;

		// rewrite all call sites
		if (sites_it != plt_call_sites.end())
		{
			for (unsigned j = 0; j < sites_it->second.size(); ++j)
			{
				unsigned long site = *sites_it->second[j];
				*(unsigned int*)(site + 1) = addr - site - 5;
			}
		}

#if PLTRANDO_DEBUG > 0
		// We can't printf here without causing a SEGV :(
		//printf("Done!\n");
#endif
	}

	// wipe the got
	memset((void*)*module->module_pltgot_base, 0, sizeof(unsigned long) * plt_entries.size());
	// remove PLT entry zero - this entry is just used for lazy binding
	memset((void*)(unsigned long)*module->module_plt_start, 0, 16);

	// We could technically also get rid of the jmprel section here.
	// However, jmprel does not contain code pointers and since the PLT
	// is now randomized, it doesn't reveal much anyway...
}

/*-----------------------------------------------------------------------------
  make_writable
-----------------------------------------------------------------------------*/
static void make_module_writable(module_info *module)
{
	// Make all executable sections readable
	Elf64_Ehdr* elf = module->elf;
	Elf64_Phdr* phdr = (Elf64_Phdr*)((unsigned long)elf + elf->e_phoff);

	// disassemble all executable segments
	for (int i = 0; i < elf->e_phnum; ++i)
	{
		unsigned long base = phdr[i].p_vaddr + *module->module_base_offset;
		unsigned long aligned_segment_addr = base & (~4095);
		unsigned long aligned_segment_size = ROUND_UP(base + phdr[i].p_memsz, 4096) - aligned_segment_addr;
		mprotect((void*)aligned_segment_addr, aligned_segment_size, PROT_EXEC | PROT_READ | PROT_WRITE);
	}
}

/*-----------------------------------------------------------------------------
		restore_prot_flags
-----------------------------------------------------------------------------*/
static void restore_prot_flags(module_info* module)
{
	Elf64_Ehdr* elf = module->elf;
	Elf64_Phdr* phdr = (Elf64_Phdr*)((unsigned long)elf + elf->e_phoff);

	for (int i = 0; i < elf->e_phnum; ++i)
	{
		if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X))
		{
			int flags = 0;

			if (phdr[i].p_flags & PF_X)
				flags |= PROT_EXEC;
			if (phdr[i].p_flags & PF_R)
				flags |= PROT_READ;
			if (phdr[i].p_flags & PF_W)
				flags |= PROT_WRITE;

			unsigned long base = phdr[i].p_vaddr + *module->module_base_offset;
			unsigned long aligned_segment_addr = base & (~4095);
			unsigned long aligned_segment_size = ROUND_UP(base + phdr[i].p_memsz, 4096) - aligned_segment_addr;
			mprotect((void*)aligned_segment_addr, aligned_segment_size, flags);
		}
	}
}

/*-----------------------------------------------------------------------------
  maybe_initialize
-----------------------------------------------------------------------------*/
static void maybe_initialize()
{
	if (!initialized)
	{
		initialized = true;

		// we have to clear these since the constructor might run before
		// the implicit constructor that initializes our globals
		got_to_plt.clear();
		plt_call_sites.clear();
#if PLTRANDO_DEBUG > 0
		plt_sym_names.clear();
#endif
		plt_targets.clear();

		init_rng();
	}
}

/*-----------------------------------------------------------------------------
  pltrando_register_module
-----------------------------------------------------------------------------*/
extern "C" __attribute__((visibility("default")))
void pltrando_register_module(unsigned long image_base)
{
	maybe_initialize();

	module_info* module = new module_info;
	module->elf = (Elf64_Ehdr*)image_base;
	// PIE support!
	Elf64_Ehdr* elf = module->elf;
	module->module_base_offset = elf->e_type == ET_DYN ? (unsigned long)elf : 0;

	// PLT magic
	parse_elf(module);

	modules.push_back(module);
}

extern "C" __attribute__((visibility("default")))
void pltrando_randomize()
{
	for (auto module : modules)
	{
		make_module_writable(module);
		pltrando_calculate_targets(module);
		pltrando_gather_call_sites(module);
		pltrando_randomize_plt(module);
		restore_prot_flags(module);
		delete module;
	}

	modules.clear();

	got_to_plt.clear();
	plt_call_sites.clear();
	plt_targets.clear();

#if PLTRANDO_DEBUG > 0
	fflush(stdout);
#endif
}

// Local Variables:
// indent-tabs-mode: t
// End:
