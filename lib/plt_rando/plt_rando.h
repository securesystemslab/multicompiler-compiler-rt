#ifndef PLT_RANDO_H
#define PLT_RANDO_H

#include <elf.h>
#include <map>
#include <vector>
#include <string>

/*-----------------------------------------------------------------------------
	Classes
-----------------------------------------------------------------------------*/

class code_ptr
{
public:
	unsigned long val;
	unsigned long operator*()
	{
		return val;
	}
	unsigned long operator+(const unsigned long v)
	{
		return val+v;
	}
	unsigned long operator-(const code_ptr& v)
	{
		return val-v.val;
	}
	void operator=(const unsigned long v)
	{
		val = v;
	}
	void operator+=(const unsigned long v)
	{
		val += v;
	}
	bool operator<(const code_ptr& v) const
	{
		return val < v.val;
	}
	bool operator>(const code_ptr& v) const
	{
		return val > v.val;
	}
	bool operator==(const code_ptr& v) const
	{
		return val == v.val;
	}
	code_ptr(const unsigned long& v)
	{
		val = v;
	}
	code_ptr()
	{
		val = 0;
	}
	~code_ptr()
	{
		val = 0;
	}
};

class module_info
{
public:
	Elf64_Ehdr* elf;
	code_ptr module_base_offset;
	code_ptr module_plt_start;
	code_ptr module_plt_end;
	unsigned char module_jmprel_type;
	code_ptr module_jmprel_base;
	unsigned long module_jmprel_size;
	code_ptr module_pltgot_base;
	code_ptr module_symtab_base;
	code_ptr module_strtab_base;

	module_info()
	{
		elf = NULL;
		module_jmprel_type = DT_RELA;
		module_jmprel_size = 0;
	}
};


#endif
