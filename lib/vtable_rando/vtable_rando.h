#ifndef VTABLE_RANDO_H
#define VTABLE_RANDO_H

#include <cxxabi.h>
#include <elf.h>
#include <map>
#include <vector>
#include <string>

/*-----------------------------------------------------------------------------
	Enumerations
-----------------------------------------------------------------------------*/
enum class_type
{
	none,
	pb,				// pure base
	si,				// single inheritance
	vmi				// virtual multiple inheritance
};

enum vcall_type
{
	unknown,
	idx,			// vcall refers to the vtable entry using an index
	absolute,		// vcall refers to the vtable entry using an absolute address
	relative,		// vcall refers to the vtable entry using a pc relative address
  method_pointer
};

enum inheritance_type
{
	_virtual,
	_nonvirtual,
	_empty_virtual
};

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

class class_info;

// These are the split up vtables
class vtable_info
{
public:
	vtable_info() :
		info(nullptr), vtable_size(0), original_vtable_size(0), offset(0),
		main_variant(nullptr), dummy_table(false), parent(nullptr) { }

	// associated class
	class_info* info;

	// number of entries in the vtable
	unsigned long vtable_size;
	unsigned long original_vtable_size;

	// offset from rtti pointer
	unsigned long offset;

	// locations for the vtables
	std::vector<code_ptr> vtable_locations;

	// class names for bases in this vtable, sorted in reversed layout order
	std::vector<const char*> base_names;

	// other vtables that are laid out just like this one
	std::vector<vtable_info*> variants;

	// vtable this layout is based on. this is set when splitting subvtables
	vtable_info *main_variant;

	// info used during shuffling
	std::vector<unsigned long> shuffled_indices;
	std::vector<unsigned long> original_targets;

	bool dummy_table;

	vtable_info *get_parent();

	void add_variant(vtable_info *variant);
	bool have_variant(vtable_info* variant);

	void randomize_variant(int i, bool cleanup=false);

private:
	// pointer from variant tables to the table on which their layout is based
	vtable_info* parent;
};

class vcall_info
{
public:
  const char* 	class_name;				// class used at the call site
	vtable_info* 	resolved_subvtable;
	code_ptr 		ptr_to_vcall;			// pointer to the vcall instruction itself
	code_ptr 		ptr_to_idx;				// pointer to the index or address within the vcall instruction
	vcall_type		type;
	unsigned long 	old_idx;				// old vcall index, in bytes, relative to the start of the primary vtable of the class
	code_ptr		old_addr;				// this is only used for vcall types relative and absolute
	unsigned long 	idx_size;				// size of the index
	unsigned long 	idx_offset; 			// offset, in bytes, of the sub vtable within the primary vtable of the class
	bool            sign_extended;
};

class class_info
{
public:
	// rtti for this class
	__cxxabiv1::__class_type_info* rtti;

	// name
  std::string name;

  // blacklist from randomization
  bool blacklist;

	// type
	class_type type;

	// address point (ptr to first vtable)
	code_ptr address_point;

	// vtables for this class. These have to be split up!
	// We put them in a temporary container because we don't know
	// if they are virtual vtables or not
	std::vector<vtable_info*> vtables;

	// This is where they ultimately wind up
	// std::vector<vtable_info*> vtables;
	// std::vector<vtable_info*> virtual_vtables;

	std::vector<class_info*> virtual_bases;

	bool has_vtable;
	bool has_virtual_base;
	bool inherits_vfns;
	bool declares_vfns;
	bool has_nonvirtual_direct_base;
	bool primary_is_virtual;

	bool visited;
	std::map<unsigned long, class_info*> children;

	std::vector<inheritance_type> parent_type;
	std::vector<class_info*> parents;

	// class_info *primary_base;

	// /// Check if this class already virtually inherits from needle through an
	// /// existing vtable
	// bool virtually_inherits_vtable(class_info *needle);

	// /// Find and set primary_base
	// void find_primary_base();

// private:
	/// Check if this class virtually inherits from needle (regardless of whether
	/// we've seen a vtable for it yet)
	// bool virtually_inherits_base(class_info *needle);
};

class module_info
{
public:
	Elf64_Ehdr* elf;
	code_ptr module_base_offset;
	code_ptr module_textrap_start;
	code_ptr module_textrap_end;
        module_info *next;

	module_info()
	{
		elf = NULL;
	}
};


#endif
