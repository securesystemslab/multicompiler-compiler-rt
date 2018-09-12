/*
 * vtable_rando.cpp
 *
 *  Created on: Apr 8, 2015
 *      Author: stijn
 */

#include "vtable_rando.h"
#include "hde64.h"
#include <algorithm>
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cxxabi.h>
#include <deque>
#include <dlfcn.h>
#include <elf.h>
#include <map>
#include <set>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

/*-----------------------------------------------------------------------------
        Macros
-----------------------------------------------------------------------------*/
// These can now be specified on the build command line for debug builds.
// This is the default debug level, and can be overridden using the environment
// variable MVEE_VTABLE_RANDO_DEBUG
#ifndef VTABLERANDO_DEBUG
#define VTABLERANDO_DEBUG 0
#endif

#define PAGE_SIZE 4096
#define ROUND_DOWN(x, multiple) ((((long)(x))) & (~(multiple - 1)))
#define ROUND_UP(x, multiple) ((((long)(x)) + multiple - 1) & (~(multiple - 1)))

// xvtable trampoline size in bytes
#define XVT_SIZE 8

static int debug_level = VTABLERANDO_DEBUG;

inline void VTBLDBG(int level, const char *format, ...) {
  if (debug_level < level)
    return;
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}

/*-----------------------------------------------------------------------------
        Globals
-----------------------------------------------------------------------------*/
//
// Shared variables
//
static module_info *modules_head = nullptr;
static std::vector<module_info *> modules;

//
// vtablerando variables
//
static std::map<unsigned long, class_info *> classes;
static std::map<std::string, class_info *> name_to_class;
static std::vector<vtable_info *> vtables;
static std::vector<vcall_info *> tmp_vcalls;
static std::map<code_ptr, vtable_info *> subtable_map;
static std::deque<class_info *> class_traversal_list;
static class_info *root = NULL;
static std::vector<std::string> blacklist{};

/*-----------------------------------------------------------------------------
  Debugging aid
-----------------------------------------------------------------------------*/
static inline unsigned long check_size(unsigned long size) {
  assert((size >> (8 * sizeof(unsigned long) - 1)) == 0);
  return size;
}

/*-----------------------------------------------------------------------------
        Method definitions
-----------------------------------------------------------------------------*/

static void init_debugging() {
  char *debug_var;
  debug_var = getenv("MVEE_VTABLE_RANDO_DEBUG");
  if (debug_var)
    debug_level = atoi(debug_var);
}

static vtable_info *
vtablerando_create_dummy_table(unsigned long vtable_size = 0,
                               unsigned long original_vtable_size = 0);

vtable_info *vtable_info::get_parent() {
  if (parent)
    return parent;

  for (auto it = base_names.begin(), end = base_names.end(); it != end; ++it) {
    auto class_entry = name_to_class.find(std::string(*it));
    VTBLDBG(2, "looking at base name %s\n", *it);
    if (class_entry == name_to_class.end()) {
      fprintf(stderr,
              "WARNING: could not find class %s during vtable splitting\n",
              *it);
      continue;
    }

    if (class_entry->second != info) {
      if (class_entry->second->vtables.size() > 0) {
        parent = class_entry->second->vtables[0];
      } else {
        VTBLDBG(2, "Creating dummy vtable for missing class %s\n",
                class_entry->second->name.c_str());
        parent = vtablerando_create_dummy_table();
        parent->info = class_entry->second;
        class_entry->second->vtables.push_back(parent);
      }
      return parent;
    }
  }

  return nullptr;
}

void vtable_info::add_variant(vtable_info *variant) {
  variants.push_back(variant);
}

bool vtable_info::have_variant(vtable_info *variant) {
  if (vtable_locations[0] == variant->vtable_locations[0])
    return true;

  for (auto variant : variants)
    if (variant->vtable_locations[0] == vtable_locations[0])
      return true;

  return false;
}

void vtable_info::randomize_variant(int i, bool cleanup) {
  // gather the original jmp targets
  for (unsigned long j = 0; j < vtable_size; ++j) {
    original_targets[j] = (vtable_locations[i] + (j * XVT_SIZE) + 1) +
                          *(int *)(vtable_locations[i] + (j * XVT_SIZE) + 1) +
                          4;

    VTBLDBG(4, "xvtbl[%lu] was %016lx\n", j, original_targets[j]);
  }

  // rewrite the vtable
  for (unsigned long j = 0; j < vtable_size; ++j) {
    // Ensure that we are writing to a properly aligned jump instruction
    *(unsigned long *)(vtable_locations[i] + (shuffled_indices[j] * XVT_SIZE)) =
        0x001f0f00000000e9ULL;
    *(int *)(vtable_locations[i] + (shuffled_indices[j] * XVT_SIZE) + 1) =
        original_targets[j] -
        (vtable_locations[i] + (shuffled_indices[j] * XVT_SIZE) + 1) - 4;

    VTBLDBG(4, "xvtbl[%lu] is now %016lx\n", shuffled_indices[j],
            (vtable_locations[i] + (shuffled_indices[j] * XVT_SIZE) + 1) +
                *(int *)(vtable_locations[i] +
                         (shuffled_indices[j] * XVT_SIZE) + 1) +
                4);
  }

  VTBLDBG(1, "Shuffled vtable for %s @ 0x%016lx\n", info->name.c_str(), *vtable_locations[i]);

  if (cleanup)
    std::fill(original_targets.begin(), original_targets.end(), 0);
}

/*-----------------------------------------------------------------------------
    get_class_type_str
-----------------------------------------------------------------------------*/
static const char *get_class_type_str(class_type type) {
#if VTABLERANDO_DEBUG > 0
  switch (type) {
  case pb:
    return "<pure base class>";
  case si:
    return "<single inheritance class>";
  case vmi:
    return "<virtual multiple inheritance class>";
  default:
    return "";
  }
#else
  return "";
#endif
}

/*-----------------------------------------------------------------------------
    print_children
-----------------------------------------------------------------------------*/
static void print_children(int level, class_info *parent) {
#if VTABLERANDO_DEBUG > 0
  for (int i = 0; i < level; ++i)
    fprintf(stderr, "  ");
  fprintf(stderr, "> %s\n", parent->name.c_str());

  for (auto child : parent->children)
    print_children(level + 1, child.second);
#endif
}

/*-----------------------------------------------------------------------------
    get_class_type_by_vtable_ptr - I'm in your RTTI, parsing your RTTI :D
-----------------------------------------------------------------------------*/
static class_type get_class_type_by_rtti_ptr(unsigned long rtti) {
  __cxxabiv1::__class_type_info *real_rtti =
      reinterpret_cast<__cxxabiv1::__class_type_info *>(rtti);

  if (dynamic_cast<__cxxabiv1::__vmi_class_type_info *>(real_rtti))
    return vmi;
  if (dynamic_cast<__cxxabiv1::__si_class_type_info *>(real_rtti))
    return si;

  return pb;
}

/*-----------------------------------------------------------------------------
        read_uleb128
-----------------------------------------------------------------------------*/
static unsigned long long read_uleb128(unsigned char **ptr) {
  unsigned long long result = 0;
  unsigned int shift = 0;

  while (true) {
    unsigned char byte = *(unsigned char *)((*ptr)++);

    result |= (unsigned long long)(byte & 0x7f) << shift;
    shift += 7;

    if ((byte & 0x80) == 0)
      return result;
  }

  return 0;
}

/*-----------------------------------------------------------------------------
    init_rng
-----------------------------------------------------------------------------*/
static void init_rng() {
  char *seedstr, *end;
  seedstr = getenv("MVEE_VTABLE_RANDO_SEED");
  if (seedstr != NULL) {
    VTBLDBG(2, "The vtable rando seed string is %s\n", seedstr);
    unsigned long seedlu = std::strtoul(seedstr, &end, 10);
    if (errno == ERANGE) {
      fprintf(stderr,
              "init_rng: Range error while parsing vtable rando seed.\n");
      exit(-1);
    } else if (seedstr == end) {
      fprintf(stderr,
              "init_rng: Failed to convert vtable rando seed to ulong.\n");
      exit(-1);
    }
    VTBLDBG(2, "The vtable rando seed integer is %lu\n", seedlu);
    std::srand(seedlu);
  } else {
    std::srand(std::time(0));
  }
}

/*-----------------------------------------------------------------------------
    add_vcall
-----------------------------------------------------------------------------*/
static void add_vcall(const char *class_type_str, unsigned long idx_size,
                      unsigned long index, unsigned long ptr_to_idx,
                      unsigned long ptr_to_ins, vcall_type type) {
  vcall_info *vcall = new vcall_info;
  vcall->resolved_subvtable = NULL;
  vcall->class_name = (const char *)class_type_str;
  vcall->idx_size = idx_size;
  vcall->old_idx = (type == idx) ? index : 0;
  vcall->old_addr = (type != idx) ? index : 0;
  vcall->ptr_to_idx = ptr_to_idx;
  vcall->ptr_to_vcall = ptr_to_ins;
  vcall->type = type;
  vcall->idx_offset = 0;
  vcall->sign_extended = true;
  tmp_vcalls.push_back(vcall);
}

/*-----------------------------------------------------------------------------
    parse_textrap
-----------------------------------------------------------------------------*/
static void parse_textrap(module_info *module) {
  VTBLDBG(1, "Parsing textrap info for module @ %p\n", module->elf);
  unsigned long ptr = *module->module_textrap_start;

  while (ptr < *module->module_textrap_end) {
    bool has_vtablevector, has_vcallvector;

    unsigned int trap_header = *(unsigned int *)ptr;
    ptr += sizeof(unsigned int);

    VTBLDBG(2, "trap_header: %08x\n", trap_header);

    // get rid of the version tag
    trap_header >>= 8;
    has_vtablevector = trap_header & 16;
    has_vcallvector = trap_header & 32;

    if (has_vtablevector) {
      VTBLDBG(2, "reading vtablevector\n");

      while (true) {
        unsigned long vtable_location = *(unsigned long *)ptr;
        unsigned long number_of_entries = 0;
        ptr += sizeof(unsigned long);

        if (!vtable_location)
          break;

        number_of_entries = (unsigned long)read_uleb128((unsigned char **)&ptr);

        std::vector<const char *> base_names;
        while (*(unsigned long *)ptr != 0) {
          base_names.push_back(*(const char **)ptr);
          ptr += sizeof(void *);
        }
        ptr += sizeof(void *);

        unsigned long rtti =
            *(unsigned long *)(vtable_location - sizeof(unsigned long));
        unsigned long name = *(unsigned long *)(rtti + sizeof(unsigned long));

        VTBLDBG(2,
                "> found vtable @ 0x%016lx with %ld entries - rtti @ %016lx - "
                "name @ 0x%016lx, type: %s\n",
                *(unsigned long *)vtable_location, number_of_entries, rtti,
                name, (const char *)name);
        for (auto name : base_names) {
          VTBLDBG(2, "  > found base %s\n", name);
        }

        auto it = classes.find(rtti);

        // allocate a new class_info if needed
        if (it == classes.end()) {
          class_info *new_class = new class_info;
          new_class->rtti =
              reinterpret_cast<__cxxabiv1::__class_type_info *>(rtti);
          new_class->name = std::string((const char *)name);
          new_class->type = get_class_type_by_rtti_ptr(rtti);
          new_class->visited = false;
          new_class->address_point = vtable_location;

          new_class->blacklist = false;
          for (auto &blacklisted : blacklist) {
            if (new_class->name == blacklisted) {
              VTBLDBG(2, "Skipping vtable %s because it is in the blacklist\n",
                      new_class->name.c_str());
              new_class->blacklist = true;
              break;
            }
          }

          auto duplicate = name_to_class.find(new_class->name);
          if (duplicate == name_to_class.end()) {
            it = classes
                     .insert(std::pair<unsigned long, class_info *>(rtti,
                                                                    new_class))
                     .first;
            name_to_class.insert(std::pair<std::string, class_info *>(
                new_class->name, new_class));
          } else {
            assert(duplicate->second->name == new_class->name);
            assert(duplicate->second->type == new_class->type);
            it = classes.find((unsigned long)duplicate->second->rtti);
            VTBLDBG(2, "inserting as duplicate into class for rtti %016lx\n",
                    duplicate->second->rtti);
          }
        }

	// Don't add duplicate entries for the same xvtable. Apparently we might
	// emit duplicate trap info.
	bool already_added = false;
	for (vtable_info *vti : it->second->vtables) {
	  auto existing = std::find(vti->vtable_locations.begin(),
				    vti->vtable_locations.end(),
				    (code_ptr) * (unsigned long *)vtable_location);
	  if (existing != vti->vtable_locations.end())
	    already_added = true;
	}

	if (!already_added) {
	  // and store this new vtable in the class_info
	  vtable_info *new_vtable = new vtable_info;
	  new_vtable->dummy_table = false;
	  new_vtable->info = it->second;
	  new_vtable->offset = 0;
	  // deref to go from vtable loc to xvtable loc
	  new_vtable->vtable_locations.push_back(
            (code_ptr) * (unsigned long *)vtable_location);
	  new_vtable->base_names = base_names;
	  new_vtable->vtable_size = check_size(number_of_entries);
	  new_vtable->original_vtable_size = check_size(number_of_entries);
	  it->second->vtables.push_back(new_vtable);
	}
      }
    }

    if (has_vcallvector) {
      unsigned long first_vcall_sym = *(unsigned long *)ptr;
      ptr += sizeof(unsigned long);

      while (true) {
        const char *class_type_str = NULL;
        unsigned long offset_from_first_sym =
            (unsigned long)read_uleb128((unsigned char **)&ptr);

        class_type_str = (const char *)*(unsigned long *)ptr;
        ptr += sizeof(unsigned long);

        if (!class_type_str)
          break;

        bool isMethodPointer = *(unsigned char *)ptr;
        ptr += sizeof(unsigned char);

        VTBLDBG(2, "> found %s @ 0x%016lx - class type: %s (%016lx)\n",
                isMethodPointer ? "method pointer" : "vcall",
                first_vcall_sym + offset_from_first_sym, class_type_str,
                (unsigned long)class_type_str);

        unsigned long vcall_instr = first_vcall_sym + offset_from_first_sym;
        vcall_type type = isMethodPointer ? method_pointer : unknown;
        add_vcall(class_type_str, 0, 0, 0, vcall_instr, type);
      }
    }
  }
}

/*-----------------------------------------------------------------------------
    vtablerando_generate_empty_class -
-----------------------------------------------------------------------------*/
static class_info *
vtablerando_generate_empty_class(const __cxxabiv1::__class_type_info *info) {
  class_info *new_class = new class_info;
  new_class->rtti = const_cast<__cxxabiv1::__class_type_info *>(info);
  new_class->name = std::string(info->name());
  new_class->type = get_class_type_by_rtti_ptr((unsigned long)info);
  new_class->visited = false;
  new_class->blacklist = false;
  name_to_class.insert(
      std::pair<std::string, class_info *>(new_class->name, new_class));
  return new_class;
}

/*-----------------------------------------------------------------------------
    vtablerando_process_class - connect class <new_class> to its parents.
    If we do not find the parent in classes, then we will add it on the fly
-----------------------------------------------------------------------------*/
static void vtablerando_process_class(std::deque<class_info *> &classes_list,
                                      class_info *new_class) {
  VTBLDBG(2, "found class: %s\n", new_class->name.c_str());
  VTBLDBG(2, "> class type is: %s\n", get_class_type_str(new_class->type));
  VTBLDBG(2, "> found %lu vtable(s) for this class\n",
          new_class->vtables.size());

  // this is a pure baseclass. It does not have any parents so we only connect
  // it to the root node
  if (new_class->type == pb) {
    root->children.insert(std::pair<unsigned long, class_info *>(
        (unsigned long)new_class->rtti, new_class));
    new_class->parents.push_back(root);
    new_class->parent_type.push_back(_nonvirtual);
    VTBLDBG(2, "connected to root node\n");
  }
  // this is a single inheritance class. It has just one parent, but from this
  // parent, it might inherit multiple vtables
  else if (new_class->type == si) {
    __cxxabiv1::__si_class_type_info *info =
        static_cast<__cxxabiv1::__si_class_type_info *>(new_class->rtti);

    class_info *parent_class = nullptr;
    auto parent = classes.find((unsigned long)info->__base_type);
    if (parent == classes.end()) {
      parent_class = vtablerando_generate_empty_class(info->__base_type);
      classes_list.push_back(parent_class);
      classes.insert(std::pair<unsigned long, class_info *>(
          (unsigned long)parent_class->rtti, parent_class));
    } else {
      parent_class = parent->second;
    }

    VTBLDBG(2, "adding class %s as child to parent class %s\n",
            new_class->name.c_str(), parent_class->name.c_str());
    parent_class->children.insert(std::pair<unsigned long, class_info *>(
        (unsigned long)new_class->rtti, new_class));
    new_class->parents.push_back(parent_class);
    new_class->parent_type.push_back(_nonvirtual);
  }
  // this is a virtual multiple inheritance class. It has several parents,
  // from each of whom it might inherit multiple vtables
  else if (new_class->type == vmi) {
    __cxxabiv1::__vmi_class_type_info *info =
        static_cast<__cxxabiv1::__vmi_class_type_info *>(new_class->rtti);

    // tmp.second->parents.resize(info->__base_count);

    for (unsigned i = 0; i < info->__base_count; ++i) {
      class_info *parent_class = nullptr;
      auto parent =
          classes.find((unsigned long)info->__base_info[i].__base_type);
      if (parent == classes.end()) {
        parent_class =
            vtablerando_generate_empty_class(info->__base_info[i].__base_type);
        classes_list.push_back(parent_class);
        classes.insert(std::pair<unsigned long, class_info *>(
            (unsigned long)parent_class->rtti, parent_class));
      } else {
        parent_class = parent->second;
      }

      VTBLDBG(2, "adding class %s as child to parent class %s\n",
              new_class->name.c_str(), parent_class->name.c_str());
      parent_class->children.insert(std::pair<unsigned long, class_info *>(
          (unsigned long)new_class->rtti, new_class));
      new_class->parents.push_back(parent_class);

      if (info->__base_info[i].__offset_flags & 1) {
        // check if vbase offset is 0 (indicating that this virtual base could
        // be a primary base)

        // TODO/FIXME: sjc: assuming that missing classes are empty for now
        if (!(*new_class->address_point))
          new_class->parent_type.push_back(_empty_virtual);
        else if (*new_class->address_point &&
                 *(long *)(*new_class->address_point +
                           (info->__base_info[i].__offset_flags >> 8)) == 0)
          new_class->parent_type.push_back(_empty_virtual);
        else
          new_class->parent_type.push_back(_virtual);
      } else
        new_class->parent_type.push_back(_nonvirtual);
    }
  }
}

/*-----------------------------------------------------------------------------
    vtablerando_create_dummy_table
-----------------------------------------------------------------------------*/
static vtable_info *
vtablerando_create_dummy_table(unsigned long vtable_size,
                               unsigned long original_vtable_size) {
  vtable_info *dummy_table = new vtable_info;
  dummy_table->vtable_size = check_size(vtable_size);
  dummy_table->original_vtable_size = check_size(original_vtable_size);
  dummy_table->vtable_locations.push_back((code_ptr)0);
  dummy_table->dummy_table = true;
  return dummy_table;
}

/*-----------------------------------------------------------------------------
  vtablerando_build_class_graph - using the classes map, we connect all
  classes to their super and subclasses
-----------------------------------------------------------------------------*/
static void vtablerando_build_class_graph() {
  std::deque<class_info *> classes_list;
  root = new class_info;
  root->name = "<[root]>";
  root->has_vtable = false;
  root->has_virtual_base = false;
  root->visited = false;

  // add all known classes to the graph
  int i = 0;
  classes_list.resize(classes.size());
  for (auto tmp : classes)
    classes_list[i++] = tmp.second;

  while (classes_list.size() > 0) {
    class_info *new_class = classes_list.front();
    classes_list.pop_front();
    vtablerando_process_class(classes_list, new_class);
  }

  for (auto tmp : root->children) {
    VTBLDBG(2, "found pure base class: %s\n", tmp.second->name.c_str());
    print_children(0, tmp.second);
  }
}

/*-----------------------------------------------------------------------------
    vtablerando_build_class_traversal_list - reverse topolical sort
-----------------------------------------------------------------------------*/
static void vtablerando_build_class_traversal_list_recurse(class_info *node) {
  node->visited = true;

  for (auto child : node->children)
    if (!child.second->visited)
      vtablerando_build_class_traversal_list_recurse(child.second);

  class_traversal_list.push_front(node);
}

/*-----------------------------------------------------------------------------
        vtablerando_add_subvtable - we want to keep the chopped up vtables
around in the subtable_map so that we can map absolue and indirect vcalls right
onto the subtable they point to. This allows us to derive exactly which element
they're pointing at and consequently, how the vcall address changes after
randomization
-----------------------------------------------------------------------------*/
static void vtablerando_add_subvtable(vtable_info *vtable) {
  if (*vtable->vtable_locations[0] == 0 || vtable->dummy_table)
    return;

  VTBLDBG(3, "Inserting subvtable: %016lx-%016lx - class: %s",
          *vtable->vtable_locations[0],
          *vtable->vtable_locations[0] + vtable->vtable_size * XVT_SIZE,
          vtable->info->name.c_str());
  vtable_info *parent = vtable->get_parent();
  if (parent)
    VTBLDBG(3, " with parent: %s\n", parent->info->name.c_str());
  else
    VTBLDBG(3, "\n");
  subtable_map.insert(
      std::pair<code_ptr, vtable_info *>(vtable->vtable_locations[0], vtable));
}

/*-----------------------------------------------------------------------------
        vtablerando_split_table - chop vtable <table> into two

        Returns the lower cut
-----------------------------------------------------------------------------*/
static vtable_info *vtablerando_split_table(vtable_info *table,
                                            unsigned long split_size) {
  if (table->dummy_table)
    return table;

  vtable_info *parent_specific_part = new vtable_info;
  parent_specific_part->info = table->info;
  // parent_specific_part->main_variant = table->get_parent();
  parent_specific_part->vtable_size =
      check_size(table->vtable_size - split_size);
  parent_specific_part->original_vtable_size =
      check_size(table->original_vtable_size);
  parent_specific_part->offset = 0;
  parent_specific_part->vtable_locations.push_back(table->vtable_locations[0]);

  table->vtable_locations[0] =
      table->vtable_locations[0] + (table->vtable_size - split_size) * XVT_SIZE;
  table->offset = parent_specific_part->vtable_size * XVT_SIZE;
  table->vtable_size = check_size(split_size);

  return parent_specific_part;
}

/*-----------------------------------------------------------------------------
        vtablerando_split_tables - we chop up the vtables into subvtables. Each
        group of subvtables must be randomized using the same permutation
-----------------------------------------------------------------------------*/
static void vtablerando_split_tables() {
  for (std::deque<class_info *>::iterator it = class_traversal_list.end() - 1;
       it != class_traversal_list.begin(); --it) {
    class_info *base = *it;
    vtable_info *primary_vtable = NULL;

    VTBLDBG(2, "Splitting tables for class %s with rtti @ 0x%016lx\n",
            base->name.c_str(), (unsigned long)base->rtti);

    // for the purposes of splitting, we consider virtual vtables to be just
    // vtables for (auto vtable : base->virtual_vtables)
    // 	base->vtables.push_back(vtable);

    if (base->vtables.size() > 0) {
      primary_vtable = base->vtables[0];
      vtable_info *parent_vtable = primary_vtable->get_parent();

      // add duplicate tables as variants of the primary
      for (auto vtable = base->vtables.begin();
           vtable != base->vtables.end();) {
        if (*vtable == primary_vtable) {
          vtable++;
          continue;
        }

        vtable_info *parent = (*vtable)->get_parent();

        // If we are handling a second copy of this class's vtable, don't try to
        // push it up
        if (!parent) {
          VTBLDBG(2,
                  "possible duplicate vtable: 0x%016lx for class %s [%lu "
                  "elements]\n",
                  *(*vtable)->vtable_locations[0],
                  (*vtable)->info->name.c_str(), (*vtable)->vtable_size);
          if (!primary_vtable->have_variant(*vtable))
            primary_vtable->add_variant(*vtable);
          vtable = base->vtables.erase(vtable);
        } else {
          vtable++;
        }
      }

      unsigned long diff = primary_vtable->vtable_size;
      if (parent_vtable)
        diff -= parent_vtable->vtable_size;

      // the leaf vtable has exactly as much elements as the parent's vtable.
      // We do not need to break down this leaf vtable into two pieces.
      // Instead, we just consider the leaf vtable to be a variant of the
      // parent's vtable
      if (!diff && parent_vtable) {
        VTBLDBG(2,
                "> class %s primary vtable does not add any vfuncs to primary "
                "vtable inherited from parent %s\n",
                base->name.c_str(), parent_vtable->info->name.c_str());
        // we can move this vtable as is
        parent_vtable->add_variant(primary_vtable);
        for (auto variant : primary_vtable->variants) {
          variant->main_variant = parent_vtable;
          parent_vtable->add_variant(variant);
        }
      } else {
        // if the parent's vtable has X elements and the leaf's vtable has Y
        // elements with Y stricly greater than X, then we want to chop up the
        // leaf's vtable (and all of its variants) into a subvtable containing X
        // elements and one containing Y-X elements.
        //
        // The subvtables that contain Y-X elements belong to the leaf.
        // The subvtables containing X elements however are just variants of the
        // parent's vtable.

        if (parent_vtable) {
          VTBLDBG(2,
                  "> class %s primary vtable adds %lu funcs to primary vtable "
                  "inherited from parent %s\n",
                  base->name.c_str(), diff, parent_vtable->info->name.c_str());

          // This is not a pure base class. We have to break up the vtables
          // We break up the main vtable first
          parent_vtable->add_variant(
              vtablerando_split_table(primary_vtable, diff));

          for (auto variant : primary_vtable->variants) {
            parent_vtable->add_variant(vtablerando_split_table(variant, diff));
            variant->main_variant = primary_vtable;
          }
        } else {
          VTBLDBG(2, "> class %s primary vtable has %lu new funcs\n",
                  base->name.c_str(), diff);
        }

        vtablerando_add_subvtable(primary_vtable);
        for (auto variant : primary_vtable->variants) {
          variant->main_variant = primary_vtable;
          vtablerando_add_subvtable(variant);
        }

        vtables.push_back(primary_vtable);
      }

      //			base->vtables.erase(base->vtables.begin());
    }

    // remaining vtables just have to be pushed to their parents
    for (auto vtable : base->vtables) {
      if (vtable == primary_vtable)
        continue;

      vtable_info *parent = vtable->get_parent();

      // parent will be valid now because we've deleted all parentless vtables
      // before splitting
      if (parent->dummy_table)
        parent->info->vtables[0] = vtable;
      else {
        parent->add_variant(vtable);

        for (auto variant : vtable->variants)
          parent->add_variant(variant);
      }
    }
  }

  VTBLDBG(2, "found %lu possible vtable layouts:\n", vtables.size());

  for (auto &vtable : vtables) {
    VTBLDBG(2, "> Main Vtable for class %s @ 0x%016lx [%lu elements]\n",
            vtable->info->name.c_str(), *vtable->vtable_locations[0],
            vtable->vtable_size);

    for (auto &variant : vtable->variants) {
      if (*variant->vtable_locations[0] == 0)
        continue;

      VTBLDBG(2,
              "	> Variant: subvtable '%s'-in-'%s' @ 0x%016lx [%lu out of %lu "
              "elements]\n",
              vtable->info->name.c_str(), variant->info->name.c_str(),
              *variant->vtable_locations[0], vtable->vtable_size,
              variant->original_vtable_size);

      vtable->vtable_locations.push_back(variant->vtable_locations[0]);
    }
  }
}

/*-----------------------------------------------------------------------------
  vtablerando_resolve_vcalls - This is where the magic happens. We have to
  map each vcall onto a specific vtable layout so that we know how to rewrite
  the vcall index after shuffling that vtable layout.
-----------------------------------------------------------------------------*/
static void vtablerando_rewrite_vcalls() {
  hde64s ins;

  for (auto vcall : tmp_vcalls) {
    // disassemble the instruction and figure out the vcall type
    hde64_disasm((const void *)*vcall->ptr_to_vcall, &ins);

    VTBLDBG(2, "Rewriting vcall instruction @ 0x%016lx\n",
            *vcall->ptr_to_vcall);

    // store whether this is a method pointer
    vcall_type original_type = vcall->type;

    // ADD [Ev, Iz] instr
    if (ins.opcode == 0x81 && ins.modrm_mod == 3 && ins.modrm_reg == 0) {
      if (ins.rex_w)
        vcall->sign_extended = true;

      vcall->idx_size = 4;
      vcall->type = idx;
      vcall->old_idx = ins.imm.imm32;

      VTBLDBG(2, "> vcall type is idx\n");
    }
    // ADD [Ev, Ib] instr
    else if (ins.opcode == 0x83 && ins.modrm_mod == 3 && ins.modrm_reg == 0) {
      vcall->sign_extended = true;
      vcall->idx_size = 1;
      vcall->type = idx;
      vcall->old_idx = ins.imm.imm8;

      VTBLDBG(2, "> vcall type is idx - idx is %lu\n", vcall->old_idx);
    }
    // 0x0 through 0x5 are all encodings of ADD
    else if (ins.opcode <= 0x5) {
      vcall->idx_size = 4;
      vcall->type = idx;
      vcall->old_idx = ins.imm.imm32;

      VTBLDBG(2, "> vcall type is idx\n");
    }
    // immediate mov into register - this is where it gets really tricky. This
    // can be an index OR an address
    else if (ins.opcode >= 0xB8 && ins.opcode <= 0xBF) {
      unsigned long tmp_addr = 0;

      // size depends on prefix - with prefix 0x66 or REX.W, we override the
      // operand size from word to double word
      if (ins.p_66 || ins.rex_w) {
        vcall->idx_size = 8;
        tmp_addr = ins.imm.imm64;
      }
      // without the prefix it's just a word
      else {
        vcall->idx_size = 4;
        tmp_addr = ins.imm.imm32;
      }

      VTBLDBG(2,
              "> This instruction is ambiguous - Determining vcall type from "
              "address/index %p\n",
              (void *)tmp_addr);

      // try to resolve it
      auto subtable = subtable_map.upper_bound((code_ptr)tmp_addr);
      --subtable;

      if (subtable != subtable_map.end() &&
          tmp_addr < subtable->second->vtable_locations[0] +
                         subtable->second->vtable_size * XVT_SIZE &&
          tmp_addr >= *subtable->second->vtable_locations[0]) {
        VTBLDBG(2,
                "> Vcall type is address - subvtable @ 0x%016lx-0x%016lx - "
                "which is at offset %016lx\n",
                *subtable->second->vtable_locations[0],
                subtable->second->vtable_locations[0] +
                    subtable->second->vtable_size * XVT_SIZE,
                subtable->second->offset);
        vcall->type = absolute;
        vcall->old_addr = tmp_addr;
        vcall->resolved_subvtable = subtable->second;
        vcall->old_idx =
            vcall->old_addr - subtable->second->vtable_locations[0];
      } else if (tmp_addr > 0x4000) {
        VTBLDBG(2, "WARNING: Found what appears to be an absolute address "
                   "vcall into a vtable that we don't know about and don't "
                   "have an address for!\n");
        VTBLDBG(2, "Skipping this vcall\n");
        continue;
      } else {
        VTBLDBG(2, "> Vcall type is index\n");
        vcall->type = idx;
        vcall->old_idx = tmp_addr;
      }
    }
    /* LEA Gv, M */
    else if (ins.opcode == 0x8d) {
      if (ins.modrm_mod == 0 && ins.modrm_rm == 5) /* disp32 */
      {
        vcall->type = relative;
        vcall->idx_size = 4;
        vcall->old_addr =
            (*vcall->ptr_to_vcall) + ins.len + (int)ins.disp.disp32;

        auto subtable = subtable_map.upper_bound(vcall->old_addr);
        --subtable;

        if (subtable != subtable_map.end() &&
            *vcall->old_addr < subtable->second->vtable_locations[0] +
                                   subtable->second->vtable_size * XVT_SIZE) {
          VTBLDBG(2,
                  "> Vcall type is relative address - subvtable @ "
                  "0x%016lx-0x%016lx - which is at offset %016lx\n",
                  *subtable->second->vtable_locations[0],
                  subtable->second->vtable_locations[0] +
                      subtable->second->vtable_size * XVT_SIZE,
                  subtable->second->offset);
          vcall->type = relative;
          vcall->resolved_subvtable = subtable->second;
          vcall->old_idx =
              vcall->old_addr - subtable->second->vtable_locations[0];
        }
      } else if (ins.modrm_mod == 2) /* [reg] + disp32 */
      {
        vcall->idx_size = 4;
        vcall->type = idx;
        vcall->old_idx = ins.disp.disp32;
        vcall->sign_extended = true;
        VTBLDBG(2, "> vcall type is idx - idx is %lu\n", vcall->old_idx);
      } else if (ins.modrm_mod == 1) /* [reg] + disp8 */
      {
        vcall->idx_size = 1;
        vcall->type = idx;
        vcall->old_idx = ins.disp.disp8;
        vcall->sign_extended = true;
        VTBLDBG(2, "> vcall type is idx - idx is %lu\n", vcall->old_idx);
      } else {
        assert(0 && "unknown LEA Mod R/M");
      }
    }
    // immediate mov into memory - this should be a method index for a member
    // pointer
    else if (ins.opcode == 0xC7) {
      vcall->type = idx;
      vcall->idx_size = 4;
      vcall->old_idx = ins.imm.imm32;
      if (ins.rex_w)
        vcall->sign_extended = true;

      VTBLDBG(2, "> vcall type is idx - idx is %lu\n", vcall->old_idx);
    } else {
      fprintf(stderr,
              "parse_textrap: Couldn't resolve index for vcall @ 0x%016lx - "
              "implement opcode: 0x%02x!\n",
              *vcall->ptr_to_vcall, ins.opcode);
      exit(-1);
    }

    vcall->ptr_to_idx = vcall->ptr_to_vcall + ins.len - vcall->idx_size;

    if (vcall->type == idx) {
      // Method pointer indices are left shifted by 1 to leave room for the
      // virtual flag
      if (original_type == method_pointer) {
        VTBLDBG(2,
                "Rewriting index method pointer with original value of %lu\n",
                vcall->old_idx);
        vcall->old_idx >>= 1;
        vcall->old_idx *= XVT_SIZE; // this code expects old_idx to point to a
                                    // multiple of XVT_SIZE
      }

      auto vcall_class = name_to_class.find(vcall->class_name);

      // this assertion might fail if we have not encountered the RTTI for this
      // class RTTIs are mainly gathered from the vtables we find in texttrap.
      // We also gather RTTIs for classes that are missing in the class
      // hierarchy during vtablerando_build_class_graph

      // stijn: making this assert into a warning. there is a corner case where
      // dead but emitted code refers to abstract classes without a vtable
      // assert(vcall_class != name_to_class.end());
      if (vcall_class == name_to_class.end()) {
        VTBLDBG(2, "WARNING: could not find class %s during vcall rewriting\n",
                vcall->class_name);
        continue;
      }

      VTBLDBG(2,
              "this is a call for class %s (%s) with rtti @ 0x%016lx - this "
              "class has %lu vtables\n",
              vcall->class_name, vcall_class->second->name.c_str(),
              (unsigned long)vcall_class->second->rtti,
              vcall_class->second->vtables.size());

      // Walk up the inheritance chain
      unsigned long elem = vcall->old_idx / XVT_SIZE;
      vcall->resolved_subvtable = vcall_class->second->vtables[0];
      vtable_info *prev = vcall->resolved_subvtable;

      VTBLDBG(4, "original size of initial subtable: %lu\n",
              vcall->resolved_subvtable->original_vtable_size);

      while (elem < vcall->resolved_subvtable->original_vtable_size) {
        VTBLDBG(3,
                "Trying to move up because elem: %lu is lower than size %lu "
                "for vtable %s\n",
                elem, vcall->resolved_subvtable->original_vtable_size,
                vcall->resolved_subvtable->info->name.c_str());

        prev = vcall->resolved_subvtable;
        vcall->resolved_subvtable = vcall->resolved_subvtable->get_parent();
        if (!vcall->resolved_subvtable) {
          vcall->idx_offset = 0;
          break;
        }
        // vcall->resolved_subvtable = parent_class->vtables[0];
        vcall->idx_offset =
            vcall->resolved_subvtable->original_vtable_size * XVT_SIZE;
      }

      vcall->resolved_subvtable = prev;

      VTBLDBG(2,
              "Resolved vcall to subvtable '%s'-in'%s' which is at offset "
              "0x%016lx in the primary vtable for %s\n",
              vcall->resolved_subvtable->info->name.c_str(), vcall->class_name,
              vcall->idx_offset, vcall->class_name);

      if (vcall->resolved_subvtable->shuffled_indices.size() == 0)
        continue;

      unsigned long old_idx_within_subvtable =
          (vcall->old_idx - vcall->idx_offset) / XVT_SIZE;

      // This assertion could fail if the old index is out of the bounds of the
      // subvtable we resolved the vcall to The one case where we've seen this
      // happen is when the vcall call type wasn't marked correctly (i.e. it was
      // pointing to the intended class' parent, which has a smaller vtable than
      // the intended class)
      assert(old_idx_within_subvtable <
             vcall->resolved_subvtable->shuffled_indices.size());

      unsigned long shuffled_idx_within_subvtable =
          vcall->resolved_subvtable->shuffled_indices[old_idx_within_subvtable];
      unsigned long new_idx =
          (vcall->idx_offset + shuffled_idx_within_subvtable * XVT_SIZE);

      if (original_type == method_pointer) {
        // method pointers only store an index, not the actual offset
        new_idx /= XVT_SIZE;
        // set lowest bit to indicate a virtual call
        new_idx <<= 1;
        new_idx += 1;
      }

      if (vcall->sign_extended) {
        // if the vcall index will get sign extended, then we have to ensure
        // that we don't accidentally set the most significant bit to one. If we
        // would, the index would become negative after rewriting
        //
        // If we ever see this, we simply need vcall instructions with more size
        // to write the index
        assert((new_idx >> ((vcall->idx_size * 8) - 1)) == 0);
      }

      VTBLDBG(3,
              "rewriting idx vcall: 0x%016lx - old idx: 0x%016lx - offset: "
              "0x%016lx - new idx: 0x%016lx - shuffled[%lu]: 0x%016lx\n",
              *vcall->ptr_to_vcall, vcall->old_idx, vcall->idx_offset, new_idx,
              (vcall->old_idx - vcall->idx_offset) / XVT_SIZE,
              vcall->resolved_subvtable
                  ->shuffled_indices[(vcall->old_idx - vcall->idx_offset) /
                                     XVT_SIZE]);

      switch (vcall->idx_size) {
      case (8): {
        *(uint64_t *)*vcall->ptr_to_idx = new_idx;
        VTBLDBG(3, "wrote idx: %lu\n", *(uint64_t *)*vcall->ptr_to_idx);
        break;
      }

      case (4): {
        // we check here if the new index will fit in the 4 byte slot
        assert((uint32_t)new_idx == new_idx);
        *(uint32_t *)*vcall->ptr_to_idx = (uint32_t)new_idx;
        VTBLDBG(3, "wrote idx: %u\n", *(uint32_t *)*vcall->ptr_to_idx);
        break;
      }

      case (2): {
        // we check here if the new index will fit in the 2 byte slot
        assert((uint16_t)new_idx == new_idx);
        *(uint16_t *)*vcall->ptr_to_idx = (uint16_t)new_idx;
        VTBLDBG(3, "wrote idx: %hu\n", *(uint16_t *)*vcall->ptr_to_idx);
        break;
      }

      case (1): {
        // we check here if the new index will fit in the 1 byte slot
        assert((uint8_t)new_idx == new_idx);
        *(uint8_t *)*vcall->ptr_to_idx = (uint8_t)new_idx;
        VTBLDBG(3, "wrote idx: %hhu\n", *(uint8_t *)*vcall->ptr_to_idx);
        break;
      }
      }
    } else if (vcall->type == absolute || vcall->type == relative) {
      // for vcall instructions that use addresses, rather than indices,
      // we resolve the subvtable during the disassembly of the instruction
      //
      // I have no idea why this would ever fail...
      assert(vcall->resolved_subvtable);

      // We resolve these instructions to an exact vtable, which might or
      // might not be a variant of some other vtable
      //
      // After the vtable splitting, all subvtables will refer to the main
      // variant on which their layout is based using the parent pointer.
      //
      // The main variant itself has its parent pointer set to NULL
      vtable_info *main_variant = vcall->resolved_subvtable->main_variant
                                      ? vcall->resolved_subvtable->main_variant
                                      : vcall->resolved_subvtable;

      // If this vtable did not get shuffled for some reason (e.g. because it
      // was too small), we just skip the rewriting step
      if (main_variant->shuffled_indices.size() == 0)
        continue;

      unsigned long old_idx_within_subvtable =
          (vcall->old_idx - vcall->idx_offset) / XVT_SIZE;
      // This assertion could fail if the old index is out of the bounds of the
      // subvtable we resolved the vcall to The one case where we've seen this
      // happen is when the vcall call type wasn't marked correctly (i.e. it was
      // pointing to the intended class' parent, which has a smaller vtable than
      // the intended class)
      assert(old_idx_within_subvtable < main_variant->shuffled_indices.size());

      unsigned long shuffled_idx_within_subvtable =
          main_variant->shuffled_indices[old_idx_within_subvtable];
      unsigned long new_idx =
          (vcall->idx_offset + shuffled_idx_within_subvtable * XVT_SIZE);
      unsigned long new_addr = vcall->old_addr - vcall->old_idx + new_idx;

      VTBLDBG(3,
              "rewriting absolute/relative vcall: 0x%016lx - old addr: "
              "0x%016lx - offset: 0x%016lx - new addr: 0x%016lx - old idx: %lu "
              "- new idx: %lu - shuffled idx: %lu\n",
              *vcall->ptr_to_vcall, *vcall->old_addr, vcall->idx_offset,
              new_addr, vcall->old_idx, new_idx, shuffled_idx_within_subvtable);

      // adjust the address if the vcall instruction uses relative addressing
      if (vcall->type == relative)
        new_addr = new_addr - (*(vcall->ptr_to_idx) + vcall->idx_size);

      switch (vcall->idx_size) {
      case (8): {
        *(uint64_t *)*vcall->ptr_to_idx = new_addr;
        VTBLDBG(3, "wrote addr: %016lx\n", *(uint64_t *)*vcall->ptr_to_idx);
        break;
      }

      case (4): {
        // check if the new address will fit in the 4 byte slot
        assert(vcall->type == relative || (uint32_t)new_addr == new_addr);
        *(uint32_t *)*vcall->ptr_to_idx = (uint32_t)new_addr;
        VTBLDBG(3, "wrote addr: %08x\n", *(uint32_t *)*vcall->ptr_to_idx);
        break;
      }
      }
    }
  }
}

/*-----------------------------------------------------------------------------
  vtablerando_randomize_vtables
-----------------------------------------------------------------------------*/
static void vtablerando_randomize_vtables() {
  char *reverse;
  reverse = getenv("MVEE_VTABLE_RANDO_REVERSE");

  for (auto vtable : vtables) {
    if (vtable->info->blacklist)
      continue;

    vtable->shuffled_indices.resize(vtable->vtable_size);
    for (unsigned long i = 0; i < vtable->vtable_size; ++i)
      vtable->shuffled_indices[i] = i;
    std::random_shuffle(vtable->shuffled_indices.begin(),
                        vtable->shuffled_indices.end());

    if (reverse != NULL) {
      std::reverse(vtable->shuffled_indices.begin(),
                   vtable->shuffled_indices.end());
    }

    vtable->original_targets.resize(vtable->vtable_size);
  }

  for (auto vtable : vtables) {
    if (vtable->info->blacklist)
      continue;

    if (vtable->vtable_size <= 1) {
      VTBLDBG(2, "Can't randomize vtable %s because it only has %lu elements\n",
              vtable->info->name.c_str(), vtable->vtable_size);
      continue;
    }

    VTBLDBG(1, "Randomizing vtable %s @ 0x%016lx\n", vtable->info->name.c_str(),
            *vtable->vtable_locations[0]);

    for (unsigned long i = 0; i < vtable->vtable_size; ++i)
      VTBLDBG(5, "shuffled[%lu] = %lu\n", i, vtable->shuffled_indices[i]);

    unsigned long num_variants = vtable->vtable_locations.size();
    for (unsigned long i = 0; i < num_variants; ++i)
      vtable->randomize_variant(i);

    std::fill(vtable->original_targets.begin(), vtable->original_targets.end(),
              0);
  }
}

/*-----------------------------------------------------------------------------
  make_writable
-----------------------------------------------------------------------------*/
static void make_module_readable(module_info *module) {
  // Make all executable sections readable
  Elf64_Ehdr *elf = module->elf;
  Elf64_Phdr *phdr = (Elf64_Phdr *)((unsigned long)elf + elf->e_phoff);

  // disassemble all executable segments
  for (int i = 0; i < elf->e_phnum; ++i) {
    if (phdr[i].p_flags & PF_X) {
      unsigned long base = phdr[i].p_vaddr + *module->module_base_offset;
      unsigned long aligned_segment_addr = base & (~4095);
      unsigned long aligned_segment_size =
          ROUND_UP(base + phdr[i].p_memsz, 4096) - aligned_segment_addr;
      mprotect((void *)aligned_segment_addr, aligned_segment_size,
               PROT_EXEC | PROT_READ);
    }
  }
}

/*-----------------------------------------------------------------------------
  make_writable
-----------------------------------------------------------------------------*/
static void make_writable() {
  // Make all executable sections writable
  for (auto module : modules) {
    Elf64_Ehdr *elf = module->elf;
    Elf64_Phdr *phdr = (Elf64_Phdr *)((unsigned long)elf + elf->e_phoff);

    // disassemble all executable segments
    for (int i = 0; i < elf->e_phnum; ++i) {
      if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
        unsigned long base = phdr[i].p_vaddr + *module->module_base_offset;
        unsigned long aligned_segment_addr = base & (~4095);
        unsigned long aligned_segment_size =
            ROUND_UP(base + phdr[i].p_memsz, 4096) - aligned_segment_addr;
        mprotect((void *)aligned_segment_addr, aligned_segment_size,
                 PROT_EXEC | PROT_READ | PROT_WRITE);
      }
    }
  }
}

/*-----------------------------------------------------------------------------
                restore_prot_flags
-----------------------------------------------------------------------------*/
static void restore_prot_flags() {
  for (auto module : modules) {
    Elf64_Ehdr *elf = module->elf;
    Elf64_Phdr *phdr = (Elf64_Phdr *)((unsigned long)elf + elf->e_phoff);

    for (int i = 0; i < elf->e_phnum; ++i) {
      if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
        int flags = 0;

        if (phdr[i].p_flags & PF_X)
          flags |= PROT_EXEC;
        if (phdr[i].p_flags & PF_R)
          flags |= PROT_READ;
        if (phdr[i].p_flags & PF_W)
          flags |= PROT_WRITE;

        unsigned long base = phdr[i].p_vaddr + *module->module_base_offset;
        unsigned long aligned_segment_addr = base & (~4095);
        unsigned long aligned_segment_size =
            ROUND_UP(base + phdr[i].p_memsz, 4096) - aligned_segment_addr;
        mprotect((void *)aligned_segment_addr, aligned_segment_size, flags);
      }
    }
  }
}

/*-----------------------------------------------------------------------------
  vtablerando_register_module

  This may run before global variables are initialized, which clears them. We
  need to be careful not to modify global C++ objects here.
-----------------------------------------------------------------------------*/
extern "C" __attribute__((visibility("default"))) void
vtablerando_register_module(unsigned long image_base,
                            unsigned long textrap_start,
                            unsigned long textrap_end) {
  module_info *module = new module_info;
  module->elf = (Elf64_Ehdr *)image_base;
  module->module_textrap_start = textrap_start;
  module->module_textrap_end = textrap_end;
  // PIE support!
  Elf64_Ehdr *elf = module->elf;
  module->module_base_offset = elf->e_type == ET_DYN ? (unsigned long)elf : 0;
  module->next = modules_head;
  modules_head = module;
}

static void read_modules() {
  module_info *cur = modules_head;
  while (cur) {
    make_module_readable(cur);
    parse_textrap(cur);
    modules.push_back(cur);
    cur = cur->next;
  }
}

/*-----------------------------------------------------------------------------
  cleanup - we free all allocated memory here and make sure that no pointers
  leak
-----------------------------------------------------------------------------*/
static void cleanup() {
  delete root;
  for (auto info : classes)
    delete info.second;
  for (auto vcall : tmp_vcalls)
    delete vcall;
  for (auto module : modules)
    delete module;
  classes.clear();
  name_to_class.clear();
  class_traversal_list.clear();
  vtables.clear();
  subtable_map.clear();
  tmp_vcalls.clear();

#if VTABLERANDO_DEBUG > 0
  fflush(stdout);
#endif
}

static void vtablerando_add_missing_table(unsigned long rtti, const char *name,
                                          unsigned long vtable_loc) {
  auto class_ = classes.find(rtti);
  if (class_ != classes.end()) {
    vtable_info *main_table = class_->second->vtables[0];
    vtable_info *new_vtable = new vtable_info;
    new_vtable->dummy_table = false;
    new_vtable->info = main_table->info;
    new_vtable->offset = 0;
    new_vtable->vtable_locations.push_back((code_ptr)vtable_loc);
    new_vtable->base_names = main_table->base_names;
    new_vtable->vtable_size = main_table->vtable_size;
    new_vtable->original_vtable_size = main_table->original_vtable_size;
    main_table->add_variant(new_vtable);
    fprintf(stderr, "added missing vtable for class %s => %016lx\n", name,
            vtable_loc);
  }
}

/*-----------------------------------------------------------------------------
  init - this constructor should run last, after all modules have registered
-----------------------------------------------------------------------------*/
extern "C" __attribute__((visibility("default"))) void vtablerando_randomize() {
  init_debugging();
  init_rng();
  read_modules();

  // Vtable magic
  vtablerando_build_class_graph();
  vtablerando_build_class_traversal_list_recurse(root);
  vtablerando_split_tables();

  // And the actual rewriting
  make_writable();
  vtablerando_randomize_vtables();
  vtablerando_rewrite_vcalls();
  restore_prot_flags();

  cleanup();
}

extern "C" __attribute__((visibility("default"))) void __llvm_boobytrap() {
  fprintf(stderr, "BOOM HEADSHOT - I AM PID: %d\n", getpid());
  pause();
  //  exit(-1);
}

// Local Variables:
// indent-tabs-mode: t
// End:
