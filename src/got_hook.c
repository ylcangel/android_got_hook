/*
 *
 * Android Got Hook
 *
 * Author : sp00f
 * Version 0.1
 */
 
#include "GotHook.h"
 
#include <fcntl.h>
#include <dlfcn.h>
#include <string.h>
#include <types.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/exec_elf.h>
#include <elf.h>
 
#ifndef MAYBE_MAP_FLAG
#define MAYBE_MAP_FLAG(x,from,to)    (((x) & (from)) ? (to) : 0)
#endif
#ifndef PFLAGS_TO_PROT
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))
#endif
#ifndef PAGE_START
#define PAGE_START(x)  ((x) & PAGE_MASK)
#endif
#ifndef PAGE_OFFSET
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)
#endif
#ifndef PAGE_END
#define PAGE_END(x)    PAGE_START((x) + (PAGE_SIZE-1))
#endif
#ifndef SOINFO_NAME_LEN
#define SOINFO_NAME_LEN 128
#endif
 
#ifndef MAYBE_MAP_FLAG
#define MAYBE_MAP_FLAG(x,from,to)    (((x) & (from)) ? (to) : 0)
#endif
#ifndef PFLAGS_TO_PROT
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))
#endif
#ifndef PAGE_START
#define PAGE_START(x)  ((x) & PAGE_MASK)
#endif
#ifndef PAGE_OFFSET
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)
#endif
#ifndef PAGE_END
#define PAGE_END(x)    PAGE_START((x) + (PAGE_SIZE-1))
#endif
#ifndef SOINFO_NAME_LEN
#define SOINFO_NAME_LEN 128
#endif
 
// mips64 interprets Elf64_Rel structures' r_info field differently.
// bionic (like other C libraries) has macros that assume regular ELF files,
// but the dynamic linker needs to be able to load mips64 ELF files.
#if defined(__mips__) && defined(__LP64__)
#undef ELF64_R_SYM
#undef ELF64_R_TYPE
#undef ELF64_R_INFO
#define ELF64_R_SYM(info)   (((info) >> 0) & 0xffffffff)
#define ELF64_R_SSYM(info)  (((info) >> 32) & 0xff)
#define ELF64_R_TYPE3(info) (((info) >> 40) & 0xff)
#define ELF64_R_TYPE2(info) (((info) >> 48) & 0xff)
#define ELF64_R_TYPE(info)  (((info) >> 56) & 0xff)
#endif
 
#if defined(__aarch64__) || defined(__x86_64__)
#define USE_RELA 1
#endif
 
typedef void (*linker_function_t)();
 
struct link_map {
  Elf_Addr l_addr;
  char* l_name;
  Elf_Dyn* l_ld;
  struct link_map* l_next;
  struct link_map* l_prev;
};
 
struct soinfo {
  char name[SOINFO_NAME_LEN];
  const Elf_Phdr* phdr;
  size_t phnum;
  Elf_Addr entry;
  Elf_Addr base;//vmap addr
  size_t size;//mmap load size
 
#ifndef __LP64__
  uint32_t unused1;  // DO NOT USE, maintained for compatibility.
#endif
 
  Elf_Dyn* dynamic;
 
#ifndef __LP64__
  uint32_t unused2; // DO NOT USE, maintained for compatibility
  uint32_t unused3; // DO NOT USE, maintained for compatibility
#endif
 
  soinfo* next;
  unsigned flags;
 
  const char* strtab;
  Elf_Sym* symtab;
 
  size_t nbucket;
  size_t nchain;
  unsigned* bucket;
  unsigned* chain;
 
  #if defined(__mips__) || !defined(__LP64__)
  // This is only used by mips and mips64, but needs to be here for
  // all 32-bit architectures to preserve binary compatibility.
  Elf_Addr** plt_got;
#endif
 
#if defined(USE_RELA)
  Elf_RelA* plt_rela;
  size_t plt_rela_count;
 
  Elf_RelA* rela;
  size_t rela_count;
#else
  Elf_Rel* plt_rel;
  size_t plt_rel_count;
 
  Elf_Rel* rel;
  size_t rel_count;
#endif
 
  linker_function_t* preinit_array;
  size_t preinit_array_count;
 
  linker_function_t* init_array;
  size_t init_array_count;
  linker_function_t* fini_array;
  size_t fini_array_count;
 
  linker_function_t init_func;
  linker_function_t fini_func;
 
#if defined(__arm__)
  // ARM EABI section used for stack unwinding.
  unsigned* ARM_exidx;
  size_t ARM_exidx_count;
#elif defined(__mips__)
  unsigned mips_symtabno;
  unsigned mips_local_gotno;
  unsigned mips_gotsym;
#endif
 
  size_t ref_count;
  struct link_map link_map_;
 
  bool constructors_called;
 
  // When you read a virtual address from the ELF file, add this
  // value to get the corresponding address in the process' address space.
  Elf_Addr load_bias;
 
#if !defined(__LP64__)
  bool has_text_relocations;
#endif
  bool has_DT_SYMBOLIC;
};
 
 
//exe maps 
// b6ec9000-b6f0c000 r-xp 00000000 b3:1c 627097     /data/local/tmp/jiagu_art
// b6f0c000-b6f0f000 r--p 00042000 b3:1c 627097     /data/local/tmp/jiagu_art
// b6f0f000-b6f12000 rw-p 00045000 b3:1c 627097     /data/local/tmp/jiagu_art
//
// exe select soinfo last phdr start and end,it is different between exe phdr Segments and  so phdr Segments
//
//
//@1 maybe has bug, i think process's so maps, always like :
//74ede000-74eea000 r-xp 00000000 b3:1c 48880      /data/app-lib/com.example.test-2/libnotify.so
//74eea000-74eeb000 r--p 0000b000 b3:1c 48880      /data/app-lib/com.example.test-2/libnotify.so
//74eeb000-74eec000 rw-p 0000c000 b3:1c 48880      /data/app-lib/com.example.test-2/libnotify.so
//so i select the mid segment (because plt got in this segment),and change it's prot
//at last i change it back
//i also found, when i change it back , the flags = PF_X not PF_R ,why ??
//@2 before this method , i change last two segments ,but when i changed it , the last two segments was combined into one segments
//so i use @1
//you can implement yours' ,like reading process's maps, and parsing the maps, than change the corrent segments.
//this is a test ,so i implement like @1 , some code was siphoned from linker code.
static int changeSegmentsProt(const Elf_Phdr* phdr_table, int phdr_count,
						Elf_Addr load_bias, int extra_prot_flags, bool isSo) {
 
	Elf_Addr prot_start = 0;
	Elf_Addr prot_mid = 0;
	Elf_Addr prot_end = 0;
 
	int flags = 0;
 
	if(isSo) {
		for (size_t i = 0; i < phdr_count; ++i) {
			const Elf_Phdr* phdr = &phdr_table[i];
			// Segment addresses in memory.
			Elf_Addr seg_start = phdr->p_vaddr + load_bias;
			Elf_Addr seg_end = seg_start + phdr->p_memsz;
 
			Elf_Addr seg_page_start = PAGE_START(seg_start);
			Elf_Addr seg_page_end = PAGE_END(seg_end);
 
			ALOGI("[*] seg_page_start = 0x%.16x , seg_page_end = 0x%.16x, length = 0x%.16x",
					seg_page_start, seg_page_end, (seg_page_end - seg_page_start));
 
			if (seg_page_start > prot_start)
				prot_start = seg_page_start;
 
			if (seg_page_end > prot_end)
				prot_end = seg_page_end;
 
			if (seg_page_end > prot_start && seg_page_end < prot_end) {
				prot_mid = seg_page_end;
				flags = PFLAGS_TO_PROT(phdr->p_flags);
			}
		}
	} else {
			const Elf_Phdr* phdr = &phdr_table[phdr_count-1];
			// Segment addresses in memory.
			Elf_Addr seg_start = phdr->p_vaddr + load_bias;
			Elf_Addr seg_end = seg_start + phdr->p_memsz;
 
			Elf_Addr seg_page_start = PAGE_START(seg_start);
			Elf_Addr seg_page_end = PAGE_END(seg_end);
 
			ALOGI("[*] seg_page_start = 0x%.16x , seg_page_end = 0x%.16x, length = 0x%.16x",
					seg_page_start, seg_page_end, (seg_page_end - seg_page_start));
					
		prot_start = seg_page_start;
		prot_mid   = seg_page_end;
		flags = PFLAGS_TO_PROT(phdr->p_flags);
	}
 
	ALOGI("[+] prot_start = 0x%.16x , prot_mid = 0x%.16x, prot_end = 0x%.16x",
			prot_start, prot_mid, prot_end);
 
	int ret = -1;
 
	if(extra_prot_flags == 0) {
		ret = mprotect((void*) prot_start, (prot_mid - prot_start),
				PROT_READ | extra_prot_flags);
	} else {
		ret = mprotect((void*) prot_start, (prot_mid - prot_start),
					flags | extra_prot_flags );
	}
 
	if (ret < 0) {
		return ret;
	}
 
	return 0;
}
 
#if defined(USE_RELA)
static bool isHookedSym(struct soinfo* si, const char* symbol, void* oldAddr,
		void* newAddr, Elf_Sym* symtab, const char* strtab,
		Elf_RelA* rel, size_t count) {
#else
static bool isHookedSym(struct soinfo* si, const char* symbol, void* oldAddr,
		void* newAddr, Elf_Sym* symtab, const char* strtab,
		Elf_Rel* rel, size_t count) {
#endif
		ALOGI("[*] into isHookedSym");
		bool isFoundSym = false;
			
		for (size_t idx = 0; idx < count; ++idx, ++rel) {
			unsigned type = ELF_R_TYPE(rel->r_info);
			unsigned sym = ELF_R_SYM(rel->r_info);
			Elf_Addr reloc = static_cast<Elf_Addr>(rel->r_offset + si->base);
 
			char* sym_name = NULL;
 
			if (type == 0) { // R_*_NONE
				continue;
			}
 
			if (sym != 0) {
				sym_name = (char *) (strtab + symtab[sym].st_name);
				// ALOGI("[*] sym_name = %s", sym_name);
 
				Elf_Addr addr = *reinterpret_cast<Elf_Addr*>(reloc);
 
				const char* symname = const_cast<const char*>(sym_name);
 
				if (strcmp(symname, symbol) == 0) {
					*reinterpret_cast<Elf_Addr*>(reloc) = (Elf_Addr) newAddr;
					*reinterpret_cast<Elf_Addr*>(oldAddr) = addr;
 
					ALOGI("[+] sys name = %s , got old addr = 0x%.16x, ret orgi_addr = 0x%.16x, new addr = 0x%.16x",
							sym_name, addr, *reinterpret_cast<Elf_Addr*>(oldAddr),
							*reinterpret_cast<Elf_Addr*>(reloc));
					
					isFoundSym = true;
					break;
				}
			}
		}
		ALOGI("[*] return isHookedSym");
		return isFoundSym;
}
 
bool gotHook(const char* libName, const char* symbol, void* oldAddr,
		void* newAddr) {
	
	bool isFoundSym = false;
	bool isSo		= true;
	void* handle = dlopen(libName, RTLD_NOW);
	if (!handle) {
		ALOGI("[-] can't find so library %s", libName);
		isSo = false;
	}
	
	if(!isSo) {
		handle = dlopen("libdl.so", RTLD_NOW);
		struct soinfo* oi = (struct soinfo*) handle;
		
		while(oi) {
			ALOGI("[*] so name=%s", oi->name);
			if(strstr(oi->name, libName)) {
				handle = (void*) oi;
				break;
			}
			oi = oi->next;
		}
		if(!handle)
			ALOGI("[-] can't find bin %s", libName);
	}
 
	struct soinfo* si = (struct soinfo*) handle;
 
	Elf_Sym* symtab = si->symtab;
	const char* strtab = si->strtab;
#if defined(USE_RELA)
	Elf_RelA* rel = si->plt_rela;
	size_t count = si->plt_rela_count;
#else
	Elf_Rel* rel = si->plt_rel;
	size_t count = si->plt_rel_count;
#endif
	
	if(count == 0) {
#if defined(USE_RELA)
		rel = si->rela;
		count = si->rela_count;
#else
		rel = si->rel;
		count = si->rel_count;
#endif
	}
	
	ALOGI("[*] import sym count = %d", count);
	
	if(count == 0) 
		return false;
	
	ALOGI("[*] module base = %.16x, module size = %.16x" , si->base, si->size);
	
	if (changeSegmentsProt(si->phdr, si->phnum, si->base, PROT_WRITE, isSo) < 0) {
		ALOGI("[-] can't unprotect loadable segments for \"%s\": %s",
			si->name, strerror(errno));
		return false;
	}
 
	isFoundSym = isHookedSym(si, symbol, oldAddr,
						newAddr, symtab, strtab,
						rel,count) ;
 
	if(!isFoundSym) {
#if defined(USE_RELA)
		rel = si->rela;
		count = si->rela_count;
#else
		rel = si->rel;
		count = si->rel_count;
#endif
		
		isFoundSym = isHookedSym(si, symbol, oldAddr,
					newAddr, symtab, strtab,
					rel,count) ;
	}
	
	if (changeSegmentsProt(si->phdr, si->phnum, si->base, 0, isSo) < 0) {
		ALOGI("[-] can't unprotect loadable segments for \"%s\": %s",
				si->name, strerror(errno));
		return false;
	}
	
	if(isSo)
		dlclose(handle);
		
	ALOGI("[*] hook %s ,sym %s is %d", libName, symbol, isFoundSym);
	return isFoundSym;
}