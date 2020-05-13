/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LEGO_PROCESSOR_SCRATCHPAD_H_
#define _LEGO_PROCESSOR_SCRATCHPAD_H_

#include <lego/list.h>
#include <lego/const.h>
#include <lego/bitops.h>
#include <lego/jiffies.h>
#include <lego/spinlock.h>
#include <processor/pcache_types.h>
#include <processor/pcache_stat.h>
#include <processor/pcache_debug.h>
#include <uapi/processor/pcache.h>


extern u64 sp_registered_start;
extern u64 sp_registered_size;

extern u64 sp_llc_size;

extern u64 sp_nr_cachelines;
extern u64 sp_nr_cachesets;

extern u64 sp_nr_pages_cacheline;
extern u64 sp_nr_pages_metadata;



extern u64 sp_phys_start_cacheline;
extern u64 sp_phys_start_metadata;
extern u64 sp_virt_start_cacheline;

extern u64 sp_cacheline_mask;
extern u64 sp_set_mask;
extern u64 sp_tag_mask;

extern u64 sp_nr_bits_cacheline ;
extern u64 sp_nr_bits_tag;

extern struct pcache_meta *sp_meta_map;
extern struct pcache_set *sp_set_map;

#define sp_for_each_way(pcm,nr)                 \
    for (nr = 0, pcm = sp_meta_map; nr<sp_nr_cachelines;    \
    nr++, pcm++)

#define sp_for_each_set(pset,nr)        \
    for (nr=0,pset = sp_set_map; nr<sp_nr_cachesets;     \
        nr++, pset++)


static inline void *sp_meta_to_pa(struct pcache_meta *pcm){
    unsigned long offset = pcm-sp_meta_map;

    BUG_ON(offset >= sp_nr_cachelines);
    return (void *)(sp_phys_start_cacheline + offset * PCACHE_LINE_SIZE);
}

static inline unsigned long sp_meta_to_pfn(struct pcache_meta *pcm)
{
	return ((unsigned long)sp_meta_to_pa(pcm)) >> PCACHE_LINE_SIZE_SHIFT;
}

static inline pte_t sp_mk_pte(struct pcache_meta *pcm, pgprot_t pgprot)
{
	return pfn_pte(sp_meta_to_pfn(pcm), pgprot);
}

static inline void* sp_meta_to_kva(struct pcache_meta *pcm){
    unsigned long offset = pcm - sp_meta_map;

    BUG_ON(offset >= sp_nr_cachelines);
    return (void *) (sp_virt_start_cacheline + offset * PCACHE_LINE_SIZE);

}

static inline unsigned long __sp_meta_index(struct pcache_meta *pcm)
{
	unsigned long offset;

	offset = pcm - sp_meta_map;
	BUG_ON(offset >= sp_nr_cachelines);
	return offset;
}


static inline bool pa_is_sp(unsigned long address)
{
    if (likely(address >= sp_phys_start_cacheline &&
            address < sp_phys_start_metadata))
            return true;
    return false;
}

static inline struct pcache_meta*
pa_to_sp_meta(unsigned long address)
{
    if (pa_is_sp(address)){
        unsigned long offset;

        offset = (address & PCACHE_LINE_MASK) - sp_phys_start_cacheline;
        offset = offset >> PCACHE_LINE_SIZE_SHIFT;
        return sp_meta_map + offset;
    }
    return NULL;
}
static inline __must_check struct pcache_meta *
pte_to_sp_meta(pte_t pte)
{
    unsigned long pa = pte_val(pte) & PTE_PFN_MASK;
    return pa_to_sp_meta(pa);
}

static inline struct pcache_set *
sp_meta_to_pcache_set(struct pcache_meta *pcm)
{
	unsigned long offset;

	offset = pcm - pcache_meta_map;
	if(offset >= nr_cachelines){
        return sp_set_map;
    }
    else{
        return NULL:
    }
	
}


unsigned long virt_sp_alloc(unsigned long len);
int build_new_mapping(struct mm_struct *mm, unsigned long new_virt_address, 
            unsigned long old_virt_address, unsigned long len);
int remove_mapping(struct mm_struct *mm, unsigned old_addr, unsigned long new_addr, unsigned long len);
unsigned long virt_sp_free(unsigned long addr, unsigned long len);
int sp_add_rmap(struct pcache_meta *pcm, pte_t *page_table, unsigned long address,
            struct mm_struct *owner_mm, struct task_struct *owner_process,
            enum rmap_caller caller);
void __init alloc_sp_rmap_map(void);
void __init sp_print_info(void);

#endif