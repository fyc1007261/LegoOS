
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
    return (void *)(sp_phys_start_cacheline + offset * PCACHE_LINES_SIZE);
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

static inline __must_check struct pcache_meta *
pte_to_sp_meta(pte_t pte)
{
    unsigned long pa = pte_val(pte) & PTE_PFN_MASK;
    return pa_to_sp_meta(pa);
}

static inline struct pcache_meta*
pa_to_sp_meta(unsigned long address)
{
    if (likely(pa_is_sp(address))){
        unsigned long offset;

        offset = (address & PCACHE_LINE_MASK) - sp_phys_start_cacheline;
        offset = offset >> PCACHE_LINE_SIZE_SHIFT;
        return sp_meta_map + offset;
    }
    return NULL;
}

static inline bool pa_is_sp(unsigned long address)
{
    if (likely(address >= sp_phys_start_cacheline &&
            address < sp_phys_start_metadata))
            return true;
    return false;
}