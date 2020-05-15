#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/ratelimit.h>
#include <lego/memblock.h>
#include <lego/profile_point.h>
#include <processor/pcache.h>
#include <processor/processor.h>
#include <processor/scratchpad.h>

#include <asm/io.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

static struct pcache_rmap *sp_rmap_map;

void __init alloc_sp_rmap_map(void)
{
    size_t size, total;

    size = sizeof(struct pcache_rmap);
    total = size *sp_nr_cachelines;

    sp_rmap_map = memblock_virt_alloc(total, PAGE_SIZE);
    if (!sp_rmap_map){
        panic("sp: unable to allocate rmap map!");
    }
    pr_info("%s(): rmap size: %zu B, total reserved: %zu B, at %p - %p\n",
		__func__, size, total, sp_rmap_map, sp_rmap_map + total);

}

static inline struct pcache_rmap *index_to_sp_rmap(unsigned long index)
{
	return &sp_rmap_map[index];
}

static struct pcache_rmap *alloc_sp_rmap(struct pcache_meta *pcm)
{
    struct pcache_rmap *rmap;
    unsigned long index;

    index = __sp_meta_index(pcm);
    rmap = index_to_sp_rmap(index);

    if (unlikely(TestSetRmapUsed(rmap))) {
		rmap = kzalloc(sizeof(*rmap), GFP_KERNEL);
		if (unlikely(!rmap))
			goto out;

		SetRmapKmalloced(rmap);
	}

    INIT_LIST_HEAD(&rmap->next);

out:
    return rmap;

}

int sp_add_rmap(struct pcache_meta *pcm, pte_t *page_table, unsigned long address,
            struct mm_struct *owner_mm, struct task_struct *owner_process,
            enum rmap_caller caller)
{
    struct pcache_rmap *rmap, *pos;
    int ret;
    pr_info("Start: sp_add_rmap");

    PCACHE_BUG_ON_PCM(PcacheLocked(pcm), pcm);
	PCACHE_BUG_ON(caller >= NR_RMAP_CALLER);

	lock_pcache(pcm);
    rmap = alloc_sp_rmap(pcm);
    if (!rmap) {
		ret = -ENOMEM;
		goto out;
	}

    rmap->page_table = page_table;
    rmap->address = address &PAGE_MASK;
    rmap->owner_mm = owner_mm;
	rmap->caller = caller;

    BUG_ON(!thread_group_leader(owner_process));
	rmap->owner_process = owner_process;

    if (likely(list_empty(&pcm->rmap)))
		goto add;
    /*
    list_for_each_entry(pos, &pcm->rmap, next) {
		BUG_ON(pos->page_table == page_table);
		BUG_ON(pos->owner_mm == owner_mm);
		BUG_ON(pos->owner_process == owner_process);
	}*/
    //pr_info("S1: sp_add_rmap");

 add:
    //pr_info("S2: sp_add_rmap");
    ret = 0;
    list_add(&rmap->next, &pcm->rmap);
    atomic_inc(&pcm->mapcount);

out:
    //pr_info("S3: sp_add_rmap");
    unlock_pcache(pcm);
    return ret;
}