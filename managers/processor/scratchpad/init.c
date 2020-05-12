
#include <lego/mm.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/memblock.h>

#include <processor/pcache.h>
#include <processor/processor.h>
#include <processor/scratchpad.h>

#include <asm/io.h>

u64 sp_registered_start;
u64 sp_registered_size;

u64 sp_llc_size;

u64 sp_nr_pages_cacheline;
u64 sp_nr_pages_metadata;

u64 sp_nr_cachelines __read_mostly;
u64 sp_nr_cachesets __read_mostly;

atomic_long_t sp_nr_used_cachelines;

u64 sp_phys_start_cacheline __read_mostly;
u64 sp_phys_start_metadata __read_mostly;
u64 sp_virt_start_cacheline __read_mostly;
struct pcache_meta *sp_meta_map __read_mostly;

/* not sure whether we need these; if we have set, there is only one set*/
struct pcache_set *sp_set_map __read_mostly;

u64 sp_cacheline_mask __read_mostly;
u64 sp_set_mask __read_mostly;
u64 sp_tag_mask __read_mostly;

u64 sp_nr_bits_cacheline ;
u64 sp_nr_bits_set;
u64 sp_nr_bits_tag;

u64 sp_way_cache_stride __read_mostly;

static void __init alloc_sp_set_map(void){
    u64 size;

    size = sp_nr_cachesets * sizeof(struct pcache_set);
    sp_set_map = memblock_virt_alloc(size, PAGE_SIZE);
	if (!sp_set_map)
		panic("sp:Unable to allocate sp set array!");
}

static void __init init_sp_meta_map(void){
    struct pcache_meta *pcm;
    int nr;

    sp_for_each_way(pcm,nr){
        pcm->bits = 0;
        INIT_LIST_HEAD(&pcm->free_list);
		INIT_LIST_HEAD(&pcm->rmap);
        pcache_mapcount_reset(pcm);
		pcache_ref_count_set(pcm, 0);    
    }
}

static void __init init_sp_set_map(void){
    struct pcache_set *pset;
    int setidx, j;
     
    sp_for_each_set(pset, setidx){
        INIT_LIST_HEAD(&pset->free_head);
		spin_lock_init(&pset->free_lock);
        for (j = 0; j < NR_PSET_STAT_ITEMS; j++)
			atomic_set(&pset->stat[j], 0);
    }

}
static void __init init_sp_set_free_list(void){
    struct pcache_set *pset;
    struct pcache_meta *pcm;
    int setidx, nr;
    sp_for_each_set(pset,setidx){
        sp_for_each_way(pcm,nr){
            list_add_tail(&pcm->free_list,&pset->free_head);
        }
    }
}

void __init sp_early_init(void){
    u64 sp_nr_cachelines_per_page, sp_nr_units;
    u64 sp_unit_size;
    
    if (sp_registered_start == 0 || sp_registered_size ==0){
        panic("sp: sp not registered, memmap $ needed!");
    }
    sp_nr_cachelines_per_page = PAGE_SIZE / PCACHE_META_SIZE;
    sp_unit_size = sp_nr_cachelines_per_page * PCACHE_LINE_SIZE;
    sp_unit_size +=PAGE_SIZE;

    sp_nr_units =  sp_registered_size / sp_unit_size;
    sp_nr_units = rounddown_pow_of_two(sp_nr_units);

    sp_llc_size = sp_nr_units * sp_unit_size;

    sp_nr_cachelines = sp_nr_units * sp_nr_cachelines_per_page;
    /* fully associative only one set*/
    sp_nr_cachesets = 1;
    

    sp_nr_pages_cacheline = sp_nr_cachelines * PCACHE_LINE_NR_PAGES;
	sp_nr_pages_metadata = sp_nr_units;

    sp_phys_start_cacheline = sp_registered_start;
	sp_phys_start_metadata = sp_phys_start_cacheline + sp_nr_pages_cacheline * PAGE_SIZE;

    sp_nr_bits_cacheline = ilog2(PCACHE_LINE_SIZE);
    sp_nr_bits_tag = 64-sp_nr_bits_cacheline;

    sp_cacheline_mask = (1ULL << sp_nr_bits_cacheline)-1;
    sp_tag_mask = ~((1ULL << (sp_nr_bits_cacheline)) - 1);

    alloc_sp_set_map();
    alloc_sp_rmap_map();
    
}

void __init sp_post_init(void){
    int ret;

#ifdef CONFIG_PROCESSOR_MEMMAP_MEMBLOCK_RESERVED
	sp_virt_start_cacheline = (unsigned long)phys_to_virt(sp_registered_start);
#else
	sp_virt_start_cacheline = (unsigned long)ioremap_cache(sp_registered_start,
							    sp_registered_size);
	if (!sp_virt_start_cacheline)
		panic("Fail to ioremap: [%#llx - %#llx]\n", sp_registered_start,
			sp_registered_start + sp_registered_size);
#endif 


    memset((void *)sp_virt_start_cacheline, 0, sp_registered_size);

    sp_meta_map = (struct pcache_meta *)(sp_virt_start_cacheline+sp_nr_cachelines*PAGE_SIZE);
    
    init_sp_meta_map();  
    init_sp_meta_map();
    init_sp_set_free_list();

    sp_print_info(); 
}

void __init sp_print_info(void){
    pr_info("Processor Scratchpad Configurations:\n");
	pr_info("    PhysStart:         %#llx\n",	sp_registered_start);
	pr_info("    VirtStart:         %#llx\n",	sp_virt_start_cacheline);
	pr_info("    Registered Size:   %#llx\n",	sp_registered_size);
	pr_info("    Actual Used Size:  %#llx\n",	sp_llc_size);
	pr_info("    NR cachelines:     %llu\n",	sp_nr_cachelines);
	pr_info("    Cacheline size:    %lu B\n",	PCACHE_LINE_SIZE);
	pr_info("    Metadata size:     %lu B\n",	PCACHE_META_SIZE);

	pr_info("    NR cacheline bits: %2llu [%2llu - %2llu] %#018llx\n",
		sp_nr_bits_cacheline,
		0ULL,
		sp_nr_bits_cacheline - 1,
		sp_cacheline_mask);
	pr_info("    NR tag bits:       %2llu [%2llu - %2llu] %#018llx\n",
		sp_nr_bits_tag,
		sp_nr_bits_cacheline,
		sp_nr_bits_cacheline+ sp_nr_bits_tag - 1,
		sp_tag_mask);

	pr_info("    NR pages for data: %llu\n",	nr_pages_cacheline);
	pr_info("    NR pages for meta: %llu\n",	nr_pages_metadata);
	pr_info("    Cacheline (pa) range:   [%#18llx - %#18llx]\n",
		sp_phys_start_cacheline, sp_phys_start_metadata - 1);
	pr_info("    Metadata (pa) range:    [%#18llx - %#18llx]\n",
		sp_phys_start_metadata, sp_phys_start_metadata + sp_nr_pages_metadata * PAGE_SIZE - 1);

	pr_info("    Cacheline (va) range:   [%#18llx - %#18lx]\n",
		sp_virt_start_cacheline, (unsigned long)sp_meta_map - 1);
	pr_info("    Metadata (va) range:    [%18p - %#18lx]\n",
		sp_meta_map, (unsigned long)(sp_meta_map + sp_nr_cachelines) - 1);
	

	pr_info("    Memmap $ semantic:       %s\n",
		IS_ENABLED(CONFIG_PROCESSOR_MEMMAP_MEMBLOCK_RESERVED) ?
		"memblock reserved" : "e820 reserved");
}



int __init sp_range_register(u64 start){
    if (WARN_ON(!start))
		return -EINVAL;

	if (WARN_ON(offset_in_page(start)))
		return -EINVAL;

	if (sp_registered_start || sp_registered_size)
		panic("Sp:Remove extra memmap from kernel parameters!");

	sp_registered_start = start;
	sp_registered_size = 2*(1UL<<30);

	return 0;
}