#include <lego/mm.h>
#include <lego/wait.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/hash.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/jiffies.h>
#include <lego/profile.h>
#include <processor/pcache.h>
#include <processor/processor.h>
#include <processor/scratchpad.h>

#include <asm/io.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>


unsigned long virt_sp_free(unsigned long addr, unsigned long len)
{
    struct p2m_sp_free_struct payload;
    struct p2m_sp_free_reply_struct retbuf;
    long retlen;
    unsigned long offset = offset_in_page(addr);
    unsigned long prev_len = len;
    len = PAGE_ALIGN(len);
    if(!len){
        return -EINVAL;
    }
    if(prev_len+offset>len){
        len=len+PAGE_SIZE;
    }
    addr = addr-offset;
    
    

    if (offset_in_page(addr) || addr > TASK_SIZE || len > TASK_SIZE - addr)
		return -EINVAL;
    
    payload.pid = current->tgid;
    payload.addr = addr;
    payload.len = len;

    /*retlen = net_send_reply_timeout(current_memory_home_node(), P2M_SP_FREE,
			&payload, sizeof(payload), &retbuf, sizeof(retbuf),
			false, DEF_NET_TIMEOUT);*/
    if (unlikely(retlen != sizeof(retbuf))) {
		retbuf.ret = -EIO;
		return retbuf.ret;
	}
    if (likely(retbuf.ret == 0)) {
        return retbuf.ret;
    }
    else{
        pr_err("sp_free() fail: %s\n", ret_to_string(retbuf.ret));
    }

}
static __always_inline pmd_t *
rmap_get_pmd(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, address);
	BUG_ON(!pgd && !pgd_present(*pgd));

	pud = pud_offset(pgd, address);
	BUG_ON(!pud && !pud_present(*pud));

	pmd = pmd_offset(pud, address);
	BUG_ON(!pmd && !pmd_present(*pmd));

	return pmd;
}
#define MIN_GAP	(128*1024*1024UL)
#define MAX_GAP	(TASK_SIZE/6*5)

static unsigned long mmap_base(void)
{
	unsigned long gap = 0; /* TODO: rlimit */

	if (gap < MIN_GAP)
		gap = MIN_GAP;
	else if (gap > MAX_GAP)
		gap = MAX_GAP;

	return PAGE_ALIGN(TASK_SIZE - gap);
}

static __always_inline pte_t *
__rmap_get_pte_locked(struct pcache_meta *pcm, struct pcache_rmap *rmap,
		      spinlock_t **ptlp, void *caller) __acquires(*ptlp)
{
	pte_t *ptep;
	pmd_t *pmd;
	spinlock_t *ptl;
	struct mm_struct *mm = rmap->owner_mm;
	unsigned long address = rmap->address;

	pmd = rmap_get_pmd(mm, address);
	ptep = pte_offset(pmd, address);

	if (unlikely(ptep != rmap->page_table)) {
		report_bad_rmap(pcm, rmap, address, ptep, caller);
		ptep = NULL;
		goto out;
	}

	if (unlikely(pcache_meta_to_pfn(pcm) != pte_pfn(*ptep))) {
		report_bad_rmap(pcm, rmap, address, ptep, caller);
		ptep = NULL;
		goto out;
	}

	ptl = pte_lockptr(mm, pmd);
	spin_lock(ptl);
	*ptlp = ptl;

out:
	return ptep;
}

static __always_inline pte_t *
rmap_get_pte_locked(struct pcache_meta *pcm, struct pcache_rmap *rmap,
		    spinlock_t **ptlp) __acquires(*ptlp)
{
	return __rmap_get_pte_locked(pcm, rmap, ptlp,
				     __builtin_return_address(0));
}

static int pcache_mapcount_is_zero(struct pcache_meta *pcm)
{
	return !pcache_mapcount(pcm);
}

static inline void __pcache_remove_rmap(struct pcache_meta *pcm,
				        struct pcache_rmap *rmap)
{
	list_del(&rmap->next);
	free_pcache_rmap(rmap);

	/*
	 * There is no PTE map to this pcache anymore
	 * Clear the Valid bit
	 */
	if (likely(pcache_mapcount_dec_and_test(pcm)))
		ClearPcacheValid(pcm);
}
static int sp_try_to_unmap_one(struct pcache_meta *pcm,
                    struct pcache_rmap *rmap, void *arg)
{
    int ret = PCACHE_RMAP_AGAIN;
	bool *dirty = arg;
	spinlock_t *ptl = NULL;
	pte_t *pte;
	pte_t pteval;

	PCACHE_BUG_ON_RMAP(RmapReserved(rmap), rmap);
    /* we only unmap the new virt addr */
    if (rmap->address>=mmap_base()-(1UL<<30)*128){
        pte = rmap_get_pte_locked(pcm, rmap, &ptl);
	    if (unlikely(!pte))
		    return ret;
        pteval = ptep_get_and_clear(0, pte);
        if (likely(pte_present(pteval))) {
		
		    if (pte_dirty(pteval))
			    *dirty = true;

		
		    flush_tlb_mm_range(rmap->owner_mm,
				    rmap->address,
				    rmap->address + PAGE_SIZE -1);
	    }
    }

    __pcache_remove_rmap(pcm, rmap);
    if (rmap->address>=mmap_base()-(1UL<<30)*128){
        spin_unlock(ptl);
    }
    return ret;
}



int sp_try_to_unmap(struct pcache_meta *pcm)
{ 
    pr_info("Start: sp_try_to_unmap");
    int ret;
	bool dirty = false;
	struct rmap_walk_control rwc = {
		.rmap_one = sp_try_to_unmap_one,
		.done = pcache_mapcount_is_zero,
		.arg = &dirty,
	};

	PCACHE_BUG_ON_PCM(!PcacheLocked(pcm), pcm);

	ret = rmap_walk(pcm, &rwc);
	if (!pcache_mapcount(pcm))
		ret = PCACHE_RMAP_SUCCEED;
	return ret;
}



int flush_one_page(struct mm_struct *mm, 
            unsigned long new_virt_address, unsigned long old_virt_address)
{
    pr_info("Start: flush_one_page");
    pgd_t *new_pgd;
	pud_t *new_pud;
	pmd_t *new_pmd;
	pte_t *new_pte;

    pgd_t *old_pgd;
	pud_t *old_pud;
	pmd_t *old_pmd;
	pte_t *old_pte;

    struct pcache_meta *old_pcm;
    struct pcache_meta *new_pcm;

    int ret;
    void* old_kva;
    void* new_kva;

    new_pgd = pgd_offset(mm, new_virt_address);
    new_pud = pud_offset(new_pgd,new_virt_address);
    if (!new_pud)
        return VM_FAULT_OOM;
    new_pmd = pmd_offset(new_pud,new_virt_address);
    if (!new_pmd)
        return VM_FAULT_OOM;
    new_pte = pte_offset(new_pmd,new_virt_address);
    if (!new_pte)
        return VM_FAULT_OOM;
    pr_info("Continue1: flush_one_page");
    
    old_pgd = pgd_offset(mm, old_virt_address);
	old_pud = pud_offset(old_pgd, old_virt_address);
	if (old_pud){
        old_pmd = pmd_offset(old_pud, old_virt_address);
	    if (old_pmd){
            old_pte = pte_offset(old_pmd,old_virt_address);
        }

    }
    pr_info("Continue2: flush_one_page");
    /* data are in pcache: local*/
    if (likely(pte_present(*old_pte))){
        pr_info("Continue3: flush_one_page");
        old_pcm = pte_to_pcache_meta(*old_pte);
        new_pcm = pte_to_sp_meta(*new_pte);
        old_kva = pcache_meta_to_kva(old_pcm);
        new_kva = sp_meta_to_kva(new_pcm);
        memcpy(old_kva, new_kva, PAGE_SIZE);
    }
    /* data are in remote memory */
    else{
        pr_info("Continue4: flush_one_page");
        ret=sp_flush_one(new_pcm);
        if(ret<0){
            return -1;
        }
    }
    pr_info("Continue5: flush_one_page");
    ret=sp_try_to_unmap(new_pcm);
    if(ret<0){
        return -1;
    }
}
int remove_mapping(struct mm_struct *mm, unsigned old_addr, unsigned long new_addr, unsigned long len)
{
    pr_info("Start: remove_mapping");
    unsigned long offset = offset_in_page(new_addr);
    unsigned long prev_len = len;
    len = PAGE_ALIGN(len);
    if (!len){
        return -1;
    }
    if(prev_len+offset>len){
        len = len+PAGE_SIZE;
    }
    struct pcache_meta *pcm;
    unsigned long nr_pcm_free = len / PAGE_SIZE;
    int ret;
    int i;
    for (i=0;i<nr_pcm_free;i++){
        pr_info("Continue1: remove_mapping");
        ret = flush_one_page(mm,new_addr+i*PAGE_SIZE,old_addr+i*PAGE_SIZE);
        if (ret<0){
            return -1;
        }
        pr_info("Continue2: remove_mapping");
    }



}
