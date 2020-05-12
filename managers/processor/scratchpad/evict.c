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


unsigned long virt_sp_free(unsigned long addr, unsigned long len)
{
    struct p2m_sp_free_struct payload;
    struct p2m_sp_free_reply_struct reply;
    long retlen;

    if (offset_in_page(addr) || addr > TASK_SIZE || len > TASK_SIZE - addr)
		return -EINVAL;
    len = PAGE_ALIGN(len);
    if(!len){
        return -EINVAL;
    }
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





int flush_one_page(struct mm_struct *mm, 
            unsigned long new_virt_address, unsigned long old_virt_address)
{
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
    
    old_pgd = pgd_offset(mm, old_virt_address);
	old_pud = pud_offset(old_pgd, old_virt_address);
	if (old_pud){
        old_pmd = pmd_offset(old_pud, old_virt_address);
	    if (old_pmd){
            old_pte = pte_offset(old_pmd,old_virt_address);
        }

    }
    /* data are in pcache: local*/
    if (likely(pte_present(*old_pte))){
        old_pcm = pte_to_pcache_meta(*old_pte);
        new_pcm = pte_to_sp_meta(*new_pte);
        old_kva = pcache_meta_to_kva(old_pcm);
        new_kva = sp_meta_to_kva(new_pcm);
        memcpy(old_kva, new_kva, PAGE_SIZE);
    }
    /* data are in remote memory */
    else{
        ret=sp_flush_one(new_pcm);
        if(ret<0){
            return -1;
        }
    }
    ret=sp_try_to_unmap(new_pcm);
    if(ret<0){
        return -1;
    }
}
int remove_mapping(struct mm_struct *mm, unsigned old_addr, unsigned long new_addr, unsigned long len)
{
    
    len = PAGE_ALIGN(len);
    if (!len){
        return -1;
    }
    struct pcache_meta *pcm;
    unsigned long nr_pcm_free = len / PAGE_SIZE;
    int ret;
    int i;
    for (i=0;i<nr_pcm_free;i++){
        ret = flush_one_page(mm,new_addr+i*PAGE_SIZE,old_addr+i*PAGE_SIZE);
        if (ret<0){
            return -1;
        }
    }



}
int sp_try_to_unmap(struct pcache_meta *pcm)
{
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

static int sp_try_to_unmap_one(struct pcache_meta *pcm,
                    struct pcache_ramp *rmap, void *arg)
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

