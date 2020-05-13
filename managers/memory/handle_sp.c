
#include <lego/mm.h>
#include <lego/rwsem.h>
#include <lego/slab.h>
#include <lego/rbtree.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/netmacro.h>
#include <lego/comp_memory.h>
#include <lego/fit_ibapi.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/vm-pgtable.h>
#include <memory/file_ops.h>
#include <memory/distvm.h>
#include <memory/replica.h>
#include <memory/thread_pool.h>



unsigned long do_sp_alloc(struct lego_task_struct *p, unsigned long len){
    if (down_write_killable(&p->mm->mmap_sem))
		return -EINTR;
    struct lego_mm_struct *mm = p->mm;
    struct vm_area_struct *vma, *prev;
    struct rb_node **rb_link, *rb_parent;
    unsigned long flags;
    unsigned long newaddr;
    pgoff_t pgoff;
    len = PAGE_ALIGN(len);
    if (!len){
        return -1;
    }
    flags = VM_READ | VM_WRITE | mm->def_flags;

    /* sp alloc */
    newaddr = get_unmapped_area(p,NULL,NULL,len,0,MAP_ANONYMOUS,1);
    if (offset_in_page(newaddr))
		return newaddr;
    while (find_vma_links(mm, newaddr, newaddr + len, &prev, &rb_link,
			      &rb_parent)) {
		if (do_munmap(mm, newaddr, len))
			return -ENOMEM;
	}
    vma = vma_merge(mm, prev, addr, addr + len, flags,
			NULL, pgoff);
	if (vma)
		goto out;
    vma = kzalloc(sizeof(*vma), GFP_KERNEL);
	if (!vma)
		return -ENOMEM;
    pgoff = newaddr >> PAGE_SHIFT;

	vma->vm_mm = mm;
	vma->vm_start = newaddr;
	vma->vm_end = newaddr + len;
	vma->vm_pgoff = pgoff;
	vma->vm_flags = flags;
	vma->vm_page_prot = vm_get_page_prot(flags);
	vma_link(mm, vma, prev, rb_link, rb_parent);

out:
    mm->total_vm += len >> PAGE_SHIFT;
	mm->data_vm += len >> PAGE_SHIFT;
    up_write(&p->mm->mmap_sem);
	return newaddr;
}
void handle_p2m_sp_alloc(struct p2m_sp_alloc_struct *payload,
		       struct common_header *hdr, struct thpool_buffer *tb){
    
    u32 nid = hdr->src_nid;
    u32 pid = payload->pid;
    unsigned long len = payload->len;
    struct lego_task_struct *tsk;
    struct lego_mm_struct *mm;
    struct p2m_sp_alloc_reply_struct *reply;

    s64 newaddr;

    reply = thpool_buffer_tx(tb);
    tb_set_tx_size(tb, sizeof(*reply));

    tsk = find_lego_task_by_pid(nid, pid);
	if (unlikely(!tsk)) {
		reply->ret_sp = RET_ESRCH;
		return;
	}


    mm = tsk->mm;
    
    
    newaddr = do_sp_alloc(tsk,len);
    tb_set_tx_size(tb, sizeof(long));
    if (unlikely(newaddr < 0)) {
		reply->ret = newaddr;
		return;
	}
    reply->ret = 0;
    reply->ret_sp = newaddr;
    replicate_vma(tsk,REPLICATE_SP,reply->ret_sp,len,0,0);

}
/* very similar to do_munmap() function; but we don't need to remove page table*/
int do_sp_free(struct lego_mm_struct *mm, unsigned long start, size_t len)
{

    unsigned long end;
	struct vm_area_struct *vma, *prev, *last;

    if ((offset_in_page(start)) || start > TASK_SIZE || len > TASK_SIZE-start)
		return -EINVAL;

	len = PAGE_ALIGN(len);
	if (len == 0)
		return -EINVAL;
    vma = find_vma(mm, start);
    if(!vma){
        return 0;
    }
    prev = vma->vm_prev;
    end = start + len;
    if (vma->vm_start >=end){
        return 0;
    }
    if (start > vma->vm_start) {
		int error;

		if (end < vma->vm_end && mm->map_count >= sysctl_max_map_count)
			return -ENOMEM;

		error = __split_vma(mm, vma, start, 0);
		if (error)
			return error;
		prev = vma;

	}
    last = find_vma(mm, end);
	if (last && end > last->vm_start) {
		int error = __split_vma(mm, last, end, 1);
		if (error)
			return error;
	}
	vma = prev ? prev->vm_next : mm->mmap;
    detach_vmas_to_be_unmapped(mm, vma, prev, end);
    remove_vma_list(mm, vma);

    return 0;







}

void handle_p2m_sp_free(struct p2m_sp_free_struct *payload,
		       struct common_header *hdr, struct thpool_buffer *tb)
{
    u32 nid = hdr->src_nid;
    u32 pid = payload->pid;
    unsigned long len = payload->len;
    unsigned long addr = payload->addr;
    struct lego_task_struct *tsk;
    struct lego_mm_struct *mm;
    struct p2m_sp_free_reply_struct *reply;
               
    reply = thpool_buffer_tx(tb);
	tb_set_tx_size(tb, sizeof(*reply));

	tsk = find_lego_task_by_pid(nid, pid);
	if (unlikely(!tsk)) {
		reply->ret = RET_ESRCH;
		return;
	}


	mm = tsk->mm;
    if (down_write_killable(&tsk->mm->mmap_sem)){
        reply->ret = RET_EINTR;
        return;

    }
    reply->ret = do_sp_free(mm,addr,len);

    up_write(&mm->mmap_sem);
    replicate_vma(tsk,REPLICATE_SP,addr,len,0,0);

               
}
