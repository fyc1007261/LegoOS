
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
    
    if (unlikely(newaddr < 0)) {
		reply->ret = newaddr;
		return;
	}
    reply->ret = 0;
    reply->ret_sp = (unsigned long)newaddr;
    pr_info("newaddr is: %#llx\n", reply->ret_sp);
    replicate_vma(tsk,REPLICATE_SP,reply->ret_sp,len,0,0);

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
