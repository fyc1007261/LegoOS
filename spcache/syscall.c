
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


asmlinkage long sys_sp_pin(unsigned long addr,unsigned long len) {
#ifdef CONFIG_COMP_PROCESSOR
    /* alloc the virtual memory from m component side */
    pr_info("Start: sys_sp_pin");
    unsigned long offset=offset_in_page(addr);
    unsigned long va = virt_sp_alloc(offset,len);
    if (va<=0){
        return -1;
    }
    pr_info("sys_sp_pin: va return");
    int ret;
    pr_info("Continue1: sys_sp_pin    %#llx\n", va);
    ret = build_new_mapping(current->mm, va, addr, len);
    if (ret<0){
        pr_info("Fail: sys_sp_pin");
        return -1;
    }
    pr_info("Continue2: sys_sp_pin");
    va = va+offset;
    return va;
#else
    return -1;
#endif
}

asmlinkage long sys_sp_unpin(unsigned long old_addr, unsigned long new_addr, unsigned long len){
#ifdef CONFIG_COMP_PROCESSOR
    int ret;
    ret = remove_mapping(current->mm,old_addr, new_addr, len);
    if(ret<0){
        return -1;
    }
    ret = virt_sp_free(new_addr,len);
    if(ret<0){
        return -1;
    }
    return 0;
#else
    return -1;
#endif
}
