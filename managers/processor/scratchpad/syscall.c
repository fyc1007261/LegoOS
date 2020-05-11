
#include <lego/mm.h>
#include <lego/syscalls.h>

asmlinkage long sys_sp_pin(unsigned addr,unsigned long len) {
    /* alloc the virtual memory from m component side */
    unsigned long va = virt_sp_alloc(len);
    if (va<=0){
        return -1;
    }
    int ret;
    ret = build_new_mapping(current->mm, va, addr, len);
    if (ret<0){
        return -1;
    }
    return va;
}

asmlinkage long sys_sp_unpin(unsigned old_addr, unsigned long new_addr, unsigned long len){
    int ret;
    ret = remove_mapping(current->mm,old_addr, new_addr, len);
    if(ret<0){
        return -1;
    }
    ret = virt_sp_free(new_addr,len)
    if(ret<0){
        return -1;
    }
    return 0;

}
