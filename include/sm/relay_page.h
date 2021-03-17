#ifndef _RELAY_PAGE_H
#define _RELAY_PAGE_H

#include "sm/enclave.h"
#include "sm/enclave_args.h"


uintptr_t asyn_enclave_call(uintptr_t *regs, uintptr_t enclave_name, uintptr_t arg);
uintptr_t split_mem_region(uintptr_t *regs, uintptr_t mem_addr, uintptr_t mem_size, uintptr_t split_addr);
int free_all_relay_page(unsigned long *mm_arg_paddr, unsigned long *mm_arg_size);

#endif /* _RELAY_PAGE_H */
