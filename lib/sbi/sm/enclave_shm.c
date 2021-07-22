#include "sbi/sbi_types.h"
#include "sm/enclave.h"
#include "sm/enclave-shm.h"
#include "sbi/riscv_locks.h"
#include "sm/enclave.h"
#include "sm/sm.h"
#include "sbi/riscv_locks.h"
#include "sm/platform/pt_area/platform_thread.h"
#include "sm/enclave_mm.h"
#include "sm/enclave_vm.h"
#include "sbi/sbi_console.h"
#include "sbi/sbi_string.h"

// static spinlock_t global_shm_lock;
static struct link_mem_t* global_shm_metadata_head;
static struct link_mem_t* global_shm_metadata_tail;
static struct link_mem_t* global_shm_metadata_current;
static unsigned long global_current_index;
extern int check_enclave_authentication();
extern int swap_from_host_to_enclave(uintptr_t *host_regs,
				     struct enclave_t *enclave);
extern int swap_from_enclave_to_host(uintptr_t *regs,
				     struct enclave_t *enclave);
static int shm_init = 0;

int enclave_shm_init()
{
	//TODO: init_mem_link allocates too much memory for shared memory meta data, may optimize later.
	global_shm_metadata_head = init_mem_link(DEFAULT_SHM_META_REGION_SIZE, sizeof(struct sbi_shm_infop));
	if(!global_shm_metadata_head)
	{
		sbi_bug("M mode: enclave shared memory module init failed, maybe lacking of memory\n");
		return -1;
	}
	global_shm_metadata_tail = global_shm_metadata_head;
	global_shm_metadata_current = global_shm_metadata_head;
	global_current_index = 0;
	return 0;
}



static struct sbi_shm_infop * get_shm_info(unsigned long shm_key)
{
	struct link_mem_t *cur = NULL;
	int found = 0;
	unsigned long i = 0;
	struct sbi_shm_infop *shm = NULL;
	for(cur = global_shm_metadata_head; cur != NULL; cur = cur->next_link_mem)
	{
		for(i = 0; i < cur->slab_num; i++)
		{
			shm = (struct sbi_shm_infop *)(cur->addr) + i;
			if(shm->state == SHM_META_INVALID)
			{
				break;
			}
			if(shm->shm_key == shm_key)
			{
				found = 1;
				break;
			}
		}
		if(shm->state == SHM_META_INVALID || found)
		{
			break;
		}
	}
	return found ? shm : NULL;
}

static struct sbi_shm_metadata* get_free_shm_meta(struct sbi_shm_infop* shm)
{
	struct sbi_shm_metadata * meta = NULL;
	if(shm->last_free_meta_index >= RISCV_PGSIZE/ sizeof(struct sbi_shm_metadata))
	{
		return NULL;
	}
	meta = (struct sbi_shm_metadata *)(shm->pma.paddr) + shm->last_free_meta_index;
	shm->last_free_meta_index += 1;
	return meta;
}

static void free_shm_meta(struct sbi_shm_infop* shm, struct sbi_shm_metadata* meta)
{
	shm->last_free_meta_index--;
	sbi_memcpy(meta, (struct sbi_shm_metadata*)shm->pma.paddr + shm->last_free_meta_index, sizeof(struct sbi_shm_metadata));
}

static void free_shm_info(struct sbi_shm_infop* shm)
{
	struct link_mem_t* pos = NULL;
	struct sbi_shm_infop* src;
	global_current_index --;
	if(global_current_index == 0)
	{
		if(global_shm_metadata_head == global_shm_metadata_current)
		{
			shm->state = SHM_META_INVALID;
			return;
		}
		else
		{
			pos = global_shm_metadata_head;
			while(pos->next_link_mem != global_shm_metadata_current)
			{
				pos = pos->next_link_mem;
			}
			global_shm_metadata_current = pos;
			global_current_index = pos->slab_num - 1;
		}
	}
	src = (struct sbi_shm_infop*)(pos->addr) + global_current_index;
	sbi_memcpy(shm, src, sizeof(struct sbi_shm_infop));
	src->state = SHM_META_INVALID;
	return;
}

static struct sbi_shm_metadata* get_shm_meta(struct sbi_shm_infop* shm, int eid)
{
	struct sbi_shm_metadata * meta = (struct sbi_shm_metadata *)shm->pma.paddr;
	int i = 0;
	struct sbi_shm_metadata * retval = NULL;
	for(i = 0; i < RISCV_PGSIZE/ sizeof(struct sbi_shm_metadata); ++i)
	{
		if(meta->eid == -1)
		{
			break;
		}
		if(meta->eid == eid)
		{
			retval = meta;
		}
	}
	return retval;
}
/**
 * \brief Encalve get shared memory need to ocall to acquire some physical memory from the host.
 * \param regs The enclave register context.
 * \param shm_key The global unique key to identify the shared memory when create/attatch/detach.
 * \param size  The size of the shared memory.
 * \param flags Shared Memory attributes flags, which are not used at this time, for future usage.
*/
uintptr_t enclave_shmget(uintptr_t *regs, uintptr_t shm_key, uintptr_t size,
			 uintptr_t flags)
{
	//TODO: flags parameter is not used at this time.
	uintptr_t retval  = 0;
	int eid			  = get_curr_enclave_id();
	struct enclave_t *enclave = NULL;
	struct sbi_shm_infop *shm;
	struct link_mem_t *next;
	if (check_in_enclave_world() < 0) 
	{
		return -1UL;
	}
	acquire_enclave_metadata_lock();
	enclave = __get_enclave(eid);
	if (!enclave || check_enclave_authentication(enclave) != 0 ||enclave->state != RUNNING) 
	{
		retval = -1UL;
		release_enclave_metadata_lock();
		return retval;
	}
	if(!shm_init)
	{
		if(enclave_shm_init() != 0)
		{
		   release_enclave_metadata_lock();
           return -1UL;
		}
		shm_init = 1;
	}
	if (size < RISCV_PGSIZE || size & (RISCV_PGSIZE - 1)) // the size request must align to page size.
	{
		release_enclave_metadata_lock();
		return -1UL;
	}
	shm = get_shm_info(shm_key);
	if(shm != NULL) // already has an associated shared memory object.
	{
		release_enclave_metadata_lock();
		return -1UL;
	}
	if(global_current_index == global_shm_metadata_current->slab_num)
	{
		next = global_shm_metadata_current->next_link_mem;
		if(next == NULL)
		{
			next = add_link_mem(&global_shm_metadata_tail);
			if(next == NULL)
			{
				sbi_bug("M mode: enclave_shmget, add_link_mem failed\n");
				release_enclave_metadata_lock();
				return -1UL;
			}
		}
		global_current_index = 0;
		global_shm_metadata_current = next;
	}
	shm = (struct sbi_shm_infop*)(global_shm_metadata_current->addr) + global_current_index;
	global_current_index += 1;
	shm->state = SHM_META_VALID;
	shm->last_free_meta_index = 0;
	shm->need_destroy = 0;
	shm->pma.paddr = 0;
	shm->shm_key = shm_key;
	shm->shm_refcount = 0;
	shm->shm_flags	  = flags;
	enclave->ocalling_shm_key = shm_key;
	copy_dword_to_host((uintptr_t *)enclave->ocall_func_id, OCALL_SHM_GET);
	copy_dword_to_host((uintptr_t *)enclave->ocall_arg1, RISCV_PGSIZE + size);
	swap_from_enclave_to_host(regs, enclave);
	enclave->state = OCALLING;
	retval	       = ENCLAVE_OCALL;
	release_enclave_metadata_lock();
	return retval;
}

//shmget_after_resume with enclave_metadata_lock hold
uintptr_t shmget_after_resume(struct enclave_t *enclave, uintptr_t paddr,
			      uintptr_t size)
{
	uintptr_t retval = 0;
	if (check_and_set_secure_memory(paddr, size) < 0) 
	{
		sbi_bug("M mode: shmget_after_resume: check_and_set_secure_memory(0x%lx, 0x%lx) failed\n", paddr, size);
		retval = -1UL;
		return retval;
	}
	struct sbi_shm_metadata *meta = (struct sbi_shm_metadata *)(paddr);
	struct sbi_shm_infop *shm     = NULL;
	unsigned long i		      = 0;
	//init shared memory meta for enclaves
	for (i = 0; i < RISCV_PGSIZE / sizeof(struct sbi_shm_metadata); ++i) 
	{
		meta->eid = -1;
		meta++;
	}
	meta = (struct sbi_shm_metadata *)(paddr);
	shm = get_shm_info(enclave->ocalling_shm_key);
	if(shm == NULL)
	{
		sbi_bug("M mode: shm_get_after resume cannot find metadata\n");
		return -1UL;
	}
	shm->pma.paddr	   = paddr;
	shm->pma.size	   = size;
	shm->pma.pm_next   = NULL;
	shm->last_free_meta_index = 1;
	meta->eid	   = enclave->eid;
	meta->vma.va_start = ENCLAVE_DEFAULT_MMAP_BASE - (size - RISCV_PGSIZE);
	meta->vma.va_end   = meta->vma.va_start + size - RISCV_PGSIZE;
	meta->vma.vm_next  = NULL;
	meta->vma.pma	   = &(shm->pma);
	if (insert_vma(&(enclave->mmap_vma), &(meta->vma),ENCLAVE_DEFAULT_MMAP_BASE) < 0) 
	{
		meta->vma.va_end   = enclave->mmap_vma->va_start;
		meta->vma.va_start = meta->vma.va_end - (size - RISCV_PGSIZE);
		meta->vma.vm_next  = enclave->mmap_vma;
		enclave->mmap_vma  = &(meta->vma);
	}
	insert_pma(&(enclave->pma_list), &(shm->pma));
	mmap((uintptr_t *)(enclave->root_page_table), &(enclave->free_pages),
	     meta->vma.va_start, paddr + RISCV_PGSIZE, size - RISCV_PGSIZE);
	shm->shm_refcount += 1;
	retval = meta->vma.va_start;
	return retval;
}

uintptr_t sm_shm_attatch(uintptr_t *regs, uintptr_t shm_key)
{
	uintptr_t retval = 0;
	int eid = get_curr_enclave_id();
	struct enclave_t * enclave = NULL;
	struct sbi_shm_infop *shm = NULL;
	struct sbi_shm_metadata* meta = NULL;
	unsigned long size;
	if(check_in_enclave_world() < 0)
	{
		return 0;
	}
	if(!shm_init)
	{
		return 0;
	}
	acquire_enclave_metadata_lock();
	shm = get_shm_info(shm_key);
	if(shm == NULL || shm->need_destroy || shm->pma.paddr == 0)
	{
		release_enclave_metadata_lock();
		return 0;
	}
	meta = get_shm_meta(shm, eid);
	if(meta != NULL) //already attached
	{
		release_enclave_metadata_lock();
		return meta->vma.va_start;
	}
	meta = get_free_shm_meta(shm);
	if(meta == NULL)
	{
		release_enclave_metadata_lock(); // exceed the limit number of shared enclaves.
		return 0;
	}
	size = shm->pma.size;
	shm->shm_refcount ++;
	meta->eid = eid;
	meta->vma.va_start = ENCLAVE_DEFAULT_MMAP_BASE - (size - RISCV_PGSIZE);
	meta->vma.va_end = meta->vma.va_start + size - RISCV_PGSIZE;
	meta->vma.vm_next = NULL;
	meta->vma.pma = &(shm->pma);
	enclave = __get_enclave(eid);
	if(insert_vma(&(enclave->mmap_vma), &(meta->vma), ENCLAVE_DEFAULT_MMAP_BASE) < 0)
	{
		meta->vma.va_end = enclave->mmap_vma->va_start;
		meta->vma.va_start = meta->vma.va_end - (size - RISCV_PGSIZE);
		meta->vma.vm_next = enclave->mmap_vma;
		enclave->mmap_vma = &(meta->vma);
	}
	mmap((uintptr_t *)(enclave->root_page_table), &(enclave->free_pages), meta->vma.va_start,
			shm->pma.paddr + RISCV_PGSIZE, size - RISCV_PGSIZE);
	retval = meta->vma.va_start;
	release_enclave_metadata_lock();
	return retval;
}

uintptr_t enclave_shmdetach(uintptr_t *regs, uintptr_t shm_key)
{
	int eid = get_curr_enclave_id();
	struct enclave_t * enclave = NULL;
	struct sbi_shm_infop *shm = NULL;
	struct sbi_shm_metadata * meta = NULL;
	struct vm_area_struct *vma = NULL;
	struct pm_area_struct *pma = NULL;
	if(check_in_enclave_world() < 0)
	{
		return -1UL;
	}
	if(!shm_init)
	{
		return -1UL;
	}
	acquire_enclave_metadata_lock();
	shm = get_shm_info(shm_key);
	if(shm == NULL || shm->pma.paddr == 0)
	{
		release_enclave_metadata_lock();
		return -1UL;
	}
	meta = (struct sbi_shm_metadata *)(shm->pma.paddr);
	meta = get_shm_meta(shm, eid);
	if(meta == NULL)
	{
		release_enclave_metadata_lock();
		return -1UL;
	}
	enclave = __get_enclave(eid);
	vma = &(meta->vma);
	pma = vma->pma;
	delete_vma(&(enclave->mmap_vma), vma);
	delete_pma(&(enclave->pma_list), pma);
	vma->vm_next = NULL;
	pma->pm_next = NULL;
	unmap((uintptr_t*)(enclave->root_page_table), vma->va_start, vma->va_end - vma->va_start);
	shm->shm_refcount -= 1;
	free_shm_meta(shm, meta);
	if(shm->shm_refcount == 0 && shm->need_destroy)
	{
		free_shm_info(shm);
		copy_dword_to_host((uintptr_t *)enclave->ocall_func_id, OCALL_UNMAP);
		copy_dword_to_host((uintptr_t *)enclave->ocall_arg0, pma->paddr);
		copy_dword_to_host((uintptr_t*)enclave->ocall_arg1, pma->size);
		swap_from_enclave_to_host(regs, enclave);
		enclave->state = OCALLING;
		free_enclave_memory(pma);
		release_enclave_metadata_lock();
		return ENCLAVE_OCALL;
	}
	release_enclave_metadata_lock();
	return 0;
}

uintptr_t enclave_shmdestroy(uintptr_t *regs, uintptr_t shm_key)
{
	struct sbi_shm_infop *shm = NULL;
	struct enclave_t *enclave = NULL;
	int eid = get_curr_enclave_id();
	if(check_in_enclave_world() < 0)
	{
		return -1UL;
	}
	if(!shm_init)
	{
		return -1UL;
	}
	acquire_enclave_metadata_lock();
	shm = get_shm_info(shm_key);
	if(shm == NULL)
	{
		release_enclave_metadata_lock();
		return -1UL;
	}
	shm->need_destroy = 1;
	enclave = __get_enclave(eid);
	if(shm->shm_refcount == 0)
	{
		free_shm_info(shm);
		copy_dword_to_host((uintptr_t *)enclave->ocall_func_id, OCALL_UNMAP);
		copy_dword_to_host((uintptr_t *)enclave->ocall_arg0, shm->pma.paddr);
		copy_dword_to_host((uintptr_t*)enclave->ocall_arg1, shm->pma.size);
		swap_from_enclave_to_host(regs, enclave);
		enclave->state = OCALLING;
		free_enclave_memory(&(shm->pma));
		release_enclave_metadata_lock();
		return ENCLAVE_OCALL;
	}
	release_enclave_metadata_lock();
	return 0;
}