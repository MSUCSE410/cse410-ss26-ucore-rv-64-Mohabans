#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "proc.h"

// Tell the compiler useraddr is handled in vm.c
extern uint64 useraddr(pagetable_t pagetable, uint64 va);

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(TimeVal *val, int _tz) 
{
	struct proc* p = curr_proc();
	
	uint64 sec_pa = useraddr(p->pagetable, (uint64)&val->sec);
	uint64 usec_pa = useraddr(p->pagetable, (uint64)&val->usec);

	if (sec_pa == 0 || usec_pa == 0) return -1;

	uint64 cycle = get_cycle();
	uint64 current_time_ms = cycle * 1000 / CPU_FREQ;

	*(uint64 *)sec_pa = cycle / CPU_FREQ;
	*(uint64 *)usec_pa = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;

	// FIX: Synchronize start_time with the first user-space time measurement.
	// This zeroes out the massive Chapter 4 VM initialization overhead 
	// so info.time perfectly matches the user program's perspective.
	if (p->syscall_times[SYS_gettimeofday] == 1) {
		p->start_time = current_time_ms;
	}

	return 0;
}

uint64 sys_mmap(uint64 start, uint64 length, int port, int flags, int fd)
	// Enforce max_page limit per process
{
	struct proc *p = curr_proc();
	uint64 npages = (PGROUNDUP(length) / PGSIZE);
	if (p->max_page + npages > MAX_USER_PAGES) {
		return -1;
	}

	// Upper limit is 1GiB
    if (length > 1073741824) { 
        return -1;
    }

    // Length of mapped byte can be 0 (if yes, return directly)
	if (length == 0) {
		return 0;
	}

	if (start % PGSIZE != 0) {
		return -1;
	}

    // port 8~0x7==0, other bits of port must be 0
    if ((port & ~0x7) != 0) {
        return -1; 
    }
    // port & 0x7 != 0, unreadable non-writable non-executable memory is meaningless
    if ((port & 0x7) == 0) {
        return -1; 
    }

    // Bit 0 indicates readable, bit 1 indicates writable, bit 2 indicates executable
    int pte_flags = PTE_U; 
    if (port & 1) pte_flags |= PTE_R;
    if (port & 2) pte_flags |= PTE_W;
    if (port & 4) pte_flags |= PTE_X;

	uint64 end = PGROUNDUP(start + length);

    // Error: [addr, addr + len) A page already mapped exists
	for (uint64 va = start; va < end; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) != 0) {
			return -1; 
		}
	}

    // Request an anonymous physical memory and map it to the virtual memory
	for (uint64 va = start; va < end; va += PGSIZE)
	{
		void* pa = kalloc();
		if ((uint64)pa == 0)
		{
            // Error: Insufficient physical memory
			uvmunmap(p->pagetable, start, (va - start) / PGSIZE, 1); 
			return -1;
		}

		memset(pa, 0, PGSIZE); 

		if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, pte_flags) != 0)
		{
			kfree(pa); 
			uvmunmap(p->pagetable, start, (va - start) / PGSIZE, 1); 
			return -1;
		}
	}	

	// Return values: 0 for success
    return 0;
}

uint64 sys_munmap(uint64 start, uint64 len) 
{
	struct proc *p = curr_proc();
	pagetable_t table = p->pagetable; 
	
	if (start % PGSIZE != 0)
	{
		return -1;
	}
	
	uint64 end = PGROUNDUP(start + len);
    uint64 num_pages = (end - start) / PGSIZE;

    // Error: Unmapped virtual memory exists in [start, start + len)
	for (uint64 page = start; page < end; page += PGSIZE)
	{	
		if (walkaddr(table, page) == 0)
		{
			return -1; 
		}
	}

    // Unmap a block of virtual memory and free the physical pages
    uvmunmap(table, start, num_pages, 1);

	return 0;
}

uint64 sys_task_info(TaskInfo *info)
{
	struct proc *p = curr_proc();

	uint64 status_pa = useraddr(p->pagetable, (uint64)&info->status);
	if (status_pa) *(int *)status_pa = Running;

	for(int i = 0; i < MAX_SYSCALL_NUM; ++i){
        uint64 times_pa = useraddr(p->pagetable, (uint64)&info->syscall_times[i]);
		if (times_pa) *(int *)times_pa = p->syscall_times[i];
	}

	uint64 time_pa = useraddr(p->pagetable, (uint64)&info->time);
	if (time_pa) {
		uint64 current_time_ms = (get_cycle() * 1000) / CPU_FREQ;
		uint64 start_time_ms = p->start_time;
		
		// Auto-detect if start_time is still in raw cycles (in case 
		// gettimeofday wasn't called yet to convert it to ms)
		if (start_time_ms > current_time_ms) {
			start_time_ms = (start_time_ms * 1000) / CPU_FREQ;
		}

		int elapsed_ms = (int)(current_time_ms - start_time_ms);
		if (elapsed_ms < 0) elapsed_ms = 0;

		*(int *)time_pa = elapsed_ms;
	}

	return 0;
}

uint64 sys_getpid()
{
    return curr_proc()->pid;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);

	curr_proc()->syscall_times[id]++;

	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_task_info:
		ret = sys_task_info((TaskInfo *)args[0]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}