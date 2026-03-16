#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "proc.h"

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

uint64 sys_gettimeofday(TimeVal *val, int _tz) // TODO: implement sys_gettimeofday in (VA to PA)
{
	// YOUR CODE
	struct proc* p = curr_proc();

	val = (TimeVal *)useraddr(p->pagetable, (uint64)val);

	val->sec = 0;
	val->usec = 0;

	/* The code in `ch3` will leads to memory bugs*/

	uint64 cycle = get_cycle();
	val->sec = cycle / CPU_FREQ;
	val->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	return 0;
}

// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)

uint64 sys_mmap(uint64 start, uint64 length, int port, int flags, int fd)
{
	struct proc *p = curr_proc();

	// Upper limit is 1GiB (1024 * 1024 * 1024 bytes)
    if (length > 1073741824) { 
        return -1; // Return -1 for error
    }

	if(length == 0){
		return 0;
	}

	if(start % PGSIZE != 0){
		return -1;
	}

    // Validate Port Permissions
    // port 8~0x7==0, other bits of port must be 0
    if ((port & ~0x7) != 0) {
        return -1; // Return -1 for error
    }
    // port & 0x7 != 0, unreadable non-writable non-executable memory is meaningless [cite: 49]
    if ((port & 0x7) == 0) {
        return -1; // Return -1 for error
    }
	// Translate 'port' bits to your OS's PTE flags
    // Bit 0: readable, Bit 1: writable, Bit 2: executable
    int pte_flags = PTE_U; // User mode flag
    if (port & 1) pte_flags |= PTE_R;
    if (port & 2) pte_flags |= PTE_W;
    if (port & 4) pte_flags |= PTE_X;

	uint64 aligned_length = PGROUNDDOWN(start);

	for(uint64 i = start; i<start+length; i+=PGSIZE){
		if(walkaddr(p->pagetable, i) != 0){
			return -1; // if the page is not mapped, return -1
		}
	}

	while (aligned_length < length)
	{
		void* pa = kalloc();
		if ((uint64) pa == 0)
		{
			uvmunmap(p->pagetable, start, (aligned_length - start) / PGSIZE, 1); // unmap the pages that have been mapped, free the physical memory
			return -1;
		}

		memset(pa, 0, PGSIZE); // zero the page

		if (mappages(p->pagetable, start, PGSIZE, (uint64) pa, pte_flags) != 0)
		{
			kfree(pa); // free the allocated page
			uvmunmap(p->pagetable, start, (aligned_length - start) / PGSIZE, 1); // unmap the pages that have been mapped, free the physical
			return -1;
		}
		aligned_length += PGSIZE;
		start += PGSIZE;
	}	

	// Return 0 for success
    return 0;
}

int sys_munmap(uint64 start, uint64 len)
{
	struct proc *p = curr_proc();
	pagetable_t table = p->pagetable; // pagetable
	
	// if start isn't aligned with a page start
	if (start % PGSIZE != 0)
	{
		return -1;
	}
	
	int num_pages = PGROUNDUP(len) / PGSIZE;

	for (uint64 page = start; page < start + num_pages * PGSIZE; page += PGSIZE)
	{	
		if(useraddr(table, page) == 0)
		{
			return -1; // if the page is not mapped, return -1
		}
		uvmunmap(table, page, 1, 0); // unmap the page, do not free the physical memory
	}

	return 0;
}
/*
* LAB1: you may need to define sys_task_info here
*/
uint64 sys_task_info(TaskInfo *info)
{

	struct proc *p = curr_proc();

	info->status = Running;
	for(int i = 0; i < MAX_SYSCALL_NUM; ++i){
		info->syscall_times[i] = p->syscall_times[i];
	}
	uint64 current_time = get_cycle() * 1000 / CPU_FREQ;
	info->time = (int)(current_time - p->start_time);
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
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/

	curr_proc()->syscall_times[id]++;

	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
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
	/*
	* LAB1: you may need to add SYS_taskinfo case here
	*/
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
