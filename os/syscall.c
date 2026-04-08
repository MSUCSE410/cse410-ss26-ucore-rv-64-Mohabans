#include "syscall.h"
#include "console.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "vm.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d str = %x, len = %d", fd, va, len);
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

uint64 sys_read(int fd, uint64 va, uint64 len)
{
	debugf("sys_read fd = %d str = %x, len = %d", fd, va, len);
	if (fd != STDIN)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	for (int i = 0; i < len; ++i) {
		int c = consgetc();
		str[i] = c;
	}
	copyout(p->pagetable, va, str, len);
	return len;
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

uint64 sys_gettimeofday(uint64 val, int _tz)
{
	struct proc *p = curr_proc();

	uint64 phys = useraddr(p->pagetable, (uint64)val); // Map virtual to physical address
	if (phys == 0) {
		return -1; // Bad address
	}

	TimeVal *new_val = (TimeVal *)phys; // Cast physical address as a time value

	uint64 cycle = get_cycle();
	new_val->sec = cycle / CPU_FREQ;
	new_val->usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	return 0;
}

uint64 sys_getpid()
{
	return curr_proc()->pid;
}

uint64 sys_getppid()
{
	struct proc *p = curr_proc();
	return p->parent == NULL ? IDLE_PID : p->parent->pid;
}

uint64 sys_clone()
{
	debugf("fork!\n");
	return fork();
}

uint64 sys_exec(uint64 va)
{
	struct proc *p = curr_proc();
	char name[200];
	copyinstr(p->pagetable, name, va, 200);
	debugf("sys_exec %s\n", name);
	return exec(name);
}

uint64 sys_wait(int pid, uint64 va)
{
	struct proc *p = curr_proc();
	int *code = (int *)useraddr(p->pagetable, va);
	return wait(pid, code);
}

uint64 sys_spawn(uint64 va)
{
	struct proc *p = curr_proc();
    struct proc *np = NULL; // np is a new proc
    char name[200];

    if (copyinstr(p->pagetable, name, va, 200) < 0) {
        return -1;
    }

    int id = get_id_by_name(name);
    if (id < 0)
        return -1; // Invalid filename

    np = allocproc();
    if (np == 0)
        return -1; // Full proc pool

    np->parent = p;

    if (loader(id, np) < 0) {
        np->state = UNUSED;
        return -1;
    }

    np->state = RUNNABLE;
    // add_task(np);

    return np->pid;
}

uint64 sys_set_priority(long long prio){
    if (prio < 2 || prio > ISIZE_MAX) { // prio must be within [2, isize_max]
		return -1;
	}
	struct proc *p = curr_proc();
    p->prio = prio;
    p->pass = BIG_STRIDE / prio; // Makes time allocated to each process proportional to prio
    return prio;
}

int sys_task_info(struct TaskInfo *info) {
	struct proc *p = curr_proc();

	uint64 phys = useraddr(p->pagetable, (uint64)info); // Map virtual to physical address
	if (phys == 0) {
		return -1; // Bad address
	}

	struct TaskInfo * new_info = (struct TaskInfo *)phys; // Cast physical address as a TaskInfo ptr
	new_info->status = p->task_info.status;

	// Copy syscall counts from current process to new task info using virtual addresses
	memmove(new_info->syscall_times, p->task_info.syscall_times, sizeof(p->task_info.syscall_times));

	uint64 curr_time = get_cycle()*1000/CPU_FREQ;
	new_info->time = curr_time - p->task_info.time;
	return 0;
}

uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd) {
	struct proc *p = curr_proc();

	// check for page-aligned start
	if (start % PGSIZE != 0) {
		return -1;
	}

	if (len == 0) {
		return -1; // No length of mapped byte
	}

	if (len > 1024 * 1024 * 1024) {
		return -1; // Length is larger than 1 GB
	}

	if (port & ~0x7) {
		return -1; // Other bits of port must be 0 (like 1101)
	}

	if ((port & 0x7) == 0) {
		return -1; // Cannot R, W, or X the memory
	}

	// Convert port into PTE permission bits. I.e. 010 = PTE_W
	int perm = 0;
	if (port & 0x1) {
		perm |= PTE_R;
	}
	if (port & 0x2) {
		perm |= PTE_W;
	}
	if (port & 0x4) {
		perm |= PTE_X;
	}
	perm |= PTE_U; // user

	uint64 a = PGROUNDUP(len);
	while (a > 0) {
		void *pa = kalloc(); // pa is a ptr to physical memory page
		if (pa == 0) {
			return -1;
		}
		if (mappages(p->pagetable, start, PGSIZE, (uint64) pa, perm) != 0) {
			return -1; // walkaddr couldn't allocate a page (page possibly already exists)
		}

		a -= PGSIZE;
		start += PGSIZE;
	}

	return 0;
}

uint64 sys_munmap(uint64 start, uint64 len) {
	struct proc *p = curr_proc();

	// check for page-aligned start
	if (start % PGSIZE != 0) {
		return -1;
	}

	if (len == 0) {
		return -1;
	}

	int num_pages = PGROUNDUP(len) / PGSIZE;

	uint64 b = start;
	for (; b < start + num_pages * PGSIZE; b += PGSIZE) {
		if (useraddr(p->pagetable, b) == 0) {
			return -1; // Can't unmap an already unmapped page
		}
		uvmunmap(p->pagetable, b, 1, 0); // Remove 1 pg from va
	}

	return 0;
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

	curr_proc()->task_info.syscall_times[id]++;
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_read:
		ret = sys_read(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
	case SYS_getpid:
		ret = sys_getpid();
		break;
	case SYS_getppid:
		ret = sys_getppid();
		break;
	case SYS_clone: // SYS_fork
		ret = sys_clone();
		break;
	case SYS_execve:
		ret = sys_exec(args[0]);
		break;
	case SYS_wait4:
		ret = sys_wait(args[0], args[1]);
		break;
	case SYS_spawn:
		ret = sys_spawn(args[0]);
		break;
	case SYS_task_info:
		ret = sys_task_info((struct TaskInfo *)args[0]);
		break;
	case SYS_mmap:
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		ret = sys_munmap(args[0], args[1]);
		break;
	case SYS_setpriority:
		ret = sys_set_priority((long long)args[0]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
