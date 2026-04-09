#include "loader.h"
#include "defs.h"
#include "file.h"
#include "trap.h"

static int app_num;
static uint64 *app_info_ptr;
extern char INIT_PROC[];
char names[MAX_APP_NUM][MAX_STR_LEN];

int get_id_by_name(char *name)
{
	for (int i = 0; i < app_num; ++i) {
		if (strncmp(name, names[i], 100) == 0)
			return i;
	}
	warnf("Cannot find such app %s", name);
	return -1;
}

int loader(int app_id, struct proc *p)
{
	return bin_loader((struct inode *)app_info_ptr[app_id], p);
}

int bin_loader(struct inode *ip, struct proc *p)
{
	ivalid(ip);
	void *page;
	uint64 length = ip->size;
	uint64 va_start = BASE_ADDRESS;
	uint64 va_end = PGROUNDUP(BASE_ADDRESS + length);
	for (uint64 va = va_start, off = 0; va < va_end;
	     va += PGSIZE, off += PAGE_SIZE) {
		page = kalloc();
		if (page == 0) {
			panic("...");
		}
		readi(ip, 0, (uint64)page, off, PAGE_SIZE);
		if (off + PAGE_SIZE > length) {
			memset(page + (length - off), 0,
			       PAGE_SIZE - (length - off));
		}
		if (mappages(p->pagetable, va, PGSIZE, (uint64)page,
			     PTE_U | PTE_R | PTE_W | PTE_X) != 0)
			panic("...");
	}
	// map ustack
	p->ustack = va_end + PAGE_SIZE;
	for (uint64 va = p->ustack; va < p->ustack + USTACK_SIZE;
	     va += PGSIZE) {
		page = kalloc();
		if (page == 0) {
			panic("...");
		}
		memset(page, 0, PGSIZE);
		if (mappages(p->pagetable, va, PGSIZE, (uint64)page,
			     PTE_U | PTE_R | PTE_W) != 0)
			panic("...");
	}
	p->trapframe->sp = p->ustack + USTACK_SIZE;
	p->trapframe->epc = va_start;
	p->max_page = PGROUNDUP(p->ustack + USTACK_SIZE - 1) / PAGE_SIZE;
	p->state = RUNNABLE;

	p->task_info.status = UnInit;
	memset(p->task_info.syscall_times, 0, sizeof(p->task_info.syscall_times));
	p->task_info.time = 0;

	p->stride = 0;
	p->prio = 16;
	p->pass = BIG_STRIDE / p->prio;

	return 0;
}

// load all apps and init the corresponding `proc` structure.
int load_init_app()
{
	struct inode *ip;
	struct proc *p = allocproc();
	init_stdio(p);
	if ((ip = namei(INIT_PROC)) == 0) {
		errorf("invalid init proc name\n");
		return -1;
	}
	debugf("load init app %s", INIT_PROC);
	bin_loader(ip, p);
	iput(ip);
	char *argv[2];
	argv[0] = INIT_PROC;
	argv[1] = NULL;
	p->trapframe->a0 = push_argv(p, argv);
	add_task(p);
	return 0;
}