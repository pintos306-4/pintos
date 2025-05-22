#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	/* 인터럽트 서비스 루틴은 syscall_entry가 유저 스택을 커널 모드 스택으로 전환하기 전까지는  
   어떤 인터럽트도 처리하지 않아야 한다. 따라서 FLAG_FL을 마스킹(mask)했다. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {

	// The order of the arguments -> %rdi, %rsi, %rdx, %r10, %r8, %r9
	// return value is f->rax
	// TODO: Your implementation goes here.
	printf ("system call!\n");
	
	//rax를 통해 시스템콜 번호를 받아온다. 
	int syscall_number = f->R.rax;

	switch (syscall_number)
	{
	case SYS_HALT :
		power_off();
		NOT_REACHED();
		break;
	
	case SYS_EXIT:
		int status = f->R.rdi;
		sys_exit(status);
		NOT_REACHED();
		break;
	
	case SYS_WRITE:
		NOT_REACHED();
		break;

	case SYS_CREATE:
		char *name = f->R.rdi;
		off_t size = f->R.rsi;

		
		filesys_create (name,size);		
		break;
	}



	thread_exit ();
}

sys_exit(){
	printf("thread exit");
	thread_exit();
}