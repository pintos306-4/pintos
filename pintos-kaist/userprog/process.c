#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */

 /* 이 함수는 file_name을 인자로 받아서
→ 그것을 실행할 새 스레드를 만들고
→ 그 스레드의 TID(thread id)를 반환하는 함수*/
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;							//실행 파일 이름을 복사해둘 공간
	tid_t tid;								//새로 생성한 스레드의 식별자

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	/*실행 파일 이름(file_name)을 복사하기 위해 페이지 단위 메모리를 할당
	이유: load() 함수에서 파일 이름을 파싱하는 동안 race condition이 생길 수 있기 때문
	즉, 원본 문자열을 다른 곳에서 수정할 수 있으므로 복사본을 만들어줌
	strlcpy()로 문자열 복사*/
	fn_copy = palloc_get_page (0);											//0으로 초기화된 페이지를 받고, 그 위에 파일의 경로를 복사한다. 
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	char *save_ptr;
	file_name = strtok_r(file_name," ",&save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);			//위의 fn_copy의 정보를 바탕으로 initd함수를 가지는 쓰레드를 생성한다. 
	if (tid == TID_ERROR)													// 에러 발생시 할당 받은 페이지를 해제한다. 
		palloc_free_page (fn_copy);		

	return tid;																//tid 반환
}

/* A thread function that launches first user process. */
// 유저 프로그램을 실제로 실행시키는 진짜 핵심 함수
static void
initd (void *f_name) {														//process_init을 실행시킨 뒤 exec를 한다. 
#ifdef VM																	
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();														// 유저 프로세스를 실행하기 위한 커널 쪽 준비를 마치는 함수

	// 인자로 받은 f_name을 실행함
	if (process_exec (f_name) < 0)											// exec에 실패할 경우 패닉
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* tid는 단순히 쓰레드의 id일 뿐이고
   실제로 해당 쓰레드의 데이터(예 : 세마포어, 스택 프레임 등)에 접근하려면
   그 쓰레드의 구조체 포인터가 필요하다. 
   그래서 get_child_process()를 통해 자식 쓰레드의 구조체를 찾는 과정*/
struct thread *get_child_process(int pid){
	/* 자식 리스트에 접근하여 프로세스 디스크립터 검색 */
	struct thread *curr = thread_current();
	struct list *child_list = &curr->child_list;
	for (struct list_elem *e = list_begin(child_list);e != list_end(child_list); e = list_next(e)){
		struct thread *t  = list_entry(e, struct thread, child_elem);
		/* 해당 pid가 존재하면 프로세스 디스크립터 반환 */
		if (t->tid == pid){
			return t;
		}
	}
	/* 리스트에 존재하지 않으면 NULL리턴 */
	return NULL;
	
}


/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {			// 현재 프로세스를 'name'이라는 이름으로 복제하는 함수 (새 프로세스의 스레드의 id를 반환함)
	/*  이 구조체를 동적으로 할당하고,
		parent_if와 thread_current()을 넣고,
		그 포인터를 thread_create()의 aux로 넘겨줍니다.*/	
	struct thread *curr = thread_current();

	// if_ 복사하기
	memcpy(&curr->parent_if,if_,sizeof(struct intr_frame));

	/* 현재 쓰레드를 새로운 쓰레드로 복제한다. */
	tid_t child_pid = thread_create(name,PRI_DEFAULT,__do_fork,curr);
	if(child_pid == TID_ERROR){
		return TID_ERROR;
	}
	/* 자식이 로드될 때까지 대기하기 위해서 방금 생성한 자식 쓰레드를 찾는다. */
	struct thread *child = get_child_process(child_pid);

	/* 부모는 세마를 통해 대기함 */
	sema_down(&child->fork_sema);	// 이를 통해 부모가 죽는 경우를 예방

	if (child->exit_status == TID_ERROR)
	{
		return TID_ERROR;
	}

	return child_pid;

	/* Clone current thread to new thread.*/
	return thread_create (name,
			PRI_DEFAULT, __do_fork, thread_current ());
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {						// pml4_for_each에 전달하여 부모의 주소공간을 복제
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;
	
	// 가상주소 복제
		
	/* 1. TODO: 부모 페이지가 커널 페이지라면 즉시 반환하세요. */
	if (is_kernel_vaddr(va)) return true;	// 커널 페이지면 이 페이지는 건너뛰고 다음 PTE도 복제해도 됨 

	/* 2. 부모의 페이지 맵 레벨4(PML4)에서 VA에 해당하는 페이지를 찾아옵니다. */
	parent_page = pml4_get_page (parent->pml4, va);
	if(parent_page == NULL){	
	 	return false;		
	}

	/* 3. TODO: 자식용 PAL_USER 페이지를 새로 할당하고, 그 결과를 NEWPAGE에 저장하세요. */
	newpage = palloc_get_page(PAL_USER|PAL_ZERO);
	if(newpage == NULL){
		return false;
	}

	/* 4. TODO: 부모의 페이지 내용을 새 페이지로 복제하고,
		  TODO: 부모 페이지가 쓰기 가능한지 확인하여 WRITABLE 값을 설정하세요. */
	memcpy(newpage,parent_page,PGSIZE);	// 첫 번째 인자 : 데이터를 복사해 넣을 대상 주소, 두 번째 인자 : 데이터를 가져올 원본 주소, 세 번째 인자 : 복사할 바이트 수  
	writable = is_writable(pte);		// 현재 페이지가 쓰기 가능한지 여부 저장 -> 자식에게 동일한 권한을 주기 위해서 

	/* 5. WRITABLE 권한으로 VA 주소에 새 페이지를 자식의 페이지 테이블에 추가하세요. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: 페이지 삽입에 실패하면 오류 처리를 수행하세요. */
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {			// 부모의 실행 context를 복제하는 쓰레드 함수
	
	struct intr_frame if_;  						 
	struct thread *parent = (struct thread*)aux;	// do_fork 넘겨줄때 부모 쓰레드 넘겨줌 
	struct thread *current = thread_current ();		// _do_fork가 실행되면 자식 쓰레드가 스케줄러를 통해 실행중인 것 -> 즉, 현재쓰레드가 자식 쓰레드이다. 
	/* TODO: 어떻게든 parent_if(즉 process_fork()의 if_)를 전달하세요. */
	struct intr_frame *parent_if = &parent->parent_if;	// 부모 프로세스에 저장하고 있던 사용자 영역의 메모리를 넘겨줌
	bool succ = true;

	// enum intr_level old_level = intr_disable();

	/* 1. Read the cpu context to local stack. cpu컨텍스트를 로컬 스택으로 읽어온다.  */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));		//if_에 parent_if를 넘겨줌

	// 레지스터 복사하기 
	if_.R.rax = 0;

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	/* 여기에 코드를 작성하세요. 
		파일디스크립터 복제부분!
 		힌트: 파일 객체를 복제하려면 include/filesys/file.h에 있는 `file_duplicate`를 사용하세요.
 		주의: 부모 프로세스는 이 함수가 자원의 복제에 성공하기 전까지 fork() 호출에서 반환해서는 안 됩니다. */
		int fd = 0;
		while(fd < FD_MAX){
			struct file *f = parent->fd_table->fd_entries[fd];
			if(f==NULL){
				current->fd_table->fd_entries[fd] = NULL;
			}
			else{
				struct file *child_f = file_duplicate(f);
				if( child_f == NULL){	// 파일 복제에 실패하면 
					// 1. 지금까지 자식 테이블에 넣어 둔 모든 파일 핸들을 하나하나 닫아 주기 ->(이유: fork가 실패하면 원래 없었던일이 되어야함(리소스 누수가 일어날 수도 있고, 나중에 닫히지 않는 파일이 문제를 일으킬 수 있음))
					for(int i = 0; i<fd;i++){
						file_close(current->fd_table->fd_entries[i]);	// 파일 핸들 닫아주기
						current->fd_table->fd_entries[i]=NULL;			// 2. 자식의 파일 디스크립터 테이블을 정리(롤백)
					}
					// 3. fork 전체를 실패(TID_ERROR 반환) 처리
					return TID_ERROR;
				}
				else{
					current->fd_table->fd_entries[fd]= child_f;
				}
			}
			fd++;
		}

	// 완전 초기화 과정 
	process_init ();

	// 자식 프로세스가 완전히 로드되었음 부모 깨움
	sema_up(&current->fork_sema);

	/* Finally, switch to the newly created process. */
	//  자식 프로세스의 준비가 성공적(succ == true)
	// do_iret(&if_)**를 호출하여 사용자 모드로 복귀
	if (succ)
		do_iret (&if_);
error:
		sema_up(&current->fork_sema);
    	thread_exit ();	
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
/*  실제로 유저 프로그램을 메모리에 적재하고, CPU를 유저 모드로 전환하는 역할을 하는 함수 */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS; 

	/* We first kill the current context */
	process_cleanup ();

	/* And then load the binary */
	//실제로 file_name에 해당하는 실행파일을 메모리에 로드 성공하면 _if.rip에 진입 주소, _if.rsp에 스택 주소 등도 설정됨
	success = load (file_name, &_if);			

	//hex_dump(_if.rsp,_if.rsp,USER_STACK-(uint64_t)_if.rsp,true);

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success)
		return -1;

	/* Start switched process. */
	/* _if에 담긴 CPU 상태(유저 코드 세그먼트, eflags, rip, rsp 등)를 레지스터에 복원하면서 유저 모드로 진입 */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
/* 자식 프로세스 pid가 종료될 때까지 기다렸다가, 해당 자식이 exit()을 통해 전달한 종료 상태(exit status)를 부모가 받아오는 함수 */
int
process_wait (tid_t child_tid) {
	/* XXX: 힌트) Pintos가 process_wait(initd)일 때 종료됩니다.
	 * XXX: process_wait을 구현하기 전에 여기에 무한 루프를 추가하는 것을 추천합니다. */
	// for(int i=0; i<200000000; i++){}
	// return -1;
	
	/* 자식을 불러오고 자식이 아니면 -1을 반환한다. */
	struct thread *child = get_child_process(child_tid);
	if(child == NULL){
		return -1;
	}

	// 자식이 종료할때까지 기다린다. (process_exit에서 자식이 종료될때 sema_up을 해줄 것이다.)
	sema_down(&child->wait_sema);

	// 자식이 종료됨을 아리는 'wait_sema' signal을 받으면 현재 쓰레드(부모)의 자식 리스트에서 제거 
	list_remove(&child->child_elem);

	// 자식이 완전히 종료되고 스케줄링이 이어지도록 자식에게 시그널을 보내기
	sema_up(&child->exit_sema);

	return child->exit_status;

	
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: 여기에 여러분의 코드를 작성하세요.
 	 * TODO: 프로세스 종료 메시지를 구현하세요 (자세한 내용은
	 * TODO: project2/process_termination.html 문서를 참고하세요).
	 * TODO: 이곳에서 프로세스의 자원 정리를 구현하는 것을 추천합니다. */

	if(curr->running !=NULL){
		file_close(curr->running);
	}


   /* 1) 부모가 process_wait()에서 sema_down으로 기다리는 wait_sema 올리기 */
    sema_up(&curr->wait_sema);

    /* 2) 부모가 exit_status를 읽고 sema_up(&exit_sema) 해줄 때까지 대기 */
    sema_down(&curr->exit_sema);

    /* 3) 열린 파일 닫기 */
    for (int fd = 2; fd < FD_MAX; fd++) {
        if (curr->fd_table->fd_entries[fd] != NULL) {
            file_close(curr->fd_table->fd_entries[fd]);
            curr->fd_table->fd_entries[fd] = NULL;
        }
    }

	
	
	// 2. 자원 정리 -> 메모리 해제, 페이지 테이블 제거, 파일 디스크립터 정리
	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();
	
#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
/* ELF 실행 파일을 열고, 헤더를 읽고, 세그먼트를 메모리에 매핑하고, 스택을 설정한 후,
최종적으로 if_->rip에 유저 프로그램의 진입 주소를 넣어주는 함수 */
static bool
load (const char *file_name, struct intr_frame *if_) {							// file name(파일결로)로부터 실행가능한 ELF파일을 현재 쓰레드로 로드하는 함수 
	struct thread *t = thread_current ();										// RIP에는 실행 파일의 진입 주소를 저장하고, RSP에는 초기 스택 포인터를 저장한다. 
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	/* 페이지 테이블 생성 및 활성화 */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* 명령어를 공백을 기준으로 나눠주고 argv배열에 넣기(파싱하는 부분) */
	int argc = 0;
	char *argv[64];
	char *token, *save_ptr;
	
	for (token = strtok_r(file_name, " ", &save_ptr);
		 token != NULL;
		 token = strtok_r(NULL, " ", &save_ptr))
		{
			//printf("argv[%d]: %s\n", argc, token);
			argv[argc++]=token;
		}


	/* Open executable file. 실행 파일 열기 */	
	file = filesys_open (file_name);							// 인자로 받은 file_name 실행 파일을 파일 시스템에서 open
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);			// 실패 시 에러 메시지 출력
		goto done;
	}

	/* Read and verify executable header. ELF 헤더 읽고 유효성 검사 */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);			// 틀리면 "잘못된 실행 파일"로 간주 → 실패 처리
		goto done;
	}

	/* Read program headers.  프로그램 헤더 순회 */
	// ELF 실행 파일에는 여러 개의 Program Header (세그먼트) 가 있음
	// 각각의 세그먼트를 순회하면서 로딩 여부 판단
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}


	file_deny_write(file);
	t->running = file;


	/* Set up stack. */
	// 스택 셋업 
	/* setup_stack()을 통해 유저 스택을 설정, 이 함수 안에서 rsp 값(if_->rsp)이 세팅됨 .인자 푸시 작업은 여기서 하거나 나중에 처리됨 */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	// 시작 주소 설정(rip를 )
	if_->rip = ehdr.e_entry;		//e_entry: ELF 헤더에 명시된 진입 주소 (유저 프로그램이 실행을 시작할 위치)
									//이 값을 if_->rip에 저장해서 나중에 do_iret()으로 점프하게 됨

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	/*스택에 데이터 push하는 로직 구현*/
	//1. 데이터를 스택에 넣기.
	char *stack_ptr = (char *)if_->rsp;	// 스택 포인터 
	char *argv_ptr[128];				// 주소를 담기 위한 포인터 배열
	for (int i = argc-1; i>=0; i--)		// argc-1을 하는 이유 마지막에는 NULL들어가기 때문에 그거 빼줄려고 
	{
		// 인자의 길이 얻기 
		int argv_len = strlen(argv[i])+1;	// +1해주는 이유는 \0까지 넣어주기 위해!
		//printf("len: %d\n", argv_len);
		
		// 그 길이만큼 포인터 이동해주기
		stack_ptr -= argv_len; 
		//메모리에 직접 쓰기
		memcpy(stack_ptr,argv[i],argv_len);	// 첫 번째 인자 : 데이터를 복사해 넣을 대상 주소, 두 번째 인자 : 데이터를 가져올 원본 주소, 세 번째 인자 : 복사할 바이트 수  
		// 해당 주소(포이터)를 저장하기 -> 나중에 주소도 스택에 담아줘야하기 때문
		argv_ptr[i]=stack_ptr;
	}

	// 2. 16바이트 정렬(패딩하기)
	while((uint16_t)stack_ptr % 16 != 0){		// 16으로 나눠질때까지 포인트 내리기
		stack_ptr -= 1;		
		memset(stack_ptr, 0, 1);
	}

	// 3. NULL 포인터 먼저 push
	stack_ptr -= 8;
	memset(stack_ptr, 0, 8);

	// 4. 데이터 넣은 주소도 스택에 담기 
	for (i = argc-1; i >= 0; i--) 
	{
		stack_ptr -= 8;							// 주소는 8바이트씩 정렬해서 넣기
		memcpy(stack_ptr, &argv_ptr[i],8);
	}
	
	// 4. %rsi 레지스터에는 argv[0]의 주소를 넣고, %rdi 레지스터에는 argc 값(인자의 개수)을 넣는다.
	if_->R.rdi = argc;
	if_->R.rsi = stack_ptr;	// 마지막에 argv[0]을 넣었기에 stack_ptr를 rsi에 넣어주자 

	// 5. 가짜 리턴 주소 하나 push하기 
	stack_ptr -= 8;
	memset(stack_ptr,0,8);

	// 다시 rsp를 stack_ptr과 맞춰주기
	if_->rsp = stack_ptr;	

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	//file_close (file);				// 열었던 실행 파일 닫고, 성공 여부 리턴
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */