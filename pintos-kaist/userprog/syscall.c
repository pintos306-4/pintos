#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "string.h"
#include "devices/input.h"
#include "threads/init.h"
#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);


void halt(void);
void exit(int status);
bool create (const char *file, unsigned initial_size);
int fork (const char *thread_name);
int exec (const char *file);
int wait (int pid_t);
bool remove (const char *file);
int open (const char *file);
int add_file(struct file *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
struct file* get_file_by_fd(int fd);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
void check_addr(void *addr);

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
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	/*
		시스템 콜 핸들러 syscall_handler() 가 제어권을 얻으면 
		시스템 콜 번호는 rax 에 있고, 인자는 %rdi, %rsi, %rdx, %r10, %r8, %r9 순서로 전달됩니다.
		syscall() 함수를 보니 인자가 최대 3개라서 arg3까지만 선언함
	*/
	switch(f->R.rax){
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		// case SYS_FORK:
		// 	fork(f->R.rdi);
		// 	break;
		// case SYS_EXEC:
		// 	exec(f->R.rdi);
		// 	break;
		// case SYS_WAIT:
		// 	wait(f->R.rdi);
		// 	break;
		case SYS_CREATE:
			create(f->R.rdi, f->R.rsi);
			break;
		// case SYS_REMOVE:
		// 	remove(f->R.rdi);
		// 	break;
		case SYS_OPEN:
			open(f->R.rdi);
			break;
		// case SYS_FILESIZE:
		// 	filesize(f->R.rdi);
		// 	break;
		case SYS_READ:
			read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		// case SYS_SEEK:
		// 	seek(f->R.rdi, f->R.rsi);
		// 	break;
		// case SYS_TELL:
		// 	tell(f->R.rdi);
		// 	break;
		// case SYS_CLOSE:
		// 	close(f->R.rdi);
		// 	break;
		default:
			exit(-1);
			break;
	}

	// printf ("system call!\n");
	// thread_exit ();
}

/* power_off를 호출하여 머신을 종료한다. */
void halt(void){
	power_off();
}

/* 현재 실행 중인 유저 프로그램을 terminate하고 커널로 status를 리턴한다. 
 * 만약 부모 프로세스가 wait 하고 있다면 wait이라는 status가 리턴되어야 한다.
 * 통상적으로 status 0은 성공, 0 외의 값은 에러를 의미한다. */
void exit(int status){
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
}

/**
 * 'thread_name'이라는 이름을 가진 현재 프로세스의 복제본을 만든다.
 * 자식 프로세스의 pid는 0
 */
int fork (const char *thread_name){
	//process_fork(thread_name, );

}

int exec (const char *file){

}

int wait (int pid_t){

}

/**
 * 'file'이라는 이름의 initial_size 크기를 가진 새로운 파일을 생성한다.
 * 새로운 파일 생성을 성공하면 true, 실패하면 false를 반환한다.
 */
bool create (const char *file, unsigned initial_size){
	check_addr(file);
	return filesys_create (file, initial_size);
}

bool remove (const char *file){

}

/* file이라는 이름을 가진 파일을 여는 시스템 콜
파일을 성공적으로 열었다면 0 또는 양수의 fd(파일 식별자), 실패했다면 -1을 반환
0번은 표준 입력(STDIN_FILENO), 1번은 표준 출력(STDOUT_FILENO)으로 사용됨 
각각의 프로세스는 독립적인 파일 식별자를 가지며, 이 값은 자식 프로세스에게 상속(전달)됨
하나의 파일이 두 번 이상 열리면 그 때마다 open 시스템 콜은 새로운 식별자를 반환 */
/* fd table에 open file을 추가하고 fd를 받아온다.*/
int open (const char *file){
	check_addr(file);
	struct file* open_file = filesys_open(file); 

	if(open_file == NULL) 
		return -1;
	
	int fd = add_file(open_file);

	return fd;
}

int add_file(struct file *file){
	check_addr(file);

	struct thread *cur = thread_current();
	check_addr(cur->fd_table);

	for(int i=FD_MIN_IDX; i<FD_MAX_SIZE; i++){
		if(cur->fd_table[i] == NULL){
			cur->fd_table[i] = file;
			return i;
		}
	}
	return -1;
}

int filesize (int fd){

}

/* fd로 열린 파일에서 size bytes의 데이터를 읽어와서 buffer에 저장 
	- 실제로 읽어온 byte 수를 반환
	- 파일의 끝에 도달하면 (더 이상 읽을 내용이 없으면) 0을 반환
	- 파일을 읽을 수 없는 경우 (파일의 끝이 아닌 다른 조건 즉 파일이 존재하지 않거나 읽기 권한이 없는 경우 등) -1을 반환
	- fd가 0이면 read함수는 키보드로부터 데이터를 읽어옴. 이 때 input_getc()함수를 사용해 키보드 입력을 받는다.
	
*/
int read (int fd, void *buffer, unsigned length){
	if(fd < 0 || fd > FD_MAX_SIZE || length < 0)
		return NULL;
	check_addr(buffer);

	if(fd == 0){
		return input_getc();
	}else if(fd == 1){
		return -1;
	}
	
	//fd로 해당 파일 검색
	struct file* cur_file = get_file_by_fd(fd);
	if(cur_file == NULL)
		return -1;

	//검색한 파일을 size bytes 만큼 읽기
	return file_read(cur_file, buffer, length);
}

struct file*
get_file_by_fd(int fd){
	struct thread *cur = thread_current();
	if(cur -> fd_table[fd] == NULL || fd < 0 || fd > FD_MAX_SIZE)
		return NULL;
	return cur -> fd_table[fd];
}

/* buffer에서 size bytes 만큼 데이터를 읽어서 fd에 연결된 파일에 쓰기 
	실제 쓰여진 byte수가 반환됨
	fd 1은 콘솔에 쓰기 작업을 수행 -> putbuf()함수를 한 번 호출하여 가능한 모든 buffer 데이터를 한 번에 쓰는 것이 좋음
	size가 클 경우 적절한 크기로 분할해 작성해야 함
*/
int write (int fd, const void *buffer, unsigned length){
	if(fd < 0 || fd > FD_MAX_SIZE || length < 0)
		return NULL;
	check_addr(buffer);

	/* 버퍼에서 length만큼 읽어서 콘솔에 출력 */
	if(fd == 1){ 
		putbuf(buffer, length);
	} 
	if(fd == 0){
		return -1;
	}
	struct file *cur_file = get_file_by_fd(fd);


}
void seek (int fd, unsigned position){

}
unsigned tell (int fd){

}
void close (int fd){

}

void check_addr(void *addr){
	/* user_vaddr가 아니거나 null pointer이라면 스레드 종료 */
	struct thread *cur = thread_current();
	if(!is_user_vaddr(addr) || addr == NULL || pml4_get_page(cur->pml4, addr) == NULL)
		exit(-1);
}