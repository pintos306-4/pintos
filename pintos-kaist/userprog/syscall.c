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
#include "threads/synch.h"
#include "userprog/process.h"
#include "threads/palloc.h"
#include "lib/string.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
int open(const char *file);
int write(int fd,const void *buffer, unsigned length);
int read (int fd, const void *buffer, unsigned length);
void close(int fd);
int wait(int pid);
void seek (int fd, unsigned position);


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

struct lock file_lock;
 
void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

    lock_init(&file_lock);
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
	

	int syscall_number = f->R.rax;

	switch (syscall_number)
	{
	case SYS_HALT:
		halt();
		break;

	case SYS_EXIT:
		exit(f->R.rdi);
		break;

	 case SYS_CREATE:
        f->R.rax = create (f->R.rdi,f->R.rsi);      
        break;
    
    case SYS_OPEN:    
        f->R.rax = open(f->R.rdi);
        break;
    
    case SYS_WRITE:
        f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    
    case SYS_READ:
        f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
        break;
    
    case SYS_CLOSE:
        close(f->R.rdi);
        break;
    
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;

    case SYS_FORK:
        f->R.rax = process_fork(f->R.rdi, f);
        break;

    case SYS_WAIT:
        f->R.rax  = wait(f->R.rdi);
        break;

    case SYS_SEEK:
        seek(f->R.rdi, f->R.rsi);
        break;

    case SYS_EXEC:
        f->R.rax = exec (f->R.rdi);
        break; 

	default:
		thread_exit ();
		break;
	}


	
}

// 주소가 유효한 지 확인하는 함수
void check_valid_address(void *addr){
    struct thread *cur = thread_current();
    
    // 주소가 유저영역에 있는지 또는 NULL포인트는 아닌지 또는 페이지에 매핑이 되어있는지   예외처리 하는 함수
    if(!is_user_vaddr(addr) || addr==NULL || pml4_get_page(cur->pml4,addr) == NULL){
        exit(-1);
    }

}

// buffer는 연속된 주소공간이다. 그리고 os는 이런 buff를 페이지 별로 관리한다. 그런 buffer가 유효한지 검사하는 함수 
void check_valid_buffer(void *buffer, size_t buff_size){
    uint8_t *end  = (uint8_t*)buffer + buff_size;
    // 페이지단위로 for문을 돌려도 상관이 없음 그중 하나만 검사해도 괜춚!
    for(void *addr = pg_round_down(buffer);addr < end;addr += PGSIZE){              //pg_round_down(addr)는 addr이 속한 페이지의 시작 주소를 구한다. 
        check_valid_address(addr);
    }
}

// 주어진 문자열이 유효한 사용자 주소 공간에 있는지 검사하는 함수
void check_valid_string(char *str){
	if (str ==NULL){
		exit(-1);
	}

    while(true){                        // 문자열의 길이는 짧기도 하고 \0까지 검사를 해야 하기에 while이 적합하다. 
        check_valid_address(str);
        if(*str == '\0'){
            break;
        }
        str++;
    }
}


// os 종료하는 함수 
void halt (void){
    power_off();
}

// 쓰레드 종료하는 함수 
void exit(int status){
    struct thread *cur = thread_current();   
    cur->exit_status = status;                           // 부모에게 종료상태를 전달하기 위해 초기화 

    printf("%s: exit(%d)\n",cur->name, status);
    thread_exit();                                      // 쓰레드 종료
}

// 파일 생성하는 함수 
bool create(const char *file, unsigned initial_size) {
    check_valid_string(file);
    return filesys_create(file, initial_size);
}

// 파일 열기 성공하면 0이상의 fd를 반환하고 실패하면 -1을 반환해라 
int open(const char *file){
    
    check_valid_string(file);   // 인자(파일 이름이) 유효한지 확인하기 
    
    struct thread *curr = thread_current();

    struct file *open_file = filesys_open(file);    // 파일 주소를 받고 
     
    if (open_file ==NULL){      // 파일 주소가 있는지 예외처리 
        return -1;
        }

    for (int fd = 2; fd<FD_MAX;fd++){                       // 파일 디스크립터를 순회하여 
        if (curr->fd_table->fd_entries[fd]==NULL){          // fd가 비어있으면 
            curr->fd_table->fd_entries[fd] = open_file;     // 거기에 파일 주소를 넣어라!
            return fd;                                      // 그리고 fd를 반환해라 
        }
    }
    
    lock_acquire(&file_lock);
    file_close(open_file);
    lock_release(&file_lock);
    return -1;
}

// 파일에 데이터를 쓰는 함수 (반환값은 실제로 쓴 바이트 수)
int write(int fd,const void *buffer, unsigned length){
    // 유효성 검사
    check_valid_buffer(buffer,length);
    struct thread *curr = thread_current();

    if(fd==0){
        return -1;
    }

    // fd가 1이면 표준 출력(stdout)
    if(fd==1){
        putbuf(buffer, length);     // 키보드 입력이 아닌 콘솔 출력이기 때문에, 파일이 아니라 putbuf()로 처리
        return length;              // 출력한 바이트 수 반환
    }

    // fd가 유효한지 확인하는 로직
    if (fd < 0||fd >= FD_MAX|| curr->fd_table->fd_entries[fd]==NULL){
        return -1;
    }
    
    struct file *f = curr->fd_table->fd_entries[fd];
    if (f ==NULL){
        return -1;
    }

    lock_acquire(&file_lock);
    int bites_length = file_write (f, buffer, length);  // file_write()를 호출하여 실제로 데이터를 쓴다. 반환값은 실제로 쓴 바이트 수임.
    lock_release(&file_lock);

    return bites_length;
}

int filesize(int fd){
	struct thread *curr = thread_current();

	// fd가 유효한지 확인하는 로직
    if (fd < 0||fd >= FD_MAX|| curr->fd_table->fd_entries[fd]==NULL){
        return -1;
    }
    struct file *f = curr->fd_table->fd_entries[fd];

	return file_length(f);
}


//  유저 프로그램이 호출한 read(fd, buffer, length)를 실제로 처리하는 함수입
int read (int fd, const void *buffer, unsigned length) {

    //유효성 검사
    check_valid_buffer(buffer,length);

    struct thread *curr = thread_current();
    
    // 표준입력 처리  
    if(fd==0){

        for (unsigned i = 0 ; i<length;i++){
            //읽은 만큼 buffer[i]에 저장하고, 끝나면 읽은 바이트 수(size)를 반환.
            ((char *)buffer)[i] = input_getc();     // input_getc()는 입력이 들어올 때까지 기다렸다가 한 글자를 리턴하는 함수 
        }
        return length;
    }
    // fd유효성 검사 
    if (fd < 0|| fd==1 ||fd >= FD_MAX|| curr->fd_table->fd_entries[fd]==NULL){
        return -1;
    }

    //파일 디스크립터 테이블에서 해당 fd에 연결된 struct file *을 꺼내기
    struct file *f = curr->fd_table->fd_entries[fd];
    if(f==NULL){
        return -1;
    }

    lock_acquire(&file_lock);
    //file_read()를 호출하여 실제 파일에서 데이터를 읽는다.반환값은 실제로 읽은 바이트 수다
    int bytes_read = file_read (f, buffer, length); 
    lock_release(&file_lock);

    return bytes_read; 
}

// 파일 디스크립터 fd에 해당하는 열린 파일을 닫고, 프로세스의 파일 디스크립터 테이블에서 해당 엔트리를 제거하는 함수
void close(int fd){
    struct thread *curr = thread_current();
    struct file *f = curr->fd_table->fd_entries[fd];

    if (fd < 0||fd >= FD_MAX|| curr->fd_table->fd_entries[fd]==NULL){
        return;
    }

    file_close(f);          // struct file *이 가리키는 실제 파일 객체를 닫는다.
    curr->fd_table->fd_entries[fd]= NULL;       //f = NULL은 지역 변수 하나를 바꾸는 것이기에 바뀌지 않음

}

int wait(int pid){
    return process_wait(pid);
}

void seek (int fd, unsigned position) {
    struct thread *curr = thread_current();
    struct file *f = curr->fd_table->fd_entries[fd];

    if (fd < 0||fd >= FD_MAX|| curr->fd_table->fd_entries[fd]==NULL){
        return;
    }
    file_seek(f,position);
}

int exec (const char *file) {
    check_valid_string(file);

    char *file_copy;
    file_copy = palloc_get_page(0);
    if(file_copy ==NULL){
        exit(-1);
    }
 
    strlcpy(file_copy, file,PGSIZE);

    if(process_exec(file_copy) == -1){
        exit(-1); 
    }
}