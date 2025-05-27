#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"

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

struct lock filesys_lock;
void
halt (void);
void
exit (int status);
pid_t
fork (const char *thread_name);
int
exec (const char *file);
int
wait (pid_t pid);
bool
create (const char *file, unsigned initial_size);
bool
remove (const char *file);
int
open (const char *file);
int
filesize (int fd);
int
read (int fd, void *buffer, unsigned size);
int
write (int fd, const void *buffer, unsigned size);
void
seek (int fd, unsigned position);

void
validation_check (void *addr) {
	struct thread *current_thread = thread_current();
	
	if (is_kernel_vaddr(addr)) exit(-1);
	if(pml4_get_page(current_thread->pml4, addr) == NULL) exit(-1);
}


static struct file *find_file_by_fd(int fd)
{
    struct thread *cur = thread_current();
    if (fd < 0 || fd >= FDCOUNT_LIMIT)
    {
        return NULL;
    }
    return cur->fd_table[fd];
}

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

	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	
	switch (f->R.rax) 
    	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi);
			break;
		case SYS_EXEC:
			if(exec(f->R.rdi) == -1) exit(-1);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
    	case SYS_OPEN:
        	f->R.rax = open(f->R.rdi);
        	break;
    	case SYS_FILESIZE:
        	f->R.rax = filesize(f->R.rdi);
        	break;
    	case SYS_READ:
        	f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
        	break;
    	case SYS_WRITE:
        	f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        	break;
    	case SYS_SEEK:
        	seek(f->R.rdi, f->R.rsi);
        	break;
    	case SYS_TELL:
        	f->R.rax = tell(f->R.rdi);
    		break;
    	case SYS_CLOSE:
        	close(f->R.rdi);
       		break;
    	default:
        	exit(-1);
        	break;
    	}

	
	/////////////////////////////
	// printf ("system call!\n");
	// thread_exit ();
}

void
halt (void) {
	power_off();
}

void
exit (int status) {
	struct thread* cur_t = thread_current();
    cur_t->exit_num = status;                         		
    printf("%s: exit(%d)\n", cur_t->name, status); 			
    thread_exit();  
}

pid_t
fork (const char *thread_name){

}

int
exec (const char *file) {
	validation_check(file);
    int file_size = strlen(file) + 1;
    char *fn_copy = palloc_get_page(PAL_ZERO);
    if (fn_copy == NULL)
    {
        exit(-1);
    }
    strlcpy(fn_copy, file, file_size); // file 이름만 복사
    if (process_exec(fn_copy) == -1)
    {
        return -1;
    }
    NOT_REACHED();
    return 0;
}

int
wait (pid_t pid) {

}

bool
create (const char *file, unsigned initial_size) {
	validation_check(file);
	return filesys_create(file, initial_size);		
}

bool
remove (const char *file) {

	validation_check(file);
	return filesys_remove(file);
}

int
open (const char *file) {
	validation_check(file);
	struct file* new_file = filesys_open(file);
	if(new_file == NULL) return -1;

	int check = add_file_to_thread(new_file);
	if(check == -1) file_close(new_file);
	return check;
}

int
filesize (int fd) {
	struct file* file  = get_file_from_thread(fd);
	if(file == NULL) return -1;
	return file_length(file);
}

int
read (int fd, void *buffer, unsigned size) {
	validation_check(buffer);
    int read_byte;
    uint8_t *read_buffer = buffer;
    if (fd == 0)
    {
        char key;
        for (read_byte = 0; read_byte < size; read_byte++)
        {
            key = input_getc();
            *read_buffer++ = key;
            if (key == '\0')
            {
                break;
            }
        }
    }
    else if (fd == 1)
    {
        return -1;
    }
    else
    {
        struct file *read_file = get_file_from_thread(fd);
        if (read_file == NULL)
        {
            return -1;
        }
        lock_acquire(&filesys_lock);
        read_byte = file_read(read_file, buffer, size);
        lock_release(&filesys_lock);
    }
    return read_byte;
}

int
write (int fd, const void *buffer, unsigned size) {
	validation_check(buffer);

	int b = -1;
	if(fd < 1) return -1;
	if(fd == 1){		// stdout print to console
		putbuf(buffer, size);
		return size;
	}

	struct file* f = get_file_from_thread(fd);
	if(f == NULL) return -1;

	lock_aquire(&filesys_lock);
	b = file_write(f, buffer, size);
	lock_release(&filesys_lock);

	return b;
}

void
seek (int fd, unsigned position) {
	struct file *s_file = get_file_from_thread(fd);
    if (s_file < 2)
    {
        return;
    }
    s_file->pos = position;
}

unsigned
tell (int fd) {
	struct file *tell_file = get_file_from_thread(fd);
    if (tell_file <= 2) return;
    return file_tell(tell_file);
}

void
close (int fd) {
	struct file *fileobj = get_file_from_thread(fd);
    if (fileobj == NULL) return;
    close_file_from_thread(fd);
}

int
dup2 (int oldfd, int newfd){

}

void *
mmap (void *addr, size_t length, int writable, int fd, off_t offset) {

}

void
munmap (void *addr) {

}

bool
chdir (const char *dir) {

}

bool
mkdir (const char *dir) {
	
}

bool
readdir (int fd, char name[READDIR_MAX_LEN + 1]) {

}

bool
isdir (int fd) {

}

int
inumber (int fd) {
	
}

int
symlink (const char* target, const char* linkpath) {

}

int
mount (const char *path, int chan_no, int dev_no) {

}

int
umount (const char *path) {

}

