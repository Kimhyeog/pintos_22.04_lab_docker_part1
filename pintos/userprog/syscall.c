#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h";

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void halt(void);
int sys_write (int fd, const void *buffer, unsigned size);
bool create (const char *file, unsigned initial_size);
int sys_open (const char *file);
void check_valid_string(char *address);
void check_valid_address(char *address);
void sys_close (int fd);
int sys_read (int fd, void *buffer, unsigned size);
int sys_filesize (int fd);
tid_t sys_fork (const char *thread_name, struct intr_frame *f);
int dup2(int oldfd, int newfd);

// int exec (const char *cmd_line);
// pid_t fork (const char *);
// int wait (pid_t);

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

struct lock file_create_look;

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

	lock_init(&file_create_look);
}

/* The main system call interface */
void syscall_handler (struct intr_frame *f UNUSED) {
	int status = f->R.rax;
	
	switch (status) {
		case SYS_WRITE: {
			int fd = f->R.rdi;
			check_valid_address((char *)f->R.rsi);
			if (fd < 0 || fd >= 512) {
				thread_current()->exit_status = -1;
				thread_exit();
			}

			lock_acquire(&file_create_look);
			size_t num = sys_write(fd, (void *)f->R.rsi, f->R.rdx);
			f->R.rax = num;
			lock_release(&file_create_look);

			break;
		}
		case SYS_EXIT:
			int exit_status = f->R.rdi;
			thread_current()->exit_status = exit_status;
			thread_exit();
			break;

		case SYS_HALT:
			halt();
			break;

		case SYS_EXEC:
			char *cmd_line = f->R.rdi;
			check_valid_string(cmd_line);
			if (cmd_line == NULL) {
				thread_current()->exit_status = -1;
				thread_exit();
			}

			if (process_exec(cmd_line) == -1) {
				thread_current()->exit_status = -1;
				thread_exit();
			}
			break;	

		case SYS_CREATE:
			char *file_name = f->R.rdi;
			unsigned initial_size = f->R.rsi; // "abcdf"
			check_valid_string(file_name);
			lock_acquire(&file_create_look);

			bool result = filesys_create(file_name, initial_size);
			f->R.rax = result;

			lock_release(&file_create_look);
			break;

		case SYS_OPEN:			
			char *file_open_name= f->R.rdi;
			check_valid_string(file_open_name);

			lock_acquire(&file_create_look);
			f->R.rax =  sys_open(file_open_name);
			lock_release(&file_create_look);
			break;

		case SYS_CLOSE:
			int fd = f->R.rdi;
			if (fd < 0 || fd >= 512) {
				break;
			}

			lock_acquire(&file_create_look);
			sys_close(fd);
			lock_release(&file_create_look);
			
			break;

		case SYS_READ:
			int read_fd = f->R.rdi;
			void *buffer = f->R.rsi;
			unsigned size = f->R.rdx;

			check_valid_address(buffer); 

			if (size > 0) {
				check_valid_address(buffer + size - 1);
			}

			if ((read_fd != 0 && read_fd < 2) || read_fd >= 512 || buffer == NULL || size < 0) {
				thread_current()->exit_status = -1;
				thread_exit();
			}

			lock_acquire(&file_create_look);
			int read_result = sys_read (read_fd, buffer, size);
			f->R.rax = read_result;
			lock_release(&file_create_look);
			
			break;

		case SYS_FILESIZE:
			int size_fd = f->R.rdi;
			if (size_fd < 0 || size_fd >= 512) {
				thread_current()->exit_status = -1;
				thread_exit();
			}

			lock_acquire(&file_create_look); 
            f->R.rax = sys_filesize(size_fd);
            lock_release(&file_create_look); 
			break;
			
		case SYS_FORK: {
			char *thread_name = f->R.rdi;
			f->R.rax = sys_fork (thread_name, f);

			break;	
		}	
		
		case SYS_WAIT: {
			f->R.rax = process_wait(f->R.rdi);
			break;
		}

        case SYS_SEEK: {
            int fd = f->R.rdi;
            off_t pos = f->R.rsi;
            
            if (fd < 2 || fd >= 512) {
                break;
            }

            lock_acquire(&file_create_look);
            struct file *file = thread_current()->fd_table[fd];
            if (file != NULL) {
                file_seek(file, pos);
            }
            lock_release(&file_create_look);
            
            break; 
        }

		case SYS_TELL: {
			int fd = f->R.rdi;
			if (fd < 2 || fd >= 512) {
				f->R.rax = -1;
				break;
			}
			lock_acquire(&file_create_look);
			struct file *file = thread_current()->fd_table[fd];
			if (file == NULL) {
				f->R.rax = -1;
			} else {
				f->R.rax = file_tell(file);
			}
			lock_release(&file_create_look);
			break;
		}

        case SYS_DUP2: {
            int oldfd = f->R.rdi;
            int newfd = f->R.rsi;
            
            lock_acquire(&file_create_look);
            f->R.rax = dup2(oldfd, newfd);
            lock_release(&file_create_look);
            
            break;
        }
		default:
			break;
	}
}

int sys_write (int fd, const void *buffer, unsigned size) {
    if (size == 0) return 0;
    if (fd <= 0 || fd >= 512) return -1; // Cannot write to stdin or invalid FDs.

    struct file *file_obj = thread_current()->fd_table[fd];

    if (file_obj == NULL) {
        // This fd is not a file. Assume it's a console output stream.
        putbuf(buffer, size);
        return size;
    }

    // It's a file.
    return file_write(file_obj, buffer, size);
}

void halt(void) {
	power_off();
}

int sys_open (const char *file_name) {
	struct file *open_file = filesys_open(file_name);

	if (open_file == NULL) {
        return -1; 
    }

	struct file **fd_table = thread_current()->fd_table;
	bool success = false;
	int i = 2;
	for (; i < 512; i++) {
		if (fd_table[i] == NULL) {
			fd_table[i] = open_file;
			success = true;
			break;
		}
	}

	if (!success) {
		file_close(open_file); 
        return -1;
	}

	return i;
}

void check_valid_string(char *address) { 
	while (true) {
		if (address == NULL || is_kernel_vaddr(address) || pml4_get_page(thread_current()->pml4, address) == NULL) {
			thread_current()->exit_status = -1;
			thread_exit();
		}
				
		if (*address == '\0') {
			break;
		}

		address++;
	}
}

void check_valid_address(char *address) {// 처음과 끝만 확인 vs 다 확인 vs 끝만 확인
	if (address == NULL || is_kernel_vaddr(address) || pml4_get_page(thread_current()->pml4, address) == NULL) {
		thread_current()->exit_status = -1;
		thread_exit();
	}
}

void sys_close (int fd) {

	struct thread *current = thread_current();
	struct file *file = current->fd_table[fd];

	if (file == NULL) {
		return;
	}

    file_close(file); 
	current->fd_table[fd] = NULL;
}

int sys_read (int fd, void *buffer, unsigned size) {
	if (size == 0) {
		return 0;
	}

	if (fd == 0) {
		char *cur = buffer;
		for (int i = 0; i < size; i++) {
			*cur = input_getc();
			cur++;
		}

		return size; // size만큼 꼭 써야하는가?
	}

	if (buffer == NULL) { 
		return -1;
	}

	struct thread *current = thread_current();
	struct file **fd_table = current->fd_table;
	struct file *read_file = fd_table[fd];

	if (read_file == NULL) {
		return -1;
	}

	int result = file_read(read_file, buffer, size);
	return result;
}

int sys_filesize (int fd) {
	struct thread *current = thread_current();
	struct file *file = current->fd_table[fd];

	if (file == NULL) {
		return -1;
	}

	int result = file_length(file);
	return result;
}

tid_t sys_fork (const char *thread_name, struct intr_frame *f) {	
	return process_fork(thread_name, f);
}

int dup2(int oldfd, int newfd) {

	if (oldfd < 0 || oldfd >= 512 || newfd < 0 || newfd >= 512) {
		return -1;
	}
    
    struct file **fd_table = thread_current()->fd_table;

	if (oldfd == newfd) {
		return newfd;
	}

	struct file *old_file = fd_table[oldfd];
	struct file *new_file = fd_table[newfd];

	if (old_file == new_file) {
		return newfd;
	}

    if (new_file != NULL) {
        file_close(new_file);
    }

	fd_table[newfd] = old_file;

	if (old_file != NULL) {
		file_dup(old_file);
	}

	return newfd;	 
}