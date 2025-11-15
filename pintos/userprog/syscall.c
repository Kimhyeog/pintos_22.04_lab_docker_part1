#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"
#include <console.h>

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
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	//%rax시스템 호출 번호 ,인자 순서 %rdi, %rsi, %rdx, %r10, %r8, and %r9
	uint64_t syscall_num = f->R.rax; 
	switch (syscall_num)
	{
	case SYS_EXIT:
		exit(f->R.rdi);
		thread_exit ();
		break;
	case SYS_EXEC:
		sys_exec(f->R.rdi);
		break;
	case SYS_WAIT:
		// wait(f->R.rdi);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	// case SYS_HALT:
	// 	halt();
	// 	break;
	// case SYS_FORK:
	// 	fork();
	// 	break;
	// case SYS_CREATE:
	// 	create();
	// 	break;
	// case SYS_OPEN:
	// 	open();
	// 	break;
	// case SYS_FILESIZE:
	// 	filefize();
	// 	break;
	// case SYS_READ:
	// 	read();
	// 	break;

	// case SYS_SEEK:
	// 	seek();
	// 	break;
	// case SYS_TELL:
	// 	tell();
	// 	break;
	// case SYS_CLOSE:
	// 	close();
	// 	break;
	default:
		break;
	}
	// printf ("system call!\n");
	// printf ("%d", syscall_num);
}
void exit (int status){ //이거 중복 선언임
	printf ("%s: exit(%d)\n", thread_name(),status);
	thread_exit();
}

int sys_exec (const char *file){
	// 이 함수를 호출한 스레드 이름 변경 X , FD는 호출 후에도 열려 있음
	//file -> 실행 cmdlineputbuf()
	//return 성공시 반환 X , 다른 경우 -1
	if (file == NULL)
		return -1;
}

int write (int fd, const void *buffer, unsigned length){
	if (fd == 1)
	{
		if (buffer !=NULL)
		{
			putbuf(buffer, length);
			return length;
		}
	}
	return -1;
}
// int wait (pid_t){

// }

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// void halt (void) NO_RETURN;
// pid_t fork (const char *thread_name);
// int wait (pid_t);
// bool create (const char *file, unsigned initial_size);
// bool remove (const char *file);
// int open (const char *file);
// int filesize (int fd);
// int read (int fd, void *buffer, unsigned length);
// void seek (int fd, unsigned position);
// unsigned tell (int fd);
// void close (int fd);
