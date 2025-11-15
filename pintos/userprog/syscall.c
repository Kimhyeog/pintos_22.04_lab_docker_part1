#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	// 의미1. 유저가 syscall을 부르면, CPU는 커널 모드로 전환 , 코드 실행 권한은 SEL_KCSEG
	// 의미2. 커널이 sysret을 실행하면, CPU는 유저 모드로 복귀 , 코드 실행 권한은 SEL_UCSEG
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);

	// 레지스터를 스택에 저장(PUSH)하고, 스택을 유저 스택에서 커널 스택으로 바꾼 뒤, 우리가 C언어로 작성할 syscall_handler(f) 함수 호출해주는 라인
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	// syscall 실행 시, 자동으로 끌(Clear) CPU 플래그(Flag)를 설정
	write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* System call numbers. */
// enum
// {
// 	/* Projects 2 and later. */
// 	SYS_HALT,	  /* Halt the operating system. */
// 	SYS_EXIT,	  /* Terminate this process. */
// 	SYS_FORK,	  /* Clone current process. */
// 	SYS_EXEC,	  /* Switch current process. */
// 	SYS_WAIT,	  /* Wait for a child process to die. */
// 	SYS_CREATE,	  /* Create a file. */
// 	SYS_REMOVE,	  /* Delete a file. */
// 	SYS_OPEN,	  /* Open a file. */
// 	SYS_FILESIZE, /* Obtain a file's size. */
// 	SYS_READ,	  /* Read from a file. */
// 	SYS_WRITE,	  /* Write to a file. */
// 	SYS_SEEK,	  /* Change position in a file. */
// 	SYS_TELL,	  /* Report current position in a file. */
// 	SYS_CLOSE,	  /* Close a file. */

// 	/* Project 3 and optionally project 4. */
// 	SYS_MMAP,	/* Map a file into memory. */
// 	SYS_MUNMAP, /* Remove a memory mapping. */

// 	/* Project 4 only. */
// 	SYS_CHDIR,	 /* Change the current directory. */
// 	SYS_MKDIR,	 /* Create a directory. */
// 	SYS_READDIR, /* Reads a directory entry. */
// 	SYS_ISDIR,	 /* Tests if a fd represents a directory. */
// 	SYS_INUMBER, /* Returns the inode number for a fd. */
// 	SYS_SYMLINK, /* Returns the inode number for a fd. */

// 	/* Extra for Project 2 */
// 	SYS_DUP2, /* Duplicate the file descriptor */

// 	SYS_MOUNT,
// 	SYS_UMOUNT,
// };

/* --- 1. 헬퍼 함수 프로토타입 선언 --- */
/* syscall_handler가 호출하기 전에 이 함수들이 선언되어 있어야 합니다. */

// 시스템 콜: Pintos 종료
void sys_halt(void);
// 시스템 콜: 현재 프로세스 종료
void sys_exit(int status);

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{

	uint64_t syscall_num = f->R.rax;

	switch (syscall_num)
	{

	case SYS_HALT:
	{
		sys_halt();
		break;
	}
	case SYS_WRITE:
	{
		break;
	}
	case SYS_EXEC:
	{
		break;
	}
	case SYS_EXIT:
	{
		// 1. rdi 레지스터에 담겨있는 thread의 상태를 꺼낸다.
		int status = f->R.rdi;
		// 2. 그 thread의 상태를 sys_exit(status)에게 전달
		sys_exit(status);
		break;
	}
	default:
		// 유효하지 않은 시스템 콜 번호가 들어온 경우
		printf("Unknown system call: %llu\n", syscall_num);
		// 프로세스를 에러 상태(-1)로 강제 종료시킵니다.
		sys_exit(-1);
		break;
	}

	// printf("system call!\n");
	// thread_exit();
}

void sys_halt(void)
{
	power_off();
}

void sys_exit(int status)
{
	struct thread *curr = thread_current();

	printf("%s : exit(%d)\n", curr->name, status);

	thread_exit();
}
