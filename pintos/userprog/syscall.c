#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"  // power_off() 사용을 위해 추가
#include "threads/vaddr.h" // is_user_vaddr() 사용
#include "threads/mmu.h"   // pml4_get_page() 사용
#include <stdint.h>

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

/////////////////////////////////////////////////////////////////////
void syscall_init(void);

void syscall_handler(struct intr_frame *f UNUSED);
// 시스템 콜: Pintos 종료
void sys_halt(void);
// 시스템 콜: 현재 프로세스 종료
void sys_exit(int status);

int sys_write(int fd, const void *buffer, unsigned size);
/////////////////////////////////////////////////////////////////////

// 유저가 제공한 포인터(주소)가 유효한지 검사
/////////////////////////////////////////////////////////////////////
/* 유저 프로그램이 시스템 콜을 통해 커널에게 전달한 포인터(메모리 주소)가 안전한지 검사함수 */
static void check_address(const void *uaddr)
{
	// [1단계] 주소가 유저 영역(user space)에 속하는지 확인합니다.
	// is_user_vaddr()는 주소가 NULL이거나 커널 영역 주소이면 false를 반환합니다.
	if (uaddr == NULL || !is_user_vaddr(uaddr))
	{
		// 유효하지 않은 주소이므로, 프로세스를 강제 종료시킵니다.
		sys_exit(-1);
	}

	// [2단계] 주소가 실제 물리 메모리에 매핑되어 있는지 확인합니다. (Project 2 Non-VM)
	// pml4_get_page()는 해당 가상 주소에 대한 페이지 테이블 엔트리(PTE)를 찾습니다.
	// 만약 NULL을 반환하면, 해당 주소는 할당된 적이 없는 '허공'의 주소입니다.
	if (pml4_get_page(thread_current()->pml4, uaddr) == NULL)
	{
		// 매핑되지 않은 주소이므로, 프로세스를 강제 종료시킵니다.
		sys_exit(-1);
	}
}

static void
check_buffer(const void *buffer, unsigned size)
{
	for (unsigned i = 0; i < size; i++)
		check_address((const char *)buffer + i);
}

/////////////////////////////////////////////////////////////////////

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

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// 인자로 받은 intr_frame에 들어있는 레지스터 rax에 인터럽트 번호가 있다.
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

		int fd = f->R.rdi;
		const void *buffer = (const void *)f->R.rsi;
		unsigned size = f->R.rdx;

		check_buffer(buffer, size);

		f->R.rax = sys_write(fd, buffer, size);

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

	//

	printf("%s: exit(%d)\n", curr->name, status);

	thread_exit();
}

int sys_write(int fd, const void *buffer, unsigned size)
{
	// 1. 표준 출력(콘솔)인 경우
	if (fd == STDOUT_FILENO)
	{
		putbuf(buffer, size); // 콘솔에 문자열 출력
		return size;		  // 쓴 바이트 수 반환
	}

	// 2. 그 외(파일 쓰기 등)는 아직 미구현 -> -1 반환
	return -1;
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
