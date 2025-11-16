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
#include "threads/palloc.h"

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
// 시스템 콜 : 현재 프로세스 실행
int sys_exec(const char *cmd_line);

int sys_write(int fd, const void *buffer, unsigned size);
/////////////////////////////////////////////////////////////////////

// 유저가 제공한 포인터(주소)가 유효한지 검사
static void check_address(const void *uaddr)
{
	// 1. 할당된 메모리 주소가 유저영역인지 확인
	if (!is_user_vaddr(uaddr))
		sys_exit(-1);

	// 2. 할당된 메모리가 매핑 유무 및 NULL인지 확인
	if (pml4_get_page(thread_current()->pml4, uaddr) == NULL)
		sys_exit(-1);
}

// 유저가 전달한 buffer 검사
static void check_buffer(const void *buffer, unsigned size)
{
	for (unsigned i = 0; i < size; i++)
		check_address((const char *)buffer + i);
}

/////////////////////////////////////////////////////////////////////

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
	case SYS_EXEC:
	{
		// 1. user_process에서 첫번째 인자로 받은 명령어
		const char *cmd_line = (const char *)f->R.rdi;

		// 2. 그 명령어로 sys_exec() 호출 및 결과값 레지스터 rax에 저장
		f->R.rax = sys_exec(cmd_line);

		break;
	}
	case SYS_WRITE:
	{
		// 1. 유저에게 전달 받은 fd , buffer , size를 레지스터에서 추출
		int fd = f->R.rdi;
		const void *buffer = (const void *)f->R.rsi;
		unsigned size = f->R.rdx;

		// 2. 버퍼 검사
		// check_buffer(buffer, size); sys_write()에서 검사하는게 더 좋다고 합니다.

		// 3. 쓰기 요청 및 결과값 rax에 저장
		f->R.rax = sys_write(fd, buffer, size);
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
	struct thread *cur = thread_current();

	// [추가 권장] 나중에 process_wait 구현을 위해 필요합니다.
	// cur->exit_status = status;

	printf("%s: exit(%d)\n", cur->name, status);

	thread_exit();
}

int sys_write(int fd, const void *buffer, unsigned size)
{
	// 1. 쓰기 전 주소 검사하는게 좋다.
	check_buffer(buffer, size);
	// 2. 표준 출력(콘솔)인 경우
	if (fd == STDOUT_FILENO)
	{
		putbuf(buffer, size); // 콘솔에 문자열 출력
		return size;		  // 쓴 바이트 수만큼 반환
	}
	// 3. 그 외(파일 쓰기 등)는 아직 미구현 -> -1 반환
	return -1;
}

int sys_exec(const char *cmd_line)
{
	// 1. 들어온 명령어 메모리 주소 유효성 검사
	check_address(cmd_line);

	// 2. 명렁어 복사
	/*
	참고 : PAL ZERO
	- PAL : Page Allocator
	- ZERO : 0으로 채운다는 뜻
	*/
	char *cmd_line_copy = palloc_get_page(PAL_ZERO);
	if (cmd_line_copy == NULL)
		return -1;

	// 3. 문자열 복사
	strlcpy(cmd_line_copy, cmd_line, PGSIZE);

	// 4. process_exec()로 cmd_line으로 만든 새 프로그램으로 context switching
	if (process_exec(cmd_line_copy) == -1)
		return -1;

	NOT_REACHED();

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
