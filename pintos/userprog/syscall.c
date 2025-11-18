#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/loader.h"
#include "userprog/process.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"  // power_off() 사용을 위해 추가
#include "threads/vaddr.h" // is_user_vaddr() 사용
#include "threads/mmu.h"   // pml4_get_page() 사용
#include <stdint.h>
#include "threads/palloc.h"

static struct lock filesys_lock; // 2. 락 변수 정의 (실제 재료)

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

void syscall_handler(struct intr_frame *f UNUSED);
// 시스템 콜: Pintos 종료
void sys_halt(void);
// 시스템 콜: 현재 프로세스 종료
void sys_exit(int status);
// 시스템 콜 : 현재 프로세스 실행
int sys_exec(const char *cmd_line);

int sys_write(int fd, const void *buffer, unsigned size);
// 시스템 콜 : create()
bool sys_create(const char *file, unsigned size);

int sys_open(const char *file);

/////////////////////////////////////////////////////////////////////

// 유저가 제공한 포인터(주소)가 유효한지 검사
static void check_address(const void *uaddr)
{
	// 1. 할당된 메모리 주소가 유저영역인지 확인 &&  NULL인지 확인
	if (uaddr == NULL || !is_user_vaddr(uaddr))
		sys_exit(-1);

	// 2. 할당된 메모리가 매핑 유무
	if (pml4_get_page(thread_current()->pml4, uaddr) == NULL)
		sys_exit(-1);
}

// 유저가 전달한 buffer 검사
static void check_buffer(const void *buffer, unsigned size)
{
	for (unsigned i = 0; i < size; i++)
		check_address((const char *)buffer + i);
}

static void check_string(const char *string)
{
	// 1. 첫번째 문자 주소 유효성 검사
	check_address(string);

	// 2. 그 이후로 계속 검사
	while (*string != '\0')
	{
		string++;
		check_address(string);
	}
}

/////////////////////////////////////////////////////////////////////

void syscall_init(void)
{

	// 파일 시스템 락 초기화
	lock_init(&filesys_lock);

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
	case SYS_WAIT:
	{
		// 1. User Program이 기다리고 싶어하는 자식 PID를 rdi 레지스터로 전달받기
		tid_t pid = f->R.rdi;

		// 2. process_wait() 수행 후, 결과를 status 받기
		int status = process_wait(pid);
		break;
	}
	case SYS_CREATE:
	{
		// 1. 유저 프로그램에서 보낸 file명과 file 초기 크기 레지스터로 전달받기
		const char *file = (const char *)f->R.rdi;

		unsigned initial_size = f->R.rsi;

		// 2. sys_create 호출 후, 결과값 rax 레지스터에 저장
		f->R.rax = sys_create(file, initial_size);

		break;
	}
	case SYS_REMOVE:
	{
		break;
	}
	case SYS_OPEN:
	{
		const char *file = (const char *)f->R.rdi;
		f->R.rax = sys_open(file);
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
		// 역할1 : putbuf는 size로 지정된 여러 바이트(문자열)를 한 번에 처리합니다.
		// 역할2 : putbuf는 내부적으로 락(lock)을 사용하거나 인터럽트를 제어
		// -> 여러 프로세스가 동시에 printf를 호출해도 출력이 섞이지 않도록 보장

		return size; // 쓴 바이트 수만큼 반환
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

bool sys_create(const char *file, unsigned size)
{
	// 1. user 프로그램이 보낸 주소 유효성 검사
	check_address(file);

	// 2. 파일 시스템은 thread가 안전하지 않음 -> 락 필요
	lock_acquire(&filesys_lock);

	// 3. 실제 파일 생성
	bool success = filesys_create(file, size);

	// 4. 락 해제
	lock_release(&filesys_lock);

	return success;
}

int sys_open(const char *file)
{

	// 1. file 유효성 검사
	check_string(file);
	// 2. 락 걸기 → file 열기 과정 → 락 해제 → 파일 검사
	lock_acquire(&filesys_lock);
	struct file *file_obj = filesys_open(file);
	lock_release(&filesys_lock);

	// 추가 : file_obj가 생성이 실패 시, -> -1 반환
	// 즉, 인자로 들어온 file 명이 빈 문자열일 시,
	if (file_obj == NULL)
		return -1;

	// 3. 현재 thread 갖고와서, FDT에 등록 및 파일 열기 성공이므로, fd 반환
	// 참고_ Pintos 명세서와 기본 C 라이브러리는 fd = 0 (STDIN)과 fd = 1 (STDOUT)만 **커널이 특별 취급(콘솔 예약)**하도록 정의
	struct thread *cur = thread_current();

	for (int fd = 2; fd < FDT_SIZE; fd++)
		if (cur->fd_table[fd] == NULL)
		{
			cur->fd_table[fd] = file_obj;
			return fd;
		}

	// 4. 파일 열기 실패 -> file_close()
	file_close(file_obj);

	// 5. return -1;
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
