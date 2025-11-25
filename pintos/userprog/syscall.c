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
#include "filesys/file.h"

struct lock filesys_lock; // 2. 락 변수 정의 (실제 재료)

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

int sys_read(int fd, void *buffer, unsigned size);

int sys_write(int fd, const void *buffer, unsigned size);
// 시스템 콜 : create()
bool sys_create(const char *file, unsigned size);

int sys_open(const char *file);

void sys_close(int fd);

bool sys_remove(const char *file_name);

int sys_filesize(int fd);

tid_t sys_fork(const char *thread_name, struct intr_frame *f);

void sys_seek(int fd, unsigned position);

int sys_tell(int fd);

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
	case SYS_FILESIZE:
	{

		// 8번
		f->R.rax = sys_filesize(f->R.rdi);
		break;
	}
	case SYS_READ:
	{
		int fd = f->R.rdi;
		void *buffer = (void *)f->R.rsi;
		unsigned size = f->R.rdx;

		f->R.rax = sys_read(fd, buffer, size);

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
	case SYS_FORK:
	{
		const char *user_name_ptr = (const char *)f->R.rdi;

		// 1. 주소 유효성 검사 (필수)
		check_address(user_name_ptr);

		// 2. 복사된 커널 포인터를 넘김
		f->R.rax = sys_fork(user_name_ptr, f);

		break;
	}
	case SYS_WAIT:
	{
		// 1. User Program이 기다리고 싶어하는 자식 PID를 rdi 레지스터로 전달받기
		tid_t pid = f->R.rdi;

		// 2. process_wait() 수행 후, 결과를 status 받기
		f->R.rax = process_wait(pid);
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
		const char *file_name = (const char *)f->R.rdi;

		f->R.rax = sys_remove(file_name);

		break;
	}
	case SYS_OPEN:
	{
		const char *file = (const char *)f->R.rdi;
		f->R.rax = sys_open(file);
		break;
	}
	case SYS_CLOSE:
	{
		int fd = f->R.rdi;
		sys_close(fd);
		break;
	}
	case SYS_SEEK:
	{
		int fd = f->R.rdi;
		unsigned position = f->R.rsi;

		sys_seek(fd, position);
		break;
	}
	case SYS_TELL:
	{
		int fd = f->R.rdi;

		f->R.rax = sys_tell(fd);

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
	case SYS_DUP2:
	{
		int oldfd = f->R.rdi;
		int newfd = f->R.rsi;

		f->R.rax = sys_dup2(oldfd, newfd);

		break;
	}
	default:
	{

		// 유효하지 않은 시스템 콜 번호가 들어온 경우
		printf("Unknown system call: %llu\n", syscall_num);
		// 프로세스를 에러 상태(-1)로 강제 종료시킵니다.
		sys_exit(-1);
		break;
	}
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
	cur->exit_status = status;

	thread_exit();
}

int sys_write(int fd, const void *buffer, unsigned size)
{

	// 1. 쓰기 전 주소 검사하는게 좋다.
	check_buffer(buffer, size);

	// 예외 fd 범위 수정
	if (fd < 0 || fd >= FDT_SIZE)
		return -1;

	// 현재 쓰레드의 FDT에 해당하는 file 포인터 추출
	struct thread *cur = thread_current();
	struct file *file_obj = cur->fd_table[fd];

	// 2. 표준 출력(콘솔)인 경우
	// fd == 1이라고 무조건 출력하는 게 아니라, FDT를 확인해야 합니다.
	if (file_obj == (struct file *)2)
	{
		putbuf(buffer, size); // 콘솔에 문자열 출력
		// 역할1 : putbuf는 size로 지정된 여러 바이트(문자열)를 한 번에 처리합니다.
		// 역할2 : putbuf는 내부적으로 락(lock)을 사용하거나 인터럽트를 제어
		// -> 여러 프로세스가 동시에 printf를 호출해도 출력이 섞이지 않도록 보장

		// 쓴 바이트 수만큼 반환
		return size;
	}
	// 3. 그 외(파일 쓰기 등)
	else if (fd >= 2 && fd < FDT_SIZE)
	{

		// file NULL인지 check
		if (file_obj == NULL)
			return -1;

		// 파일 쓰기 요청
		lock_acquire(&filesys_lock);
		int byte_written = file_write(file_obj, buffer, size);
		lock_release(&filesys_lock);

		return byte_written;
	}

	return -1;
}

int sys_exec(const char *cmd_line)
{

	check_address(cmd_line);

	char *cmd_line_copy = palloc_get_page(PAL_ZERO);
	if (cmd_line_copy == NULL)
		return -1;

	strlcpy(cmd_line_copy, cmd_line, PGSIZE);

	if (process_exec(cmd_line_copy) == -1)
	{
		palloc_free_page(cmd_line_copy);
		return -1;
	}

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

	// 추가 : file_obj가 생성이 실패 시, -> -1 반환
	// 즉, 인자로 들어온 file 명이 빈 문자열일 시,
	if (file_obj == NULL)
	{
		lock_release(&filesys_lock);
		return -1;
	}

	// 3. 현재 thread 갖고와서, FDT에 등록 및 파일 열기 성공이므로, fd 반환
	// 참고_ Pintos 명세서와 기본 C 라이브러리는 fd = 0 (STDIN)과 fd = 1 (STDOUT)만 **커널이 특별 취급(콘솔 예약)**하도록 정의
	struct thread *cur = thread_current();

	if (cur->fd_table == NULL)
	{
		file_close(file_obj);		 // 1. 파일 닫기
		lock_release(&filesys_lock); // 2. 락 해제
		return -1;
	}

	int fd = 2;
	while (fd < FDT_SIZE)
	{

		if (cur->fd_table[fd] == NULL)
			break;

		fd++;
	}

	if (fd >= FDT_SIZE)
	{
		file_close(file_obj);
		lock_release(&filesys_lock);
		return -1;
	}

	cur->fd_table[fd] = file_obj;
	lock_release(&filesys_lock);
	return fd;
}

void sys_close(int fd)
{
	if (fd < 0 || fd >= FDT_SIZE)
		return;

	struct thread *cur = thread_current();
	struct file *file = cur->fd_table[fd];

	if (file == NULL)
		return;

	// [수정] 표준 입출력(Dummy)이 아닐 때만 실제 file_close 호출
	if (file > (struct file *)2)
	{
		lock_acquire(&filesys_lock);
		file_close(file);
		lock_release(&filesys_lock);
	}

	cur->fd_table[fd] = NULL;
}
bool sys_remove(const char *file_name)
{
	// 1. 문자열 전체 유효성 검사
	check_string(file_name);
	// 2. 락 걸기
	lock_acquire(&filesys_lock);
	// 3. filesys_remove() 결과 반환
	bool result = filesys_remove(file_name);
	// 4. 락 해제
	lock_release(&filesys_lock);
	// 5. 결과 반환
	return result;
}

int sys_read(int fd, void *buffer, unsigned size)
{
	// 1. 버퍼 유효성 검사
	check_buffer(buffer, size);

	struct thread *cur = thread_current();
	struct file *file_obj = cur->fd_table[fd];

	// 2. fd==0일 시, 키보드 입력
	if (file_obj == (struct file *)1)
	{
		char *buf_ptr = (char *)buffer;

		for (unsigned i = 0; i < size; i++)
		{
			char c = input_getc();
			if (c == '\r')
				c = '\n';
			buf_ptr[i] = c;
		}
		return size;
	}
	else if (fd >= 2 && fd < FDT_SIZE)
	{
		int byte_read_size = -1;
		lock_acquire(&filesys_lock);

		if (file_obj == NULL)
		{
			lock_release(&filesys_lock);
			return -1;
		}

		byte_read_size = file_read(file_obj, buffer, size);

		lock_release(&filesys_lock);
		return byte_read_size;
	}

	return -1;
}
int sys_filesize(int fd)
{
	struct thread *curr = thread_current();

	// fd 유효성 검사
	if (fd < 2 || fd >= FDT_SIZE)
		return -1;

	if (curr->fd_table == NULL)
		return -1;

	struct file *file_obj = curr->fd_table[fd];

	if (file_obj == NULL)
		return -1;

	// 락을 걸고 파일 길이 가져오기
	lock_acquire(&filesys_lock);
	int length = file_length(file_obj);
	lock_release(&filesys_lock);

	return length;
}

tid_t sys_fork(const char *thread_name, struct intr_frame *f)
{

	tid_t result = process_fork(thread_name, f);

	return result;
}

void sys_seek(int fd, unsigned position)
{

	// 1. 표준 입출력과 범위 외에 FD 값 제외
	if (fd < 2 || fd >= FDT_SIZE)
		return;
	// 2. 해당되는 파일 갖고 오기
	struct file *file = thread_current()->fd_table[fd];
	if (file == NULL)
		return;
	// 3. file seek() 호출
	lock_acquire(&filesys_lock);
	file_seek(file, position);
	lock_release(&filesys_lock);
}

int sys_tell(int fd)
{
	if (fd < 2 || fd >= FDT_SIZE)
		return -1;

	struct file *file_obj = thread_current()->fd_table[fd];
	if (file_obj == NULL)
		return -1;

	lock_acquire(&filesys_lock);
	unsigned position = file_tell(file_obj);
	lock_release(&filesys_lock);

	return position;
}

int sys_dup2(int oldfd, int newfd)
{
	struct thread *cur = thread_current();

	// 1. fd 유효성 검사
	if (oldfd < 0 || oldfd >= FDT_SIZE || newfd < 0 || newfd >= FDT_SIZE)
		return -1;

	// 2. 자기 자신 복제는 그냥 리턴
	if (oldfd == newfd)
		return newfd;

	struct file *old_file = cur->fd_table[oldfd];
	if (old_file == NULL)
		return -1;

	struct file *new_file = cur->fd_table[newfd];

	// 3. newfd가 이미 열려있다면 닫기 (표준 입출력이 아닐 경우에만)
	if (new_file != NULL)
	{
		if (new_file > (struct file *)2)
		{
			lock_acquire(&filesys_lock); // 파일 조작 시 락 필수
			file_close(new_file);
			lock_release(&filesys_lock);
		}
		cur->fd_table[newfd] = NULL;
	}

	// 4. 복제 수행
	// old_file이 표준 입출력(dummy)인 경우와 실제 파일인 경우 분기
	if (old_file > (struct file *)2)
	{
		lock_acquire(&filesys_lock);
		cur->fd_table[newfd] = file_duplicate_shallow(old_file); // ref_cnt 증가
		lock_release(&filesys_lock);
	}
	else
	{
		// 표준 입출력은 그냥 값만 복사 (ref_cnt 개념 없음)
		cur->fd_table[newfd] = old_file;
	}

	return newfd;
}