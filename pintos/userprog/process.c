#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);
/* (헬퍼 함수) tid에 해당하는 자식 스레드 구조체를 찾는 함수 */
static struct thread *get_child_process(tid_t tid);

/* General process initializer for initd and other process. */
static void process_init(void)
{
	struct thread *current = thread_current();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *file_name)
{

	char *fn_copy;

	tid_t tid;

	/* 1. fn_copy 할당 및 file_name 복사 : initd 홤수로 넘겨줄 보조용 */

	fn_copy = palloc_get_page(0);

	if (fn_copy == NULL)

		return TID_ERROR;

	strlcpy(fn_copy, file_name, PGSIZE);

	/* 2. thread_name_copy 할당 및 복사*/

	char *thread_name = palloc_get_page(0);

	if (thread_name == NULL)
	{
		palloc_free_page(fn_copy);
		return TID_ERROR;
	}

	strlcpy(thread_name, file_name, PGSIZE);

	/* 3. thread_name_copy */

	char *save_ptr;

	char *thread_real_name = strtok_r(thread_name, " ", &save_ptr);

	tid = thread_create(thread_real_name, PRI_DEFAULT, initd, fn_copy);

	/* 4. thread_name_copy 해제 */

	palloc_free_page(thread_name);

	if (tid == TID_ERROR)

		palloc_free_page(fn_copy);

	return tid;
}

/* A thread function that launches first user process. */
static void
initd(void *f_name)
{
#ifdef VM
	supplemental_page_table_init(&thread_current()->spt);
#endif

	process_init();

	if (process_exec(f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED)
{

	struct thread *cur = thread_current();

	// 부모의 IF를 구조체에 백업 (자식이 가져갈 수 있도록)
	memcpy(&cur->parent_if, if_, sizeof(struct intr_frame));

	// 4번째 인자로 if_가 아니라 'cur'(부모 스레드 포인터)를 넘겨야 함!
	tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, cur);

	if (tid == TID_ERROR)
		return TID_ERROR;

	// 자식 스레드 구조체 찾기 (직접 구현 필요)
	struct thread *child = get_child_process(tid);

	if (child == NULL)
		return TID_ERROR;

	// 부모 thread 재우기
	sema_down(&child->fork_sema);

	/* 자식 새끼 생성 된 후. 장애인인지 정상 애새끼인지 판정 */

	if (child->exit_status == TID_ERROR)
		return TID_ERROR;

	return tid;
}

static struct thread *get_child_process(tid_t tid)
{
	struct thread *parent = thread_current();
	struct list_elem *e;

	for (e = list_begin(&parent->child_list); e != list_end(&parent->child_list); e = list_next(e))
	{
		// list_entry() 마지막 인자 : 그 구조체 안의 멤버 이름
		struct thread *t = list_entry(e, struct thread, child_elem);

		if (t->tid == tid)
		{
			return t; // 찾았으면 해당 스레드 포인터 반환
		}
	}

	return NULL;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
// pte : 부모 thread의 Page table Entry , 쓰기 가능한지(W bit), 유저 모드 접근 가능한지(U bit) 등의 정보
// va : pte를 가리키는 가상 주소 ,자식 프로세스에게 **"어느 주소"**에 메모리를 매핑해 줄지 알려주는 좌표
// aux : 부모 스레드의 포인터
static bool duplicate_pte(uint64_t *pte, void *va, void *aux)
{
	struct thread *current = thread_current();
	struct thread *parent = (struct thread *)aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. 만약 커널 주소라면 복사하지 않고 그냥 성공(true) 반환 */
	if (is_kernel_vaddr(va))
		return true;

	/* 2. 부모의 가상 주소(va)에 매핑된 물리 주소 가져오기 (원본 데이터 위치) */
	parent_page = pml4_get_page(parent->pml4, va);
	if (parent_page == NULL)
		return false; // 뭔가 잘못됨 (유효한 PTE인데 물리 주소가 없다면)

	/* 3. 자식을 위한 새 물리 페이지 할당 (새로운 그릇) */
	newpage = palloc_get_page(PAL_USER);
	if (newpage == NULL)
		return false; // 메모리 부족 등으로 실패

	/* 4. 내용 복사 */
	memcpy(newpage, parent_page, PGSIZE);

	// 4-1. 쓰기 가능 여부 확인 (부모의 PTE에서 권한 비트 확인)
	// (*pte) 값에서 PTE_W 비트가 1인지 확인
	writable = is_writable(pte);

	/* 5. 자식의 페이지 테이블에 "이 가상 주소(va)는 저 새 물리 주소(newpage)다"라고 등록 */
	if (!pml4_set_page(current->pml4, va, newpage, writable))
	{
		/* 6. 매핑 실패 시 할당받은 메모리 반납 */
		palloc_free_page(newpage);
		return false;
	}

	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void __do_fork(void *aux)
{
	struct intr_frame if_;
	struct thread *parent = (struct thread *)aux; // 이제 aux는 진짜 부모 스레드임
	struct thread *current = thread_current();

	// 1. 부모의 parent_if 멤버 포인터 추출 및 자식에게 전달용 f에 parent_if 복사
	struct intr_frame *parent_if = &parent->parent_if;
	memcpy(&if_, parent_if, sizeof(struct intr_frame)); // 복사

	// 2. 복사 성공용 bool success ture
	bool succ = true;

	// 3. 자식 새끼의 rax에 0 저장 (정상적인 child 성공)
	if_.R.rax = 0;

	/* 4. 자식의 페이지 테이블 생성 및 활설화 */

	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate(current);

#ifdef VM
	supplemental_page_table_init(&current->spt);
	if (!supplemental_page_table_copy(&current->spt, &parent->spt))
		goto error;
#else
	// 부모의 페이지 테이블을 뒤지면서, 유효한 유저영역 Entry둘울 duplicate_pte()로 복사
	if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
		goto error;
#endif
	// 5. 부모의 FDT 복사 과정
	for (int fd = 2; fd < FDT_SIZE; fd++)
	{
		struct file *file_obj = parent->fd_table[fd];
		if (file_obj != NULL)
		{
			// file_duplicate: 파일 객체를 복제하고 open count를 증가시킴
			// (주의: 단순히 포인터만 복사하면 한쪽이 close할 때 문제 발생)
			lock_acquire(&filesys_lock);
			struct file *dup_file = file_duplicate(file_obj);
			lock_release(&filesys_lock);
			if (dup_file == NULL)
				goto error;

			/* 자식의 FDT에 복제된 파일 할당 */
			current->fd_table[fd] = dup_file;
		}
	}

	// process_init();

	/* Finally, switch to the newly created process. */
	if (succ)
	{
		// 자식새끼의 sema 반납으로 부모 깨우기
		sema_up(&current->fork_sema);

		// 자식새끼 유저모드로 변경
		do_iret(&if_);
	}
error:
	// 정상적으로 자식 못만들었을 시,
	// 자식 상태 코드 , 부모 꺠우긴 해야함 , 자식새끼 종료
	current->exit_status = TID_ERROR;
	sema_up(&current->fork_sema);
	thread_exit();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
// 기존 프로그램을 메모리, 코드, 스택을 변경하는 과정
int process_exec(void *f_name)
{
	char *file_name = f_name;
	bool success;

	// 1. 파일 이름만 파싱 작업
	char *fn_copy = palloc_get_page(PAL_ZERO);
	if (fn_copy == NULL)
		return -1;

	strlcpy(fn_copy, file_name, PGSIZE);

	char *save_ptr;
	char *prog_name = strtok_r(fn_copy, " ", &save_ptr);

	// 2. 파싱한 파일명으로 파일 열기
	lock_acquire(&filesys_lock);
	struct file *file_obj = filesys_open(prog_name);
	lock_release(&filesys_lock);

	// 3-1. 해당 파일이 없을 시,
	if (file_obj == NULL)
	{
		printf("load: %s: open failed\n", file_name);
		// 복사해놨던 파일 이름 free
		palloc_free_page(fn_copy);
		// 명령어도 free
		palloc_free_page(f_name);

		// // 현재 thread 종료 상태 오류로 변경
		// thread_current()->status = -1;
		thread_current()->exit_status = -1;

		// // thread 종료
		thread_exit();

		return -1;
	}

	// 3-2. 해당 파일이 있을 시,
	// 파일 있는거 확인 했으므로, 닫기
	lock_acquire(&filesys_lock);
	file_close(file_obj);
	lock_release(&filesys_lock);

	// 복사해 놨던 fn_copy page 해제
	palloc_free_page(fn_copy);

	// 4. 현재 thread의 청소
	// Intr_frame 청소
	// process 청소

	// 기존 현재 스레드의 메모리를 다 날려버릴 것이기 때문에 지역변수로 선언
	struct intr_frame _if;
	/* ds, es, ss: 데이터 세그먼트 (유저 데이터 영역 SEL_UDSEG) */
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	/* cs: 코드 세그먼트 (유저 코드 영역 SEL_UCSEG) */
	_if.cs = SEL_UCSEG;
	/* eflags: 인터럽트 허용 플래그 */
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	/*현재 프로세스의 페이지 테이블(pml4)을 지우기 */
	process_cleanup();

	// 5. 해당 파일로 실행 loac함수 호출
	/* And then load the binary */
	/*file_name 실행 파일을 읽어 메모리에 올린다.*/
	success = load(file_name, &_if);

	/* If load failed, quit. */
	/*새 프로그램의 시작점 정보가 담깁 , 실패시 오류 처리*/
	if (!success)
	{
		palloc_free_page(file_name);
		thread_current()->exit_status = -1; // (O) 실패 흔적 남기고
		thread_exit();
	}
	palloc_free_page(file_name);

	/* Start switched process. */
	/* Context Switching*/
	do_iret(&_if);
	/* do_iret이 성공하면 이 줄은 절대 실행되지 않습니다.*/
	NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */

// 현제 호출중인 thread는 부모 thread
int process_wait(tid_t tid)
{
	// 1. 현재 thread(부모) wait을 요청할 자식 tid로 자식 thread 찾기
	struct thread *child = get_child_process(tid);
	if (child == NULL)
		return -1;

	// 2. 부모 thread를 재우기 == wait_sema 챙기기 -> 그떄동안 child thread를 종료 시키기
	sema_down(&child->wait_sema);

	// 3. 자식 thread의 exit_status를 뽑기
	int status = child->exit_status;

	// 4. 해당 child를 현재 thread의 자식 리스트에서 제거
	list_remove(&child->child_elem);

	// 5. 해당 부모 thread의 fork_sema 반납 : child의 유언 듣기 전까지는 죽지 않도록 하기
	// 부모가 sema_up(&free_sema)를 하여, 1이 증가되고, 그떄 지혼자 감옥으로 간
	// 자식이 wait_;ist에서 나와 뒤짐
	sema_up(&child->free_sema);

	return status;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void)
{
	struct thread *cur = thread_current();

	lock_acquire(&filesys_lock);

	if (cur->pml4 != NULL)
	{
		printf("%s: exit(%d)\n", cur->name, cur->exit_status);
	}

	if (cur->fd_table != NULL)
	{
		for (int fd = 0; fd < FDT_SIZE; fd++)
			if (cur->fd_table[fd] != NULL)
			{
				file_close(cur->fd_table[fd]);
				cur->fd_table[fd] = NULL;
			}

		palloc_free_page(cur->fd_table);
		cur->fd_table = NULL;
	}

	struct list_elem *e;

	for (
		e = list_begin(&cur->child_list);
		e != list_end(&cur->child_list);
		e = list_next(e))
	{
		struct thread *child = list_entry(e, struct thread, child_elem);
		sema_up(&child->free_sema);
	}

	// running file 닫기
	if (cur->running_file != NULL)
	{
		file_close(cur->running_file);
		cur->running_file = NULL;
	}

	lock_release(&filesys_lock);

	process_cleanup();

	sema_up(&cur->wait_sema);
	sema_down(&cur->free_sema);

	// thread_exit();
}

/* Free the current process's resources. */
static void process_cleanup(void)
{
	struct thread *curr = thread_current();

#ifdef VM
	supplemental_page_table_kill(&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL)
	{
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate(NULL);
		pml4_destroy(pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next)
{
	/* Activate thread's page tables. */
	pml4_activate(next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update(next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0			/* Ignore. */
#define PT_LOAD 1			/* Loadable segment. */
#define PT_DYNAMIC 2		/* Dynamic linking info. */
#define PT_INTERP 3			/* Name of dynamic loader. */
#define PT_NOTE 4			/* Auxiliary info. */
#define PT_SHLIB 5			/* Reserved. */
#define PT_PHDR 6			/* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr
{
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR
{
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
						 uint32_t read_bytes, uint32_t zero_bytes,
						 bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load(const char *file_name, struct intr_frame *if_)
{
	struct thread *t = thread_current();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* [수정 1] 스택 오버플로우 방지를 위해 힙에 할당 */
	/* argv용 포인터 배열과 argv_addr용 포인터 배열을 담을 페이지 할당 */
	/* 4KB 페이지 하나면 (128 * 8) * 2 = 2KB니까 충분함 */
	char **argv = palloc_get_page(0);
	if (argv == NULL)
		return false;

	// argv_addr은 페이지의 절반 지점부터 사용 (포인터 연산)
	char **argv_addr = argv + 128;

	// (1). 수정본 복제
	char *fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
		goto done;
	strlcpy(fn_copy, file_name, PGSIZE);

	// (2). 파싱 작업
	// char *argv[128];  <-- [삭제] 이거 때문에 스택 터짐
	int argc = 0;
	char *token, *save_ptr;
	for (
		token = strtok_r(fn_copy, " ", &save_ptr);
		token != NULL;
		token = strtok_r(NULL, " ", &save_ptr))
	{
		argv[argc++] = token;
		if (argc >= 128)
			break;
	}
	// 빈명령어 처리
	if (argc == 0)
		goto done;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create();
	if (t->pml4 == NULL)
		goto done;
	process_activate(thread_current());

	/* Open executable file. */
	lock_acquire(&filesys_lock);
	file = filesys_open(argv[0]);
	if (file == NULL)
	{
		printf("load: %s: open failed\n", file_name);
		goto done;
	}

	/* ... (ELF 헤더 읽기 및 검증 코드는 그대로 유지) ... */
	/* Read and verify executable header. */
	if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 0x3E // amd64
		|| ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024)
	{
		printf("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++)
	{
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length(file))
			goto done;
		file_seek(file, file_ofs);

		if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type)
		{
		// ... (Switch 문 내부 코드는 기존과 동일) ...
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment(&phdr, file))
			{
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint64_t file_page = phdr.p_offset & ~PGMASK;
				uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint64_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0)
				{
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
				}
				else
				{
					read_bytes = 0;
					zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
				}
				if (!load_segment(file, file_page, (void *)mem_page,
								  read_bytes, zero_bytes, writable))
					goto done;
			}
			else
				goto done;
			break;
		}
	}

	/* Set up stack. */
	if (!setup_stack(if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* Argument Passing */
	// char *argv_addr[128]; <-- [삭제] 이것도 스택 터짐

	for (int i = argc - 1; i >= 0; i--)
	{
		size_t len = strlen(argv[i]) + 1;
		if_->rsp -= len;
		memcpy((void *)if_->rsp, argv[i], len);
		argv_addr[i] = (char *)if_->rsp; // [수정] 힙에 할당된 배열 사용
	}

	// Padding
	if_->rsp = (uintptr_t)if_->rsp & ~0x7;

	// NULL pointer
	if_->rsp -= 8;
	*(uint64_t *)if_->rsp = 0;

	// 주소값 PUSH
	for (int i = argc - 1; i >= 0; i--)
	{
		if_->rsp -= 8;
		memcpy((void *)if_->rsp, &argv_addr[i], sizeof(char *));
	}

	// Return Address
	if_->R.rdi = argc;
	if_->R.rsi = if_->rsp;

	if_->rsp -= 8;
	*(uint64_t *)if_->rsp = 0;

	success = true;

done:
	/* We arrive here whether the load is successful or not. */

	if (argv != NULL)
		palloc_free_page(argv);

	if (fn_copy != NULL)
		palloc_free_page(fn_copy);

	/* [이전에 수정한 부분 유지] */
	if (success)
	{
		t->running_file = file;
		file_deny_write(file);
	}
	else
	{
		file_close(file);
	}
	lock_release(&filesys_lock);

	return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Phdr *phdr, struct file *file)
{
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t)file_length(file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr((void *)phdr->p_vaddr))
		return false;
	if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	file_seek(file, ofs);
	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page(PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
		{
			palloc_free_page(kpage);
			return false;
		}
		memset(kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page(upage, kpage, writable))
		{
			printf("fail\n");
			palloc_free_page(kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack(struct intr_frame *if_)
{
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if (kpage != NULL)
	{
		success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page(kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment(struct page *page, void *aux)
{
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
			 uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT(pg_ofs(upage) == 0);
	ASSERT(ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0)
	{
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer(VM_ANON, upage,
											writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack(struct intr_frame *if_)
{
	bool success = false;
	void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
