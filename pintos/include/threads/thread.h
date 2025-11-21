#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/synch.h" // sema 사용을 위해
#include "filesys/file.h"  // file 구조체 사용을 위해
#ifdef VM
#include "vm/vm.h"
#endif

typedef int fixed_t;

// 파일 디스크립터 테이블
#define FDT_SIZE 128

#define F (1 << 14)

/* Convert integer to fixed point */
#define INT_TO_FP(n) ((n) * F)

/* Convert fixed point to integer (truncate) */
#define FP_TO_INT(x) ((x) / F)

/* Convert fixed point to integer (round to nearest) */
#define FP_TO_INT_ROUND(x) ((x) >= 0 ? ((x) + F / 2) / F : ((x) - F / 2) / F)

/* Add fixed + fixed */
#define FP_ADD(x, y) ((x) + (y))

/* Add fixed + int */
#define FP_ADD_INT(x, n) ((x) + (n) * F)

/* Sub fixed - fixed */
#define FP_SUB(x, y) ((x) - (y))

/* Sub fixed - int */
#define FP_SUB_INT(x, n) ((x) - (n) * F)

/* Mul fixed * fixed */
#define FP_MUL(x, y) ((fixed_t)(((int64_t)(x)) * (y) / F))

/* Mul fixed * int */
#define FP_MUL_INT(x, n) ((x) * (n))

/* Div fixed / fixed */
#define FP_DIV(x, y) ((fixed_t)(((int64_t)(x)) * F / (y)))

/* Div fixed / int */
#define FP_DIV_INT(x, n) ((x) / (n))
#define FP_DIV_INT_ZERO(x, n) ((n) == 0 ? 0 : (x) / (n))

/* States in a thread's life cycle. */
enum thread_status
{
	THREAD_RUNNING, /* Running thread. */
	THREAD_READY,	/* Not running but ready to run. */
	THREAD_BLOCKED, /* Waiting for an event to trigger. */
	THREAD_DYING	/* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) - 1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0	   /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63	   /* Highest priority. */

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread
{
	/* Owned by thread.c. */
	tid_t tid;				   /* Thread identifier. */
	enum thread_status status; /* Thread state. */
	char name[16];			   /* Name (for debugging purposes). */
	int priority;			   /* Priority. */

	/* Shared between thread.c and synch.c. */
	struct list_elem elem; /* List element. */

	// timer 기능
	int64_t awake_tick;

	// 기부 전용 명찰
	struct list_elem donation_elem;

	// 기부자들
	struct list donations;

	// 원래 우선순위
	int original_priority;

	// 어떤 락을 기다리고있는지 처음에는 NULL
	struct lock *waiting_on;

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4; /* Page map level 4 */
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;	  /* Information for switching */
	unsigned magic;			  /* Detects stack overflow. */
	int nice;				  /* MLFQS nice 값 */
	fixed_t recent_cpu;		  /* 최근 CPU 사용량 */
	struct list_elem allelem; /* 모든 스레드 리스트용 */

	struct file **fd_table;

	// 1. 프로세스 종료 상태 저장
	int exit_status;

	// 2. 자식 프로세스 생성 동기화 (fork)
	struct semaphore fork_sema;

	// 3. 자식 프로세스 종료 대기 (wait)
	struct semaphore wait_sema;
	// [추가] 자식 메모리 해제 대기용 (부모가 허락해줄 때까지 대기)
	struct semaphore free_sema;

	// 4. 자식 프로세스 목록 관리
	struct list child_list;
	struct list_elem child_elem;

	// 5. 현재 실행 중인 파일
	// 프로세스가 실행되는 동안에는 해당 실행 파일에 대한 쓰기(Write)를 막기용
	struct file *running_file;

	// 6. 부모 프로세스의 인터럽트 프레임 (fork 시 사용)
	struct intr_frame parent_if;

	int fd_idx;
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

void do_iret(struct intr_frame *tf);

void thread_check_sleepers(int64_t current_ticks);

void thread_sleep(int64_t awake_tick);
void thread_wake_up(int64_t current_ticks);

void thread_check_sleepers(int64_t current_ticks);

void thread_sleep(int64_t awake_tick);
void thread_wake_up(int64_t current_ticks);
int priority_less(const struct list_elem *a,
				  const struct list_elem *b, void *aux);

#endif /* threads/thread.h */
