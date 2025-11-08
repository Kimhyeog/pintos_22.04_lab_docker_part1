#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

static struct list sleep_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4		  /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);
static int thread_awake_less(const struct list_elem *a,
							 const struct list_elem *b,
							 void *aux);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *)(pg_round_down(rrsp())))

// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = {0, 0x00af9a000000ffff, 0x00cf92000000ffff};

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void thread_init(void)
{
	ASSERT(intr_get_level() == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof(gdt) - 1,
		.address = (uint64_t)gdt};
	lgdt(&gdt_ds);

	/* Init the globla thread context */
	lock_init(&tid_lock);
	list_init(&ready_list);
	list_init(&destruction_req);
	list_init(&sleep_list);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread();
	init_thread(initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void)
{
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init(&idle_started, 0);
	thread_create("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void)
{
	struct thread *t = thread_current();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return();
}

/* Prints thread statistics. */
void thread_print_stats(void)
{
	printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
		   idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t thread_create(const char *name, int priority,
					thread_func *function, void *aux)
{
	struct thread *t;
	tid_t tid;

	ASSERT(function != NULL);

	/* Allocate thread. */
	t = palloc_get_page(PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread(t, name, priority);
	tid = t->tid = allocate_tid();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t)kernel_thread;
	t->tf.R.rdi = (uint64_t)function;
	t->tf.R.rsi = (uint64_t)aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	// ready_list에 새로운 thread 삽입 작업
	thread_unblock(t);

	//
	// 삽입 후 정렬된 후의 ready_list_front_tread 와 CPU 현재 실행중인 thread 우선순위 비교
	// ready_list 앞 thread가 우선순위 더 클떄만 교체
	if (priority > thread_current()->priority)
		thread_yield();

	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void)
{
	ASSERT(!intr_context());
	ASSERT(intr_get_level() == INTR_OFF);
	thread_current()->status = THREAD_BLOCKED;
	schedule();
}

/**
 * @brief 현재 실행 중인 스레드를 잠들게(sleep) 만듭니다.
 * @details 이 함수는 현재 스레드를 'sleep_list'에 깨어날 시간 순서로 정렬 삽입하고,
 * thread_block()을 호출하여 스레드를 차단(Block)시킵니다. 모든 과정은 인터럽트를 끄고
 * (intr_disable) 처리되어 원자성을 보장합니다.
 *
 * @param awake_tick 스레드가 깨어나야 할 절대 시간 (타이머 틱 값).
 *
 * [주요 변수 설명]
 * struct thread *cur: 현재 실행 중인 스레드 ('잠들 주체')
 * enum intr_level old_level: 인터럽트 끄기 전의 원래 상태 (복원용)
 */
void thread_sleep(int64_t awake_tick)
{

	struct thread *cur = thread_current();

	// 인터럽트 끄기
	enum intr_level old_level = intr_disable();

	cur->awake_tick = awake_tick;

	// 'Sleep 리스트'에 'thread_awake_less' 함수를 기준으로 '정렬 삽입'
	list_insert_ordered(&sleep_list, &cur->elem, thread_awake_less, NULL);

	// 잠들기
	thread_block();

	// 깨어난 후 인터럽트 복원
	intr_set_level(old_level);
}

/**
 * @brief 두 스레드를 비교하여 깨어날 시간이 더 빠른 스레드를 결정하는 비교 함수입니다.
 * @details list_insert_ordered()에서 사용되며, 반환 값이 1(True)이면
 * 첫 번째 인자(a)가 두 번째 인자(b)보다 리스트의 앞쪽에 위치하도록 지시합니다.
 * 이 함수 덕분에 'sleep_list'는 깨어날 시간이 빠른 순서대로 정렬됩니다.
 *
 * @param a 비교 대상이 되는 첫 번째 리스트 요소의 포인터.
 * @param b 비교 대상이 되는 두 번째 리스트 요소의 포인터.
 * @param aux 사용되지 않는 보조 인자.
 * * [주요 변수 설명]
 * struct thread *t_a: 리스트 요소 a에 연결된 스레드 구조체.
 * struct thread *t_b: 리스트 요소 b에 연결된 스레드 구조체.
 */
int thread_awake_less(const struct list_elem *a,
					  const struct list_elem *b, void *aux)
{
	struct thread *t_a = list_entry(a, struct thread, elem);
	struct thread *t_b = list_entry(b, struct thread, elem);

	if (t_a->awake_tick < t_b->awake_tick)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

/**
 * @brief 두 스레드의 우선순위를 비교합니다 (내림차순 정렬용).
 * @details list_insert_ordered() 등에 사용되어 우선순위가 높은 스레드가 리스트의 앞쪽에
 * 위치하도록 합니다. 우선순위가 같을 경우 false를 반환하여 기존 요소 뒤에 삽입되므로
 * FIFO 순서가 보장됩니다.
 *
 * @param a 비교할 첫 번째 리스트 요소
 * @param b 비교할 두 번째 리스트 요소
 * @param aux 사용하지 않음 (NULL)
 * @return a의 우선순위가 b보다 높으면 true, 그렇지 않으면 false
 *
 * [사용 예시]
 * 두 스레드의 우선순위 비교 (내림차순 정렬용)
 * 사용 예: list_insert_ordered(&ready_list, &t->elem, cmp_priority, NULL);
 * ready_list에 t를 삽입하되, cmp_priority에 따라 정렬된 위치에 넣음
 */
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
	struct thread *ta = list_entry(a, struct thread, elem);
	struct thread *tb = list_entry(b, struct thread, elem);

	return ta->priority > tb->priority;
}

/**
 * @brief 현재 시스템 시간을 기준으로, 깨어날 시간이 된 모든 스레드를 깨웁니다.
 * @details sleep_list를 순회하며, 스레드의 awake_tick이 current_ticks보다 작거나
 * 같은 경우(즉, 깨어날 시간이 된 경우) 해당 스레드를 sleep_list에서 제거하고
 * ready_list로 이동(thread_unblock)시켜 다시 실행 가능 상태로 만듭니다.
 * sleep_list가 깨어날 시간 순으로 정렬되어 있으므로, 깨어날 시간이 안 된 스레드를
 * 만나면 즉시 루프를 중단하여 효율적입니다.
 *
 * @param current_ticks 현재 타이머의 틱 값 (thread_tick에서 전달).
 *
 * [주요 변수 설명]
 * struct list_elem *e: 현재 확인 중인 sleep_list 요소 (노드).
 * struct thread *t: 리스트 요소 e에 연결된 스레드 구조체.
 */
void thread_wake_up(int64_t current_ticks)
{

	while (!list_empty(&sleep_list))
	{

		struct list_elem *e = list_begin(&sleep_list);
		struct thread *t = list_entry(e, struct thread, elem);

		if (t->awake_tick > current_ticks)
		{
			break;
		}

		list_remove(e);
		thread_unblock(t);
	}
}

/**
 * 역할1 : 함수는 블록(대기) 상태였던 스레드를 깨워 실행 가능한 상태(THREAD_READY) 전환
 * 역할2 : ready_list 넣기
 * 인자 : sleep_list에 들어갈 thread
 * 결과 : 해당 thread를 실행 대기 상태로 전환 및 ready_list로 이동됨
 */

void thread_unblock(struct thread *t)
{
	// 1. CPU Interrupt 상태 보관용 변수
	enum intr_level old_level;

	// 2. ready_list로 옮길 thread가 유효 상태인지 확인
	// ASSERT() : thread가 유효하지 않을 시, 커널 패닉 발생
	ASSERT(is_thread(t));

	// 3. Interrupt 비활성화 및 블록 상태 확인
	old_level = intr_disable();
	ASSERT(t->status == THREAD_BLOCKED);

	// 4. ready_list에 thread t 삽입
	list_insert_ordered(&ready_list, &t->elem, cmp_priority, NULL);

	// 5. thread t 의 실행대기중 상태로 변환
	t->status = THREAD_READY;

	// 6. interrupt 상태 복구
	intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name(void)
{
	return thread_current()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current(void)
{
	struct thread *t = running_thread();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT(is_thread(t));
	ASSERT(t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void)
{
	return thread_current()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void)
{
	ASSERT(!intr_context());

#ifdef USERPROG
	process_exit();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable();
	do_schedule(THREAD_DYING);
	NOT_REACHED();
}

/**
 * 역할1 : CPU에서 실행중인 thread 포기 r
 * 역할2 : readylist의 맨 앞 thread를 꺼내서, 실행
 * 역할3 : readylist에서 꺼낸 thread CPU에 장착
 * 역할4 : Context Switching 작업
 * 인자 : X
 * 결과 : CP
 */
void thread_yield(void)
{
	// 1.현재 CPU에서 실행중인 thread 갖고오기
	struct thread *cur = thread_current();

	// 2. Interrupt 상태 임시 보관 변수 선언
	enum intr_level old_level;

	// 3. Interrupt에 의해서 발생된 함수가 아니라는 걸 커널에게 알리는 코드
	ASSERT(!intr_context());

	// 4. interrupt 비활성화
	old_level = intr_disable();

	// 5. 현재 CPU가 실행중인 thread가 idle_thread가 아닐시에만 , ready_list에 삽입
	if (cur != idle_thread)
		list_insert_ordered(&ready_list, &cur->elem, cmp_priority, NULL);

	// 6. context Switch : CPU와 ready_list에서 꺼낸 thread 상태 서로 업데이트
	do_schedule(THREAD_READY);
	// 7. interrupt 상태 복구 -> intr_set_level()
	intr_set_level(old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void thread_set_priority(int new_priority)
{
	thread_current()->priority = new_priority;
	// ready_list가 비어있지 않고, 맨 앞 스레드가 나보다 우선순위가 높으면 양보
	if (!list_empty(&ready_list) &&
		list_entry(list_begin(&ready_list), struct thread, elem)->priority > new_priority)
	{
		thread_yield();
	}
}

/* Returns the current thread's priority. */
int thread_get_priority(void)
{
	return thread_current()->priority;
}

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice UNUSED)
{
	/* TODO: Your implementation goes here */
}

/* Returns the current thread's nice value. */
int thread_get_nice(void)
{
	/* TODO: Your implementation goes here */
	return 0;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void)
{
	/* TODO: Your implementation goes here */
	return 0;
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void)
{
	/* TODO: Your implementation goes here */
	return 0;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle(void *idle_started_ UNUSED)
{
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current();
	sema_up(idle_started);

	for (;;)
	{
		/* Let someone else run. */
		intr_disable();
		thread_block();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread(thread_func *function, void *aux)
{
	ASSERT(function != NULL);

	intr_enable(); /* The scheduler runs with interrupts off. */
	function(aux); /* Execute the thread function. */
	thread_exit(); /* If function() returns, kill the thread. */
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread(struct thread *t, const char *name, int priority)
{
	ASSERT(t != NULL);
	ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT(name != NULL);

	memset(t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy(t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t)t + PGSIZE - sizeof(void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;
	t->awake_tick = 0;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run(void)
{
	if (list_empty(&ready_list))
		return idle_thread;
	else
		return list_entry(list_pop_front(&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void do_iret(struct intr_frame *tf)
{
	__asm __volatile(
		"movq %0, %%rsp\n"
		"movq 0(%%rsp),%%r15\n"
		"movq 8(%%rsp),%%r14\n"
		"movq 16(%%rsp),%%r13\n"
		"movq 24(%%rsp),%%r12\n"
		"movq 32(%%rsp),%%r11\n"
		"movq 40(%%rsp),%%r10\n"
		"movq 48(%%rsp),%%r9\n"
		"movq 56(%%rsp),%%r8\n"
		"movq 64(%%rsp),%%rsi\n"
		"movq 72(%%rsp),%%rdi\n"
		"movq 80(%%rsp),%%rbp\n"
		"movq 88(%%rsp),%%rdx\n"
		"movq 96(%%rsp),%%rcx\n"
		"movq 104(%%rsp),%%rbx\n"
		"movq 112(%%rsp),%%rax\n"
		"addq $120,%%rsp\n"
		"movw 8(%%rsp),%%ds\n"
		"movw (%%rsp),%%es\n"
		"addq $32, %%rsp\n"
		"iretq"
		: : "g"((uint64_t)tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch(struct thread *th)
{
	uint64_t tf_cur = (uint64_t)&running_thread()->tf;
	uint64_t tf = (uint64_t)&th->tf;
	ASSERT(intr_get_level() == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile(
		/* Store registers that will be used. */
		"push %%rax\n"
		"push %%rbx\n"
		"push %%rcx\n"
		/* Fetch input once */
		"movq %0, %%rax\n"
		"movq %1, %%rcx\n"
		"movq %%r15, 0(%%rax)\n"
		"movq %%r14, 8(%%rax)\n"
		"movq %%r13, 16(%%rax)\n"
		"movq %%r12, 24(%%rax)\n"
		"movq %%r11, 32(%%rax)\n"
		"movq %%r10, 40(%%rax)\n"
		"movq %%r9, 48(%%rax)\n"
		"movq %%r8, 56(%%rax)\n"
		"movq %%rsi, 64(%%rax)\n"
		"movq %%rdi, 72(%%rax)\n"
		"movq %%rbp, 80(%%rax)\n"
		"movq %%rdx, 88(%%rax)\n"
		"pop %%rbx\n" // Saved rcx
		"movq %%rbx, 96(%%rax)\n"
		"pop %%rbx\n" // Saved rbx
		"movq %%rbx, 104(%%rax)\n"
		"pop %%rbx\n" // Saved rax
		"movq %%rbx, 112(%%rax)\n"
		"addq $120, %%rax\n"
		"movw %%es, (%%rax)\n"
		"movw %%ds, 8(%%rax)\n"
		"addq $32, %%rax\n"
		"call __next\n" // read the current rip.
		"__next:\n"
		"pop %%rbx\n"
		"addq $(out_iret -  __next), %%rbx\n"
		"movq %%rbx, 0(%%rax)\n" // rip
		"movw %%cs, 8(%%rax)\n"	 // cs
		"pushfq\n"
		"popq %%rbx\n"
		"mov %%rbx, 16(%%rax)\n" // eflags
		"mov %%rsp, 24(%%rax)\n" // rsp
		"movw %%ss, 32(%%rax)\n"
		"mov %%rcx, %%rdi\n"
		"call do_iret\n"
		"out_iret:\n"
		: : "g"(tf_cur), "g"(tf) : "memory");
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status)
{
	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(thread_current()->status == THREAD_RUNNING);
	while (!list_empty(&destruction_req))
	{
		struct thread *victim =
			list_entry(list_pop_front(&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current()->status = status;
	schedule();
}

static void
schedule(void)
{
	struct thread *curr = running_thread();
	struct thread *next = next_thread_to_run();

	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(curr->status != THREAD_RUNNING);
	ASSERT(is_thread(next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate(next);
#endif

	if (curr != next)
	{
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread)
		{
			ASSERT(curr != next);
			list_push_back(&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch(next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid(void)
{
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire(&tid_lock);
	tid = next_tid++;
	lock_release(&tid_lock);

	return tid;
}
/**
 * @brief 현재 실행 중인 스레드와 ready_list의 가장 높은 우선순위 스레드를 비교하여
 * 선점이 필요하면 intr_yield_on_return()을 호출합니다.
 */
void thread_test_preemption(void)
{
	// 1. ready_list 비어있다면, 검사 안해도됨
	if (!list_empty(&ready_list))
	{
		// 2. ready_list의 맨 앞 thread 꺼내기 -> list_entry
		struct thread *front_thread = list_entry(list_begin(&ready_list), struct thread, elem);

		// 3. 교체 검사
		if (front_thread->priority > thread_current()->priority)
			intr_yield_on_return(); // 인터럽트 종료 후에 교체되도록 예약 함수
	}
}
