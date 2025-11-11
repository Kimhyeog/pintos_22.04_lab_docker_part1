/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) {
	ASSERT (sema != NULL);

	sema->value = value;
	list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void
sema_down (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);
	ASSERT (!intr_context ());

	old_level = intr_disable ();


	while (sema->value == 0) {
      list_insert_ordered(&sema->waiters, &thread_current()->elem, thread_priority_less ,NULL);
      thread_block ();
   }
   sema->value--;
	intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) {
	enum intr_level old_level;
	bool success;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level (old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
/* threads/synch.c */

void
sema_up (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);
   
	old_level = intr_disable ();
   sema->value++; // 임계 구역 안으로

   if (!list_empty (&sema->waiters))
   {
      struct list_elem *max_elem = list_begin(&sema->waiters); // front
      struct thread *max_thread = list_entry(max_elem, struct thread, elem);

      struct list_elem *e;
      for (e = list_next(max_elem); e != list_end(&sema->waiters); e = list_next(e)) // front를 기준으로 탐색
      {
         struct thread *t = list_entry(e, struct thread, elem);
         if (t->priority > max_thread->priority) {
               max_thread = t;
               max_elem = e;
         }
      }
      list_remove(max_elem);
      thread_unblock(max_thread);
   }
	intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
	struct semaphore sema[2];
	int i;

	printf ("Testing semaphores...");
	sema_init (&sema[0], 0);
	sema_init (&sema[1], 0);
	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up (&sema[0]);
		sema_down (&sema[1]);
	}
	printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down (&sema[0]);
		sema_up (&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock) {
	ASSERT (lock != NULL);

	lock->holder = NULL;
	sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */

void update_holder_priority(struct thread *holder){
   int max_priority = holder->base_priority;
   if (!list_empty(&holder->donations))
   {
      struct list_elem *front_elem = list_front(&holder->donations);
      struct thread *highest_donor =  list_entry(front_elem, struct thread, donation_elem);

      if (highest_donor->priority > max_priority){ //기증자중 가장 큰놈과 비교
         max_priority = highest_donor->priority;
      }
   }
   holder->priority = max_priority; // 최종 아웃풋
}

void remove_my_donation(struct lock *lock){
   struct thread *holder = thread_current();
   struct list *donations_list = &holder->donations;
   struct list_elem *e=list_begin(donations_list); //순회 하기 위한 임시 포인터
   while (e != list_end(donations_list))
   {
      struct thread *donor = list_entry(e, struct thread, donation_elem); // 그 순회하고 있는 이름표의 쓰레드
      if (donor->waiting_on == lock)
         e = list_remove(e);
      else
         e = list_next(e); // 다음 탐색
   }
}

bool donate_priority_less (const struct list_elem *a,
                   const struct list_elem *b, void *aux) {
	struct thread *t_a = list_entry (a, struct thread, donation_elem);
	struct thread *t_b = list_entry (b, struct thread, donation_elem);
	return (t_a->priority > t_b->priority); 
}

void
lock_acquire (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));
	enum intr_level old_level = intr_disable ();
   
   if (lock->holder != NULL) 
   {
      thread_current()->waiting_on = lock; // 어떤 락을 기다리는지
      list_insert_ordered(&lock->holder->donations, &thread_current()->donation_elem, donate_priority_less, NULL); //holder 쓰레드의 대기열에 추가
      // update_holder_priority(lock->holder); // holder의 우선 순위를 재계산 (기부)
      struct thread *holder = lock->holder;
      while (holder)
      {
         update_holder_priority(holder); // 홀더의 우선순위 계산
         if (holder->waiting_on)
            holder = holder->waiting_on->holder;
         else
            break; // 기다리는 락 없으면 전파 중지
      }
   }
   sema_down(&lock->semaphore); // 대기 P 연산(While) 여기서는 sema->waiter에 대기열로 추가 elem으로
   
   // 획득 후
   thread_current()->waiting_on = NULL;
   lock->holder = thread_current ();

   intr_set_level(old_level); // 임계 구역 종료
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock) {
	bool success;

	ASSERT (lock != NULL);
	ASSERT (!lock_held_by_current_thread (lock));

	success = sema_try_down (&lock->semaphore);
	if (success)
		lock->holder = thread_current ();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (lock_held_by_current_thread (lock));

   enum intr_level old_level = intr_disable();
   
   remove_my_donation(lock); // 기부자 정리
   update_holder_priority(lock->holder); // 우선순위 계산
   
	lock->holder = NULL; // 소유권 포기
	sema_up (&lock->semaphore); // 다음 놈 깨우기
   intr_set_level (old_level);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
	ASSERT (lock != NULL);

	return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem {
	struct list_elem elem;              /* List element. */
	struct semaphore semaphore;         /* This semaphore. */
	int priority;
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
	ASSERT (cond != NULL);

	list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */

static bool
cond_waiter_less (const struct list_elem *a,const struct list_elem *b, void *aux UNUSED)
{
    struct semaphore_elem *waiter_a = list_entry(a, struct semaphore_elem, elem);
    struct semaphore_elem *waiter_b = list_entry(b, struct semaphore_elem, elem);

    /* 2. 티켓에 '복사된' priority를 비교 */
    return waiter_a->priority > waiter_b->priority;
}
void
cond_wait (struct condition *cond, struct lock *lock) 
{
    struct semaphore_elem waiter; //알람 벨

    ASSERT (cond != NULL);
    ASSERT (lock != NULL); 
    ASSERT (!intr_context ());
    ASSERT (lock_held_by_current_thread (lock)); // lock 들고있는거 확인했어

    sema_init (&waiter.semaphore, 0);
    waiter.priority = thread_current ()->priority; // 티켓에 우선순위 복사
    list_insert_ordered (&cond->waiters, &waiter.elem, cond_waiter_less, NULL);

    lock_release (lock); // 락을 푼다 -> sema up
    sema_down (&waiter.semaphore); // 초인종
    lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	if (!list_empty (&cond->waiters))
		sema_up (&list_entry (list_pop_front (&cond->waiters),
					struct semaphore_elem, elem)->semaphore);
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters))
		cond_signal (cond, lock);
}
