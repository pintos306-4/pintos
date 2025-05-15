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
		list_insert_ordered (&sema->waiters, &thread_current()->elem,priority_less_func,NULL);
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
void
sema_up (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	/* 1) 먼저 세마포어 값을 올려서, 다음 down 재진입 시 value > 0 조건이 만족되도록 한다. */
	sema->value++;
	 /* 2) 대기 리스트에서 가장 높은 우선순위 스레드를 깨운다. */
	if (!list_empty (&sema->waiters)){
		list_sort(&sema->waiters,priority_less_func,NULL);		// 쓰레드의 우선순위가 변경될 경우에 대비해서 정렬
		thread_unblock (list_entry (list_pop_front (&sema->waiters),
					struct thread, elem));
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

/* LOCK을 획득한다. 필요하다면 LOCK이 사용 가능해질 때까지 잠든다.  
이때, 현재 스레드가 이미 해당 LOCK을 보유하고 있어서는 안 된다.

이 함수는 잠들 수 있기 때문에, **인터럽트 핸들러 내에서 호출되어서는 안 된다.**  
인터럽트가 비활성화된 상태에서 호출될 수는 있지만,  
잠들어야 하는 상황이라면 인터럽트는 자동으로 다시 활성화된다.. */
void
lock_acquire (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));

	//여기에 우선순위를 기부해야한다.  
	if(	lock->semaphore.value==0){	//누군가가 락을 보유하고 있다는 뜻
		// cpu를 실행하고 있는 쓰레드의 우선순위가 락을 소유하고 있는 쓰레드의 우선순위보다 크면
		if(lock->holder->priority < thread_current()->priority){	
			lock->holder->origin_priority = lock->holder->priority; // 기존 우선순위를 저장하고
			lock->holder->priority = thread_current()->priority; 	// 우선순위 기부하기
			lock->holder->is_donated = true;						// 기부받았다고 체크하기
		}
	}

	sema_down (&lock->semaphore);
	lock->holder = thread_current ();
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

/* 현재 스레드가 소유하고 있는 LOCK을 해제한다.
   이 함수는 lock_release 함수이다.

   인터럽트 핸들러는 락을 획득할 수 없기 때문에,
   인터럽트 핸들러 내에서 락을 해제하려고 시도하는 것은 의미가 없다 */
void
lock_release (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (lock_held_by_current_thread (lock));

	//현재 실행중인애가 락을 갖고있음(즉 curr랑 lock->holder랑 같음)
	struct thread *curr = thread_current(); 

	// 우선순위 복구 해주기-> 왜냐면 락을 풀면 쓰레드는 종료되는 것이 아니라 다른 자원에 다시 접근할 수 도 있다. 
	// 이때 복구를 해주지 않으면 다른자원에서의 스케줄링이 망가지기때문에 이전 우선순위를 저장하고 복구를 해줘야한다.  
	if(curr->is_donated){		
		curr->is_donated=false;
		curr->priority = curr->origin_priority;
	}

	lock->holder = NULL;				// 락 소유자를 null로
	sema_up (&lock->semaphore);			// 대기 중인 스레드가 있다면 우선순위가 가장 높은 스레드를 깨우기
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

   /*  조건 변수 대기 리스트(cond->waiters)를 정렬할 때 사용하는 비교 함수입니다.
   각 리스트 요소는 struct semaphore_elem이며, 그 내부의 semaphore.waiters 리스트에
   실제 대기 중인 thread가 들어 있습니다.

   우선순위는 semaphore.waiters 리스트에 대기 중인 스레드들 중 가장 앞에 있는 스레드의
   priority로 비교합니다. 하지만 아래 주의사항이 있습니다.

   📌 주의: 이 비교 함수는 cond_wait() 내에서 list_insert_ordered() 시 호출되는데,
   이 시점에는 아직 sema_down()이 호출되기 전이라, 현재 스레드가
   waiter.semaphore.waiters 리스트에 들어가지 않았습니다.
   따라서 대부분의 경우 이 리스트는 아직 비어있는 상태이며,
   비어 있는 경우에는 예외적으로 우선순위 비교를 생략해야 합니다. */
   bool sema_priority_less_func(const struct list_elem *a, const struct list_elem *b, void *aux){
	struct semaphore_elem *sema_elem_a  =list_entry(a,struct semaphore_elem, elem);
	struct semaphore_elem *sema_elem_b  =list_entry(b,struct semaphore_elem, elem);

	// 두 대기 세마포어 리스트가 모두 비어 있다면 우선순위 비교 불가 → 무조건 false 리턴
	if (list_empty(&sema_elem_a->semaphore.waiters) && list_empty(&sema_elem_b->semaphore.waiters))
		return false;
	// waiters리스트가 비어있는 거 예외처리 (안하면 몇개의 쓰레드만 시작하고 전체쓰레드는 시작못함(priority-condvar에서...))
	if (list_empty(&sema_elem_a->semaphore.waiters)){
		return false;
	}
	if (list_empty(&sema_elem_b->semaphore.waiters)){
		return true;
	}
	struct thread *x = list_entry(list_front(&sema_elem_a->semaphore.waiters),struct thread, elem);
	struct thread *y = list_entry(list_front(&sema_elem_b->semaphore.waiters),struct thread, elem);

	return x->priority > y->priority;
}
/* 현재 스레드를 조건 변수에 등록하고 락을 잠시 반납한 뒤,
다른 스레드가 신호(cond_signal 또는 cond_broadcast)를 줄 때까지 기다렸다가
다시 락을 획득하고 돌아오는 함수 */
void
cond_wait (struct condition *cond, struct lock *lock) {
	struct semaphore_elem waiter;

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	sema_init (&waiter.semaphore, 0);
	//list_push_back (&cond->waiters, &waiter.elem);
	//cond->wait를 정렬하기 위해 waiters 리스트에 삽입할 때, semaphore_elem 구조체에 담긴 세마포어의 대기 스레드 우선순위를 기준으로 삽입하는 코드
	list_insert_ordered (&cond->waiters, &waiter.elem,sema_priority_less_func,NULL);		  
	lock_release (lock);
	sema_down (&waiter.semaphore);
	lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
// cond_signal()은 조건 변수(Condition Variable)를 사용할 때, 기다리고 있는 스레드 중 하나를 깨우기 위한 함수  
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	if (!list_empty (&cond->waiters)){
		// cond->waiters는 삽입당시 정렬되어 있지만, 우선순위가 도중에 변경될 수 있다. 따라서 여기에서 다시 한 번 정렬 필요!
		// 예: thread_set_priority() 등으로 runtime에서 우선순위가 바뀌면 정렬 순서가 무너짐.
		list_sort(&cond->waiters, sema_priority_less_func, NULL);
		sema_up (&list_entry (list_pop_front (&cond->waiters),
					struct semaphore_elem, elem)->semaphore);
		}
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
