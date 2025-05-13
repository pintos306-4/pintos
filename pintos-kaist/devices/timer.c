#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
static int64_t ticks;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

static struct list sleep_list;

static intr_handler_func timer_interrupt;
static bool too_many_loops (unsigned loops);
static void busy_wait (int64_t loops);
static void real_time_sleep (int64_t num, int32_t denom);
static bool list_less_endtime(const struct list_elem *a, const struct list_elem *b, void *aux);
static void thread_wake(struct list *list);

/* Sets up the 8254 Programmable Interval Timer (PIT) to
   interrupt PIT_FREQ times per second, and registers the
   corresponding interrupt. */
void
timer_init (void) {
	/* 8254 input frequency divided by TIMER_FREQ, rounded to
	   nearest. */
	uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;

	outb (0x43, 0x34);    /* CW: counter 0, LSB then MSB, mode 2, binary. */
	outb (0x40, count & 0xff);
	outb (0x40, count >> 8);

	intr_register_ext (0x20, timer_interrupt, "8254 Timer");
	list_init(&sleep_list);
}

/* Calibrates loops_per_tick, used to implement brief delays. */
void
timer_calibrate (void) {
	unsigned high_bit, test_bit;

	ASSERT (intr_get_level () == INTR_ON);
	printf ("Calibrating timer...  ");

	/* Approximate loops_per_tick as the largest power-of-two
	   still less than one timer tick. */
	loops_per_tick = 1u << 10;
	while (!too_many_loops (loops_per_tick << 1)) {
		loops_per_tick <<= 1;
		ASSERT (loops_per_tick != 0);
	}

	/* Refine the next 8 bits of loops_per_tick. */
	high_bit = loops_per_tick;
	for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
		if (!too_many_loops (high_bit | test_bit))
			loops_per_tick |= test_bit;

	printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
int64_t
timer_ticks (void) {
	enum intr_level old_level = intr_disable ();
	int64_t t = ticks;
	intr_set_level (old_level);
	barrier ();
	return t;
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
int64_t
timer_elapsed (int64_t then) {
	return timer_ticks () - then;
}

/* Suspends execution for approximately TICKS timer ticks. */
void
timer_sleep (int64_t ticks) {
	enum intr_level old_level;
	int64_t start = timer_ticks ();												//timer_sleep()이 호출된 시점의 시간
	int64_t end = start + ticks;												//스레드의 sleep이 끝나는 시간

	ASSERT (intr_get_level () == INTR_ON);										//인터럽트가 발생하면 그 다음 코드를 실행함

	struct thread *curr = thread_current ();									//현재 스레드 저장
	curr->end = end;															//현재 스레드의 end값 초기화

	old_level = intr_disable();													//인터럽트를 disable시킴 (임계영역 보호)
	list_insert_ordered (&sleep_list, &curr->elem, list_less_endtime, NULL);	//sleep list에 스레드 넣기
	thread_block();																//현재 실행 중인 스레드를 sleep상태(blocked 상태)로 바꿔주기 
	intr_set_level(old_level);													//임계 영역 해제
}

/* Compares the value of two list elements A and B, given
   auxiliary data AUX.  Returns true if A is less than B, or
   false if A is greater than or equal to B. */

/* 인자로 들어온 a, b 스레드 중 끝나는 시간(end)이 a가 더 크면 true, b가 더 크면 false를 리턴 */
bool
list_less_endtime(const struct list_elem *a, const struct list_elem *b, void *aux){
	
	struct thread* t_a = list_entry(a, struct thread, elem);
	struct thread* t_b = list_entry(b, struct thread, elem);
	
	//a<b이면 true, a>=b이면 false 리턴
	return t_a->end < t_b->end;
}


/* Suspends execution for approximately MS milliseconds. */
void
timer_msleep (int64_t ms) {
	real_time_sleep (ms, 1000);
}

/* Suspends execution for approximately US microseconds. */
void
timer_usleep (int64_t us) {
	real_time_sleep (us, 1000 * 1000);
}

/* Suspends execution for approximately NS nanoseconds. */
void
timer_nsleep (int64_t ns) {
	real_time_sleep (ns, 1000 * 1000 * 1000);
}

/* Prints timer statistics. */
void
timer_print_stats (void) {
	printf ("Timer: %"PRId64" ticks\n", timer_ticks ());
}

/* Timer interrupt handler. */
static void
timer_interrupt (struct intr_frame *args UNUSED) {
	enum intr_level old_level;

	ticks++;							//시스템 전체 tick 증가
	
	old_level = intr_disable();			//임계 영역 설정
	thread_wake (&sleep_list);			//지정된 시간 만큼 잠들었던 스레드들을 모두 깨우기
	intr_set_level(old_level);			//임계 영역 해제
	
	thread_tick ();						//현재 스레드 실행 시간이 TIME_SLICE에 도달했다면 문맥 교환 처리
}

/* tick이 한 번 지나서 타이머 인터럽트가 호출될 때마다 sleep(blocked)상태인 스레드 중 
어떤 스레드를 깨워야 할지 조건문을 확인해 골라서 깨우기 */
static void
thread_wake(struct list *list){ 			//인자로 sleep_list 받기
	
	struct list_elem *e;

	while(!list_empty(list)) { 
		e = list_front(list);

		struct thread *t_now = list_entry(e, struct thread, elem);
		int64_t end_time = t_now->end;

		if(end_time > ticks) 				//wake 조건 : 스레드가 끝나는 시간이 현재 시간보다 크거나 같을 때 
			break;
		
		list_pop_front(list);				//해당 스레드를 그 스레드가 포함된 리스트에서 제거
		thread_unblock(t_now); 				//스레드를 ready_list에 넣기
	}
}

/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
static bool
too_many_loops (unsigned loops) {
	/* Wait for a timer tick. */
	int64_t start = ticks;
	while (ticks == start)
		barrier ();

	/* Run LOOPS loops. */
	start = ticks;
	busy_wait (loops);

	/* If the tick count changed, we iterated too long. */
	barrier ();
	return start != ticks;
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE
busy_wait (int64_t loops) {
	while (loops-- > 0)
		barrier ();
}

/* Sleep for approximately NUM/DENOM seconds. */
static void
real_time_sleep (int64_t num, int32_t denom) {
	/* Convert NUM/DENOM seconds into timer ticks, rounding down.

	   (NUM / DENOM) s
	   ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
	   1 s / TIMER_FREQ ticks
	   */
	int64_t ticks = num * TIMER_FREQ / denom;

	ASSERT (intr_get_level () == INTR_ON);
	if (ticks > 0) {
		/* We're waiting for at least one full timer tick.  Use
		   timer_sleep() because it will yield the CPU to other
		   processes. */
		timer_sleep (ticks);
	} else {
		/* Otherwise, use a busy-wait loop for more accurate
		   sub-tick timing.  We scale the numerator and denominator
		   down by 1000 to avoid the possibility of overflow. */
		ASSERT (denom % 1000 == 0);
		busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
	}
}

