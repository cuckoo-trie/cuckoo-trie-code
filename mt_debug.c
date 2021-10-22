#include <pthread.h>
#include <assert.h>
#include "random.h"
#include <stdio.h>
#include "cuckoo_trie.h"

#define MAX_THREADS 128

#define MAX_DWORD 0xFFFFFFFFU
#define NO_THREAD -1

static int mt_debug_enabled = 0;
static uint64_t rand_state = 1;
static int running_thread = NO_THREAD;
static pthread_t threads[MAX_THREADS];
static int num_threads = 0;
static int num_running_threads = 0;
static int finished[MAX_THREADS];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t running_thread_changed = PTHREAD_COND_INITIALIZER;

// Advance the random generator and decide which thread will access next
void next_turn_locked() {
	int i;
	float rand;
	int running_seen = 0;

	if (num_running_threads == 0)
		return;   // All threads finished - no need to schedule anyone

	rand = ((float)rand_dword_r(&rand_state)) / MAX_DWORD;
	for (i = 0;i < num_threads;i++) {
		if (finished[i])
			continue;

		running_seen++;
		if (running_seen >= num_running_threads * rand)
			break;
	}

	if (i == num_threads || finished[i])
		assert(0);

	running_thread = i;
}

void next_turn() {
	pthread_mutex_lock(&lock);
	next_turn_locked();
	pthread_mutex_unlock(&lock);

	// Notify waiting thread(s) that their turn might have come
	pthread_cond_broadcast(&running_thread_changed);
}

int thread_index() {
	int i;

	// Wait until threads are registered
	while (__atomic_load_n(&running_thread, __ATOMIC_ACQUIRE) == NO_THREAD)
		;

	for (i = 0;i < num_threads;i++) {
		if (pthread_equal(pthread_self(), threads[i]))
			return i;
	}
	assert(0);

	// Otherwise GCC warns "control reaches the end of a non-void function"
	__builtin_unreachable();
}

#ifdef NDEBUG
void mt_debug_wait_for_access() {
}

void mt_debug_access_done() {
}
#else
void mt_debug_wait_for_access() {
	int this_thread;

	if (!mt_debug_enabled)
		return;

	this_thread = thread_index();

	pthread_mutex_lock(&lock);

	while (mt_debug_enabled && running_thread != this_thread) {
		// It is not our turn to access the trie. Wait.
		pthread_cond_wait(&running_thread_changed, &lock);
	}

	pthread_mutex_unlock(&lock);
}

void mt_debug_access_done() {
	if (!mt_debug_enabled)
		return;

	next_turn();
}
#endif

void ct_mtdbg_register_thread(pthread_t thread_id) {
	threads[num_threads] = thread_id;
	finished[num_threads] = 0;
	num_threads++;
	num_running_threads++;
}

void ct_mtdbg_start() {
	assert(mt_debug_enabled);
	next_turn();
}

// This thread finished. Skip its turn from now on.
void ct_mtdbg_thread_done() {
	if (!mt_debug_enabled)
		return;

	pthread_mutex_lock(&lock);

	// Do this under the lock s.t. num_running_threads and the <finished> array are kept in sync
	finished[thread_index()] = 1;
	num_running_threads--;

	// If we're currently the running thread, pass the turn to somebody else
	if (running_thread == thread_index())
		next_turn_locked();

	pthread_mutex_unlock(&lock);

	pthread_cond_broadcast(&running_thread_changed);
}

void ct_mtdbg_set_enabled(int enabled) {
	__atomic_store_n(&mt_debug_enabled, enabled, __ATOMIC_RELEASE);
	pthread_cond_broadcast(&running_thread_changed);
}

void ct_mtdbg_seed(uint64_t seed) {
	rand_state = seed;
}
