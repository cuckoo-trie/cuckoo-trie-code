#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>

#include "cuckoo_trie_internal.h"
#include "random.h"
#include "dataset.h"
#include "util.h"

#define PID_NO_PROFILER 0
#define WORKLOAD_SIZE_DYNAMIC 0

#define MAX_THREADS 64

#define MILLION 1000000
#define DEFAULT_NUM_THREADS 4
#define DEFAULT_VALUE_SIZE 8

#define TRIE_CELLS_AUTO 0xFFFFFFFFFFFFFFFFULL

// A better name is timer_t, but it is already defined in time.h
typedef struct timespec stopwatch_t;

pid_t profiler_pid = PID_NO_PROFILER;

// Notify the profiler that the critical section starts, so it should start collecting statistics
void notify_critical_section_start() {
	if (profiler_pid != PID_NO_PROFILER)
		kill(profiler_pid, SIGUSR1);
}

void notify_critical_section_end() {
	if (profiler_pid != PID_NO_PROFILER)
		kill(profiler_pid, SIGUSR1);
}

void timer_start(stopwatch_t* timer) {
	clock_gettime(CLOCK_MONOTONIC, timer);
}

float timer_seconds(stopwatch_t* timer) {
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - timer->tv_sec + (now.tv_nsec - timer->tv_nsec) / 1.0e9);
}

void timer_report(stopwatch_t* timer, uint64_t num_ops) {
	float time_diff = timer_seconds(timer);

	printf("Took %.2fs for %lu ops (%.0fns/op, %.2fMops/s)\n", time_diff, num_ops,
		   (time_diff / num_ops) * 1.0e9,
		   (num_ops / time_diff) / 1.0e6);

    // print a line in machine-readable format for automatic graph creation
    printf("RESULT: ops=%lu ms=%d\n", num_ops, (int)(time_diff*1000));
}

void timer_report_mt(stopwatch_t* timer, uint64_t num_ops, int num_threads) {
	float time_diff = timer_seconds(timer);

	printf("Took %.2fs for %lu ops in %d threads (%.0fns/op, %.2fMops/s per thread)\n",
		   time_diff, num_ops, num_threads,
		   (time_diff / num_ops * num_threads) * 1.0e9,
		   (num_ops / time_diff / num_threads) / 1.0e6);

    printf("RESULT: ops=%lu threads=%d ms=%d\n", num_ops, num_threads, (int)(time_diff*1000));
}

cuckoo_trie* alloc_trie(dataset_t* dataset, uint64_t requested_cells) {
	uint64_t num_cells;

	if (requested_cells == TRIE_CELLS_AUTO) {
		num_cells = dataset->num_keys * 5 / 2;
	} else {
		num_cells = requested_cells;
	}

	return ct_alloc(num_cells);
}

// Makes the CPU wait until all preceding instructions have completed
// before it starts to execute following instructions.
// Used to make sure that calls to the benchmarked index operation
// (e.g. insert) in consecutive loop iterations aren't overlapped by
// the CPU.
static inline void speculation_barrier(void) {
	uint32_t unused;
	__builtin_ia32_rdtscp(&unused);
	__builtin_ia32_lfence();
}


typedef struct {
	void* (*thread_func)(void*);
	void* arg;
	int cpu;
} run_with_affinity_ctx;

void* run_with_affinity(void* arg) {
	run_with_affinity_ctx* ctx = (run_with_affinity_ctx*) arg;
	cpu_set_t cpu_set;

	CPU_ZERO(&cpu_set);
	CPU_SET(ctx->cpu, &cpu_set);
	sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set);
	return ctx->thread_func(ctx->arg);
}

int run_multiple_threads(void* (*thread_func)(void*), int num_threads, void* thread_contexts, int context_size) {
	uint64_t i;
	int result;
	int cpu = 0;
	run_with_affinity_ctx wrapper_contexts[num_threads];
	pthread_t threads[num_threads];
	cpu_set_t mask;

	sched_getaffinity(0, sizeof(cpu_set_t), &mask);

	for (i = 0;i < num_threads;i++) {
		run_with_affinity_ctx* wrapper_ctx = &(wrapper_contexts[i]);

		// Find next allowed CPU
		while (!CPU_ISSET(cpu, &mask)) {
			cpu++;
			if (cpu == CPU_SETSIZE) {
				printf("Not enough CPUs for all threads\n");
				return 0;
			}
		}

		wrapper_ctx->thread_func = thread_func;
		wrapper_ctx->arg = thread_contexts + context_size * i;
		wrapper_ctx->cpu = cpu;
		result = pthread_create(&(threads[i]), NULL, run_with_affinity, wrapper_ctx);
		if (result != 0) {
			printf("Thread creation error\n");
			return 0;
		}

		// Run the next thread on another CPU
		cpu++;
	}

	for (i = 0; i < num_threads; i++) {
		result = pthread_join(threads[i], NULL);
		if (result != 0) {
			printf("Thread join error\n");
			return 0;
		}
	}
	return 1;
}

void bench_insert(char* dataset_name, uint64_t trie_size) {
	stopwatch_t timer;
	uint64_t i;
	uint64_t duplicates = 0;
	int result;
	uint8_t* buf_pos;
	dataset_t dataset;
	cuckoo_trie* trie;

	seed_from_time();
	init_dataset(&dataset, dataset_name, DATASET_ALL_KEYS);

	trie = alloc_trie(&dataset, trie_size);

	build_kvs(&dataset, DEFAULT_VALUE_SIZE);
	buf_pos = dataset.kvs;

	timer_start(&timer);
	notify_critical_section_start();
	for (i = 0;i < dataset.num_keys;i++) {
		ct_kv* kv = (ct_kv*) buf_pos;
		result = ct_insert(trie, kv);
		if (result == S_ALREADYIN) {
			duplicates++;
		} else if (result != S_OK) {
			printf("Insertion error %d after %lu keys\n", result, i);
			return;
		}
		buf_pos += kv_size(kv);
		speculation_barrier();
	}
	timer_report(&timer, dataset.num_keys);
	if (duplicates > 0)
		printf("Note: %lu / %lu keys were duplicates\n", duplicates, dataset.num_keys);
}

uint8_t* sample_keys(ct_kv** kv_pointers, uint64_t num_kvs, uint64_t sample_size) {
	uint64_t i;
	dynamic_buffer_t buf;

	dynamic_buffer_init(&buf);

	for (i = 0; i < sample_size;i++) {
		ct_kv* src = kv_pointers[rand_uint64() % num_kvs];
		uint64_t blob_size = sizeof(blob_t) + kv_key_size(src);
		uint64_t blob_pos = dynamic_buffer_extend(&buf, blob_size);
		blob_t* dst = (blob_t*) &(buf.ptr[blob_pos]);
		dst->size = kv_key_size(src);
		memcpy(dst->bytes, kv_key_bytes(src), kv_key_size(src));
	}
	return buf.ptr;
}

int insert_kvs(cuckoo_trie* trie, uint8_t* kvs_buf, uint64_t num_kvs) {
	uint64_t i;
	int result;
	uint8_t* buf_pos = kvs_buf;

	for (i = 0; i < num_kvs;i++) {
		ct_kv* kv = (ct_kv*) buf_pos;
		result = ct_insert(trie, kv);
		if (result != S_OK)
			return result;
		buf_pos += kv_size(kv);
	}
	return S_OK;
}

void bench_pos_lookup(dataset_t* dataset, uint64_t trie_size) {
	const uint64_t num_lookups = 10 * MILLION;
	stopwatch_t timer;
	uint64_t i;
	int result;
	uint8_t* target_keys_buf;
	uint8_t* buf_pos;
	cuckoo_trie* trie;

	build_kvs(dataset, DEFAULT_VALUE_SIZE);

	trie = alloc_trie(dataset, trie_size);
	result = insert_kvs(trie, dataset->kvs, dataset->num_keys);
	if (result != S_OK) {
		printf("Insertion error %d\n", result);
		return;
	}

	target_keys_buf = sample_keys(dataset->kv_pointers, dataset->num_keys, num_lookups);

	notify_critical_section_start();
	timer_start(&timer);
	buf_pos = target_keys_buf;
	for (i = 0; i < num_lookups; i++) {
		blob_t* target = (blob_t*) buf_pos;
		ct_kv* kv = ct_lookup(trie, target->size, target->bytes);
		if (kv == NULL) {
			printf("Error: A key that was inserted wasn't found\n");
			return;
		}
		buf_pos += sizeof(blob_t) + target->size;
		speculation_barrier();
	}
	timer_report(&timer, num_lookups);
	notify_critical_section_end();
}

typedef struct {
	cuckoo_trie* trie;
	uint64_t num_keys;
	uint8_t* target_keys;
	uint64_t keys_done;
	int stop;
} lookup_thread_ctx;

typedef struct {
	cuckoo_trie* trie;
	uint64_t num_kvs;
	uint8_t* target_kvs;
	uint64_t kvs_done;
} insert_thread_ctx;

void* lookup_thread(void* context) {
	uint64_t i;
	uint8_t* buf_pos;
	ct_kv* result;
	lookup_thread_ctx* ctx = (lookup_thread_ctx*) context;

	buf_pos = ctx->target_keys;
	for (i = 0; i < ctx->num_keys; i++) {
		blob_t* key = (blob_t*) buf_pos;
		result = ct_lookup(ctx->trie, key->size, key->bytes);
		if (result == NULL) {
			printf("Error: A key that was inserted wasn't found\n");
			return NULL;
		}
		buf_pos += sizeof(blob_t) + key->size;
		if (__atomic_load_n(&(ctx->stop), __ATOMIC_ACQUIRE))
			break;
		speculation_barrier();
	}
	ctx->keys_done = i;
	return NULL;
}

void* insert_thread(void* context) {
	uint64_t i;
	int result;
	uint8_t* buf_pos;
	insert_thread_ctx* ctx = (insert_thread_ctx*) context;

	buf_pos = ctx->target_kvs;
	for (i = 0; i < ctx->num_kvs; i++) {
		ct_kv* kv = (ct_kv*) buf_pos;
		result = ct_insert(ctx->trie, kv);
		if (result != S_OK) {
			printf("Insertion error %d\n", result);
			return NULL;
		}
		buf_pos += kv_size(kv);
		speculation_barrier();
	}
	ctx->kvs_done = i;
	return NULL;
}

void bench_mt_pos_lookup(char* dataset_name, uint64_t trie_size, int num_threads) {
	const uint64_t lookups_per_thread = 10 * MILLION;
	stopwatch_t timer;
	uint64_t i;
	dataset_t dataset;
	uint8_t* buf_pos;
	lookup_thread_ctx thread_contexts[num_threads];

	cuckoo_trie* trie;
	int result;

	seed_from_time();
	init_dataset(&dataset, dataset_name, DATASET_ALL_KEYS);

	build_kvs(&dataset, DEFAULT_VALUE_SIZE);

	trie = alloc_trie(&dataset, trie_size);

	printf("Inserting...\n");
	result = insert_kvs(trie, dataset.kvs, dataset.num_keys);
	if (result != S_OK) {
		printf("Insertion error %d\n", result);
		return;
	}

	// Create thread contexts and workloads
	printf("Creating workloads...\n");
	for (i = 0; i < num_threads; i++) {
		lookup_thread_ctx* ctx = &(thread_contexts[i]);
		ctx->trie = trie;
		ctx->num_keys = lookups_per_thread;
		ctx->stop = 0;
		ctx->target_keys = sample_keys(dataset.kv_pointers, dataset.num_keys, lookups_per_thread);
	}

	notify_critical_section_start();
	timer_start(&timer);
	run_multiple_threads(lookup_thread, num_threads, thread_contexts, sizeof(lookup_thread_ctx));
	timer_report_mt(&timer, lookups_per_thread * num_threads, num_threads);
	notify_critical_section_end();
}

void bench_mw_insert_pos_lookup(char* dataset_name, uint64_t trie_size, int num_insert_threads, int num_lookup_threads) {
	uint64_t lookup_workload_size;
	uint64_t threaded_inserts;
	stopwatch_t timer;
	uint64_t i;
	dataset_t dataset;
	lookup_thread_ctx lookup_contexts[num_lookup_threads];
	insert_thread_ctx insert_contexts[num_insert_threads];
	pthread_t lookup_threads[num_lookup_threads];
	pthread_t insert_threads[num_insert_threads];

	cuckoo_trie* trie;
	int result;

	seed_from_time();
	init_dataset(&dataset, dataset_name, DATASET_ALL_KEYS);
	build_kvs(&dataset, DEFAULT_VALUE_SIZE);

	threaded_inserts = dataset.num_keys / 2;
	if (threaded_inserts > 10 * MILLION * num_insert_threads)
		threaded_inserts = 10 * MILLION * num_insert_threads;

	// Large enough s.t. lookup threads don't finish before the insert thread
	lookup_workload_size = (threaded_inserts / num_insert_threads) * 4;

	trie = alloc_trie(&dataset, trie_size);

	// Insert the first part of the dataset
	result = insert_kvs(trie, dataset.kvs, dataset.num_keys - threaded_inserts);
	if (result != S_OK) {
		printf("Insertion error %d\n", result);
		return;
	}

	// Create lookup thread workloads
	for (i = 0; i < num_lookup_threads; i++) {
		lookup_thread_ctx* ctx = &(lookup_contexts[i]);
		ctx->trie = trie;
		ctx->num_keys = lookup_workload_size;
		ctx->target_keys = sample_keys(dataset.kv_pointers,
						   dataset.num_keys - threaded_inserts,
						   lookup_workload_size);
		ctx->stop = 0;

	}

	// Split the rest of the dataset into insert thread workloads
	uint64_t kvs_per_insert_thread = (threaded_inserts / num_insert_threads) + 1;
	uint64_t first_key = dataset.num_keys - threaded_inserts;
	for (i = 0; i < num_insert_threads; i++) {
		insert_contexts[i].trie = trie;

		if (i != num_insert_threads - 1) {
			insert_contexts[i].num_kvs = kvs_per_insert_thread;
		} else {
			insert_contexts[i].num_kvs = dataset.num_keys - first_key;
		}
		insert_contexts[i].target_kvs = (uint8_t*) dataset.kv_pointers[first_key];

		first_key += insert_contexts[i].num_kvs;
	}

	timer_start(&timer);
	for (i = 0;i < num_insert_threads; i++) {
		result = pthread_create(&(insert_threads[i]), NULL, insert_thread, &(insert_contexts[i]));
		if (result != 0) {
			printf("Insert thread creation error %d\n", result);
			return;
		}
	}

	for (i = 0; i < num_lookup_threads; i++) {
		result = pthread_create(&(lookup_threads[i]), NULL, lookup_thread, &(lookup_contexts[i]));
		if (result != 0) {
			printf("Lookup thread creation error %d\n", result);
			return;
		}
	}

	// Wait for the insert threads to finish
	for (i = 0; i < num_insert_threads; i++) {
		result = pthread_join(insert_threads[i], NULL);
		if (result != 0) {
			printf("Insert thread join error %d\n", result);
			return;
		}
	}

	// Stop lookup threads
	for (i = 0; i < num_lookup_threads; i++) {
		__atomic_store_n(&(lookup_contexts[i].stop), 1, __ATOMIC_RELEASE);
	}
	uint64_t total_lookups = 0;
	for (i = 0; i < num_lookup_threads; i++) {
		result = pthread_join(lookup_threads[i], NULL);
		if (result != 0) {
			printf("Lookup thread join error %d\n", result);
			return;
		}
		if (lookup_contexts[i].keys_done >= lookup_workload_size) {
			printf("Error: a lookup thread finished before the insert thread\n");
			return;
		}
		total_lookups += lookup_contexts[i].keys_done;
	}

	float time_took = timer_seconds(&timer);
	uint64_t lookups_per_thread = total_lookups / num_lookup_threads;
	printf("Took %.2fs\n", time_took);
	printf("Insert: %lu ops, %.2fMops/s (per thread: %.2fMops/s, %.0fns/op)\n", threaded_inserts,
		((float)threaded_inserts) / time_took / 1.0e6,
		((float)kvs_per_insert_thread) / time_took / 1.0e6,
		time_took / ((float)kvs_per_insert_thread) * 1.0e9);
	printf("Lookup: %lu ops, %.2fMops/s (per thread: %.2fMops/s, %.0fns/op)\n", total_lookups,
		((float)total_lookups) / time_took / 1.0e6,
		((float)lookups_per_thread) / time_took / 1.0e6,
		time_took / ((float)lookups_per_thread) * 1.0e9);
}

void bench_mw_insert(char* dataset_name, uint64_t trie_size, int num_threads) {
	uint64_t i;
	int result;
	stopwatch_t timer;
	insert_thread_ctx thread_contexts[num_threads];
	cuckoo_trie* trie;
	dataset_t dataset;

	seed_from_time();

	printf("Reading dataset...\n");
	init_dataset(&dataset, dataset_name, DATASET_ALL_KEYS);
	build_kvs(&dataset, DEFAULT_VALUE_SIZE);

	trie = alloc_trie(&dataset, trie_size);

	uint64_t workload_start = 0;
	uint64_t workload_end;
	for (i = 0; i < num_threads;i++) {
		insert_thread_ctx* ctx = &(thread_contexts[i]);
		workload_end = dataset.num_keys * (i+1) / num_threads;
		ctx->target_kvs =  (uint8_t*) dataset.kv_pointers[workload_start];
		ctx->num_kvs = workload_end - workload_start;
		ctx->trie = trie;

		workload_start = workload_end;
	}

	printf("Inserting...\n");
	notify_critical_section_start();
	timer_start(&timer);
	run_multiple_threads(insert_thread, num_threads, thread_contexts, sizeof(insert_thread_ctx));
	timer_report_mt(&timer, dataset.num_keys, num_threads);
	notify_critical_section_end();
}

void range_read_from_key(cuckoo_trie* trie, uint64_t num_ranges, uint64_t range_size,
						 dataset_t* dataset) {
	uint64_t i, j;
	uint64_t checksum = 0;
	ct_iter* iter;

	iter = ct_iter_alloc(trie);
	for (i = 0;i < num_ranges;i++) {
		ct_kv* range_start = dataset->kv_pointers[rand_uint64() % dataset->num_keys];
		ct_iter_goto(iter, kv_key_size(range_start), kv_key_bytes(range_start));

		for (j = 0;j < range_size;j++) {
			ct_kv* kv = ct_iter_next(iter);
			if (!kv)
				break;   // Reached the end of the dataset

			checksum += kv_key_size(kv);  // Touch the key data to force reading it from RAM
		}
	}
	printf("Done. Checksum: %lu\n", checksum);
}

void range_prefetch_from_key(cuckoo_trie* trie, uint64_t num_ranges, uint64_t range_size,
						 dataset_t* dataset) {
	uint64_t i, j;
	uint64_t checksum = 0;
	ct_kv* kvs[range_size];
	ct_iter* iter;

	iter = ct_iter_alloc(trie);
	for (i = 0;i < num_ranges;i++) {
		ct_kv* range_start = dataset->kv_pointers[rand_uint64() % dataset->num_keys];
		ct_iter_goto(iter, kv_key_size(range_start), kv_key_bytes(range_start));

		for (j = 0;j < range_size;j++) {
			ct_kv* kv = ct_iter_next(iter);
			kvs[j] = kv;
			if (!kv)
				break;   // Reached the end of the dataset

			__builtin_prefetch(kv);
		}
		for (j = 0;j < range_size;j++) {
			ct_kv* kv = kvs[j];
			if (!kv)
				break;   // Reached the end of the dataset
			checksum += kv_key_size(kv);  // Touch the key data to force reading it from RAM
		}
	}
	printf("Done. Checksum: %lu\n", checksum);
}

void range_skip_from_key(cuckoo_trie* trie, uint64_t num_ranges, uint64_t range_size,
						 dataset_t* dataset) {
	uint64_t i, j;
	ct_iter* iter;

	iter = ct_iter_alloc(trie);
	for (i = 0;i < num_ranges;i++) {
		ct_kv* range_start = dataset->kv_pointers[rand_uint64() % dataset->num_keys];
		ct_iter_goto(iter, kv_key_size(range_start), kv_key_bytes(range_start));

		for (j = 0;j < range_size;j++) {
			ct_kv* kv = ct_iter_next(iter);
			if (!kv)
				break;   // Reached the end of the dataset
		}
	}
}

typedef void (*range_func_t)(cuckoo_trie*, uint64_t, uint64_t, dataset_t*);

void bench_range_from_key(char* dataset_name, uint64_t trie_size, range_func_t range_func) {
	const uint64_t range_size = 50;
	const uint64_t num_ranges = MILLION;
	stopwatch_t timer;
	uint64_t i;
	dataset_t dataset;
	cuckoo_trie* trie;

	seed_from_time();
	init_dataset(&dataset, dataset_name, DATASET_ALL_KEYS);

	if (dataset.num_keys < range_size * 10)
		printf("Warning: dataset is small. Many ranges will reach the end of the dataset.\n");

	build_kvs(&dataset, DEFAULT_VALUE_SIZE);

	trie = alloc_trie(&dataset, trie_size);
	insert_kvs(trie, dataset.kvs, dataset.num_keys);

	// Read ranges
	printf("Reading ranges...\n");
	notify_critical_section_start();
	timer_start(&timer);
	range_func(trie, num_ranges, range_size, &dataset);
	timer_report(&timer, num_ranges);

}

float load_factor(cuckoo_trie* trie) {
	int i;
	uint64_t bucket;
	uint64_t used_cells = 0;
	uint64_t total_cells = trie->num_buckets * CUCKOO_BUCKET_SIZE;

	for (bucket = 0; bucket < trie->num_buckets; bucket++) {
		for (i = 0; i < CUCKOO_BUCKET_SIZE; i++) {
			ct_entry_storage* entry = &(trie->buckets[bucket].cells[i]);
			if (entry_type((ct_entry*) entry) != TYPE_UNUSED)
				used_cells++;
		}
	}

	return ((float)used_cells) / total_cells;
}

int kvs_fit_in_trie(uint8_t* kvs_buf, uint64_t num_kvs, uint64_t trie_size) {
	uint64_t i;
	int result;
	cuckoo_trie* trie;
	uint8_t* buf_pos;

	printf("Trying to insert to a trie of %lu cells... ", trie_size);
	fflush(stdout);
	trie = ct_alloc(trie_size);
	if (trie == NULL) {
		printf("Couldn't allocate trie\n");
		return -1;
	}

	buf_pos = kvs_buf;
	for (i = 0;i < num_kvs;i++) {
		ct_kv* kv = (ct_kv*) buf_pos;
		result = ct_insert(trie, kv);
		if (result == S_OVERFLOW) {
			printf("Overflow (Load factor %.1f%%)\n", load_factor(trie) * 100);
			ct_free(trie);
			return 0;
		}
		if (result != S_OK && result != S_ALREADYIN) {
			printf("Insertion error %d\n", result);
			ct_free(trie);
			return -1;
		}
		buf_pos += kv_size(kv);
	}
	printf("OK (Load factor %.1f%%)\n", load_factor(trie) * 100);
	ct_free(trie);
	return 1;
}

// Meause the trie size required for the dataset. As resizing isn't currently supported,
// we binary-search over different sizes until we arrive at the minimal size that works.
void bench_mem_usage(dataset_t* dataset) {
	int result;
	uint64_t step;
	uint64_t size = 10000;

	build_kvs(dataset, 0);

	while (1) {
		result = kvs_fit_in_trie(dataset->kvs, dataset->num_keys, size);
		if (result == -1)
			return;
		if (result == 1)
			break;
		size *= 2;
	}

	// We know that <size> is large enough, and <size>/2 is too small, so the
	// next size to try is <size>-<size>/4
	step = size / 8;
	size -= size / 4;
	while (step > size / 1000) {
		result = kvs_fit_in_trie(dataset->kvs, dataset->num_keys, size);
		if (result == -1)
			return;
		if (result == 1)
			size -= step;
		else
			size += step;
		step /= 2;
	}

	float bytes_per_key = (((float)size) / CUCKOO_BUCKET_SIZE) * sizeof(ct_bucket) / dataset->num_keys;
	printf("Minimal trie size is about %lu cells (%.2f cells / key, %.1fb/key)\n", size,
			((float)size) / dataset->num_keys, bytes_per_key);
	printf("RESULT: keys=%lu bytes=%lu\n", dataset->num_keys, size * sizeof(ct_bucket) / CUCKOO_BUCKET_SIZE);
}

#define YCSB_READ 0
#define YCSB_READ_LATEST 1
#define YCSB_UPDATE 2
#define YCSB_INSERT 3
#define YCSB_SCAN 4
#define YCSB_RMW 5
#define YCSB_NUM_OP_TYPES 6

#define YCSB_UNIFORM 0
#define YCSB_ZIPF 1

// From https://github.com/brianfrankcooper/YCSB/blob/master/core/src/main/java/site/ycsb/generator/ZipfianGenerator.java
#define YCSB_SKEW 0.99

typedef struct {
	int type;
	uint64_t data_pos;
} ycsb_op;

typedef struct {
	uint64_t initial_num_keys;
	uint64_t num_ops;
	ycsb_op* ops;
	uint8_t* data_buf;

	// For each thread, a pointer to an array of block-pointers. In that array,
	// the K-th block contains keys with a distribution assuming that K of the inserts
	// in this workload were done.
	uint8_t** read_latest_blocks_for_thread[MAX_THREADS];
} ycsb_workload;

typedef struct {
	float op_type_probs[YCSB_NUM_OP_TYPES];
	uint64_t num_ops;
	int distribution;
} ycsb_workload_spec;

const ycsb_workload_spec YCSB_A_SPEC = {{0.5,  0,    0.5,  0,    0,    0  }, 10 * MILLION, YCSB_ZIPF};
const ycsb_workload_spec YCSB_B_SPEC = {{0.95, 0,    0.05, 0,    0,    0  }, 10 * MILLION, YCSB_ZIPF};
const ycsb_workload_spec YCSB_C_SPEC = {{1.0,  0,    0,    0,    0,    0  }, 10 * MILLION, YCSB_ZIPF};
const ycsb_workload_spec YCSB_D_SPEC = {{0,    0.95, 0,    0.05, 0,    0  }, 10 * MILLION, YCSB_ZIPF};
const ycsb_workload_spec YCSB_E_SPEC = {{0,    0,    0,    0.05, 0.95, 0  }, 2  * MILLION, YCSB_ZIPF};
const ycsb_workload_spec YCSB_F_SPEC = {{0.5,  0,    0,    0,    0,    0.5}, 10 * MILLION, YCSB_ZIPF};

typedef struct ycsb_thread_ctx_t {
	cuckoo_trie* trie;
	uint64_t thread_id;
	uint64_t num_threads;
	uint64_t inserts_done;
	struct ycsb_thread_ctx_t* thread_contexts;
	ycsb_workload workload;
} ycsb_thread_ctx;

int choose_ycsb_op_type(const float* op_probs) {
	uint64_t i;
	float sum = 0.0;
	float rand = rand_float();
	for (i = 0;i < YCSB_NUM_OP_TYPES;i++) {
		sum += op_probs[i];
		if (sum > 1.00001) {
			printf("Error: Inconsistent YCSB probabilities\n");
			return -1;
		}

		// <rand> can be exactly 1.0 so we use "<="
		if (rand <= sum)
			return i;
	}
	printf("Error: Inconsistent YCSB probabilities\n");
	return -1;
}

void* ycsb_thread(void* arg) {
	uint64_t i, j;
	uint64_t range_size;
	int result;
	blob_t* key;
	ct_kv* kv;
	ct_iter* iter;
	uint64_t inserter_idx;
	uint64_t total_read_latest = 0;
	uint64_t failed_read_latest = 0;
	uint64_t read_latest_from_thread = 0;
	ycsb_thread_ctx* inserter;
	ycsb_thread_ctx* ctx = (ycsb_thread_ctx*) arg;

	uint64_t last_inserts_done[ctx->num_threads];
	uint8_t* next_read_latest_key[ctx->num_threads];
	uint8_t** thread_read_latest_blocks[ctx->num_threads];

	for (i = 0;i < ctx->num_threads;i++) {
		last_inserts_done[i] = 0;
		thread_read_latest_blocks[i] = ctx->thread_contexts[i].workload.read_latest_blocks_for_thread[ctx->thread_id];
		uint8_t* block_start = ctx->thread_contexts[i].workload.read_latest_blocks_for_thread[ctx->thread_id][0];
		next_read_latest_key[i] = block_start;
	}

	iter = ct_iter_alloc(ctx->trie);

	for (i = 0;i < ctx->workload.num_ops; i++) {
		ycsb_op* op = &(ctx->workload.ops[i]);
		switch (op->type) {
			case YCSB_READ_LATEST:
				total_read_latest++;
				inserter_idx = read_latest_from_thread;

				// Get key pointer for current read
				key = (blob_t*) next_read_latest_key[inserter_idx];

				// Advancing next_read_latest_key must be done before checking whether to
				// move to another block (by comparing inserts_done). Otherwise, in the
				// single-threaded case, we'll advance next_read_latest_key[0] after it was
				// set to the block start, and by an incorrect amount.
				if (key->size != 0xFFFFFFFFU)
					next_read_latest_key[inserter_idx] += sizeof(blob_t) + key->size;

				// Compute key pointer for next read
				read_latest_from_thread++;
				if (read_latest_from_thread == ctx->num_threads)
					read_latest_from_thread = 0;

				inserter = &(ctx->thread_contexts[read_latest_from_thread]);
				uint64_t inserts_done = __atomic_load_n(&(inserter->inserts_done), __ATOMIC_RELAXED);
				if (inserts_done != last_inserts_done[read_latest_from_thread]) {
					last_inserts_done[read_latest_from_thread] = inserts_done;

					uint8_t* block_start = thread_read_latest_blocks[read_latest_from_thread][inserts_done];
					next_read_latest_key[read_latest_from_thread] = block_start;
					__builtin_prefetch(&(thread_read_latest_blocks[read_latest_from_thread][inserts_done+8]));
				}
				__builtin_prefetch(next_read_latest_key[read_latest_from_thread]);

				if (unlikely(key->size == 0xFFFFFFFF)) {
					// Reached end-of-block sentinel
					failed_read_latest++;
					break;
				}

				// Lookup
				kv = ct_lookup(ctx->trie, key->size, key->bytes);
				if (kv == NULL) {
					printf("Error: a key was not found!\n");
					return NULL;
				}
				speculation_barrier();
				break;

			case YCSB_READ:
				key = (blob_t*) &(ctx->workload.data_buf[op->data_pos]);
				kv = ct_lookup(ctx->trie, key->size, key->bytes);
				if (kv == NULL) {
					printf("Error: a key was not found!\n");
					return NULL;
				}
				speculation_barrier();
				break;

			case YCSB_UPDATE:
				kv = (ct_kv*) &(ctx->workload.data_buf[op->data_pos]);
				result = ct_update(ctx->trie, kv);
				if (result != S_OK) {
					printf("Error: ct_update returned %d\n", result);
					return NULL;
				}
				speculation_barrier();
				break;

			case YCSB_RMW:
				kv = (ct_kv*) &(ctx->workload.data_buf[op->data_pos]);

				// Get pointer to current value
				ct_kv* current_kv = ct_lookup(ctx->trie, kv_key_size(kv), kv_key_bytes(kv));
				if (current_kv == NULL) {
					printf("Error: a key was not found!\n");
					return NULL;
				}

				// Write the new value
				result = ct_update(ctx->trie, kv);
				if (result != S_OK) {
					printf("Error: ct_update returned %d\n", result);
					return NULL;
				}
				speculation_barrier();
				break;

			case YCSB_INSERT:
				kv = (ct_kv*) &(ctx->workload.data_buf[op->data_pos]);
				result = ct_insert(ctx->trie, kv);
				if (result != S_OK) {
					printf("Error: ct_insert returned %d\n", result);
					return NULL;
				}
				// Use atomic_store to make sure that the write isn't reordered with ct_insert,
				// and eventually becomes visible to other threads.
				__atomic_store_n(&(ctx->inserts_done), ctx->inserts_done + 1, __ATOMIC_RELEASE);
				speculation_barrier();
				break;

			case YCSB_SCAN:
				key = (blob_t*) &(ctx->workload.data_buf[op->data_pos]);
				range_size = (rand_dword() % 100) + 1;

				uint64_t checksum = 0;
				ct_iter_goto(iter, key->size, key->bytes);
				for (j = 0;j < range_size;j++) {
					ct_kv* kv = ct_iter_next(iter);
					if (!kv)
						break;   // Reached the end of the dataset

					checksum += (uintptr_t) kv;
				}

				// Make sure <checksum> isn't optimized away
				if (checksum == 0xFFFFFFFFFFFF)
					printf("Impossible!\n");
				speculation_barrier();
				break;
		}
	}
	if (failed_read_latest > 0) {
		printf("Note: %lu / %lu (%.1f%%) of read-latest operations were skipped\n",
				failed_read_latest, total_read_latest,
				((float)failed_read_latest) / total_read_latest * 100.0);
	}
	return NULL;
}

int generate_ycsb_workload(dataset_t* dataset, ycsb_workload* workload,
						   const ycsb_workload_spec* spec, int thread_id,
						   int num_threads) {
	uint64_t i;
	int data_size;
	ct_kv* kv;
	uint64_t inserts_per_thread;
	uint64_t insert_offset;
	uint64_t num_inserts = 0;
	uint64_t read_latest_block_size = 0;
	dynamic_buffer_t workload_buf;
	rand_distribution dist;
	rand_distribution backward_dist;

	if (num_threads > MAX_THREADS)
		return 0;

	workload->ops = malloc(sizeof(ycsb_op) * spec->num_ops);
	workload->num_ops = spec->num_ops;

	inserts_per_thread = spec->op_type_probs[YCSB_INSERT] * spec->num_ops;
	workload->initial_num_keys = dataset->num_keys - inserts_per_thread * num_threads;
	insert_offset = workload->initial_num_keys + inserts_per_thread * thread_id;

	if (inserts_per_thread * num_threads > dataset->num_keys) {
		printf("Error: dataset too small\n");
		return 0;
	}

	if (workload->initial_num_keys < dataset->num_keys * 3 / 4 &&
		spec->op_type_probs[YCSB_INSERT] < 1.0) {
		printf("Warning: many inserts relative to dataset size. Read/read_latest/scan/update will only use a small part of the dataset.\n");
	}

	if (spec->distribution == YCSB_UNIFORM) {
		rand_uniform_init(&dist, workload->initial_num_keys);
	} else if (spec->distribution == YCSB_ZIPF) {
		rand_zipf_init(&dist, workload->initial_num_keys, YCSB_SKEW);
	} else {
		printf("Error: Unknown YCSB distribution\n");
		return 0;
	}

	if (spec->op_type_probs[YCSB_READ_LATEST] > 0.0) {
		// spec->distribution is meaningless for read-latest. Read offsets for read-latest are
		// always Zipf-distributed.
		assert(spec->distribution == YCSB_ZIPF);
		rand_zipf_rank_init(&backward_dist, workload->initial_num_keys, YCSB_SKEW);

		double read_latest_per_thread = spec->op_type_probs[YCSB_READ_LATEST] * spec->num_ops;
		read_latest_block_size = read_latest_per_thread / (double)(inserts_per_thread + 1);
		read_latest_block_size = read_latest_block_size / num_threads + 1;
		read_latest_block_size *= 5;
	}

	dynamic_buffer_init(&workload_buf);
	for (i = 0; i < spec->num_ops; i++) {
		ycsb_op* op = &(workload->ops[i]);
		op->type = choose_ycsb_op_type(spec->op_type_probs);

		if (num_inserts == inserts_per_thread && op->type == YCSB_INSERT) {
			// Used all keys intended for insertion. Do another op type.
			i--;
			continue;
		}

		switch (op->type) {
			case YCSB_READ:
			case YCSB_SCAN:
				kv = dataset->kv_pointers[rand_dist(&dist)];
				data_size = sizeof(blob_t) + kv_key_size(kv);
				op->data_pos = dynamic_buffer_extend(&workload_buf, data_size);

				blob_t* data = (blob_t*) (workload_buf.ptr + op->data_pos);
				data->size = kv_key_size(kv);
				memcpy(data->bytes, kv_key_bytes(kv), kv_key_size(kv));
				break;

			case YCSB_READ_LATEST:
				// A read-latest op has no data
				break;

			case YCSB_RMW:
			case YCSB_UPDATE:
				kv = dataset->kv_pointers[rand_dist(&dist)];
				op->data_pos = dynamic_buffer_extend(&workload_buf, kv_size(kv));

				memcpy(workload_buf.ptr + op->data_pos, kv, kv_size(kv));
				break;

			case YCSB_INSERT:
				kv = dataset->kv_pointers[insert_offset + num_inserts];
				num_inserts++;
				op->data_pos = dynamic_buffer_extend(&workload_buf, kv_size(kv));

				memcpy(workload_buf.ptr + op->data_pos, kv, kv_size(kv));
				break;

			default:
				printf("Error: Unknown YCSB op type %d\n", op->type);
				return 0;
		}
	}

	// Create the read-latest key blocks
	uint64_t block;
	uint64_t thread;
	for (thread = 0; thread < num_threads; thread++) {
		uint8_t** block_offsets = malloc(sizeof(uint64_t) * (num_inserts + 1));
		workload->read_latest_blocks_for_thread[thread] = block_offsets;

		// We have one block for each amount of inserts between 0 and num_inserts, /inclusive/
		for (block = 0; block < num_inserts + 1; block++) {
			for (i = 0; i < read_latest_block_size; i++) {
				uint64_t backwards = rand_dist(&backward_dist);
				if (backwards < block * num_threads) {
					// This read-latest op refers to a key that was inserted during the workload
					backwards /= num_threads;
					kv = dataset->kv_pointers[insert_offset + block - backwards - 1];
				} else {
					// This read-latest op refers to a key that was loaded before the workload started
					backwards -= block * num_threads;
					kv = dataset->kv_pointers[workload->initial_num_keys - backwards - 1];
				}

				// Write the chosen key to the workload data buffer
				data_size = sizeof(blob_t) + kv_key_size(kv);
				uint64_t data_pos = dynamic_buffer_extend(&workload_buf, data_size);

				blob_t* data = (blob_t*) (workload_buf.ptr + data_pos);
				data->size = kv_key_size(kv);
				memcpy(data->bytes, kv_key_bytes(kv), kv_key_size(kv));

				if (i == 0)
					block_offsets[block] = (uint8_t*) data_pos;
			}
			uint64_t sentinel_pos = dynamic_buffer_extend(&workload_buf, sizeof(blob_t));
			blob_t* sentinel = (blob_t*) (workload_buf.ptr + sentinel_pos);
			sentinel->size = 0xFFFFFFFF;
		}
	}

	workload->data_buf = workload_buf.ptr;

	// Now that the final buffer address is known, convert the read-latest offsets to pointers
	for (thread = 0; thread < num_threads; thread++) {
		for (block = 0; block < num_inserts + 1; block++)
			workload->read_latest_blocks_for_thread[thread][block] += (uintptr_t) (workload->data_buf);
	}
	return 1;
}

void bench_ycsb(char* dataset_name, uint64_t trie_size, const ycsb_workload_spec* base_spec, int num_threads) {
	uint64_t i;
	int result;
	ycsb_thread_ctx thread_contexts[num_threads];
	stopwatch_t timer;
	dataset_t dataset;
	cuckoo_trie* trie;
	ycsb_workload_spec spec = *base_spec;

	seed_from_time();

	init_dataset(&dataset, dataset_name, DATASET_ALL_KEYS);
	build_kvs(&dataset, DEFAULT_VALUE_SIZE);

	trie = alloc_trie(&dataset, trie_size);

	printf("Creating workloads");
	for (i = 0;i < num_threads; i++) {
		result = generate_ycsb_workload(&dataset, &(thread_contexts[i].workload), &spec, i, num_threads);
		if (!result) {
			printf("Error creating workload\n");
			return;
		}
		thread_contexts[i].trie = trie;
		thread_contexts[i].thread_id = i;
		thread_contexts[i].num_threads = num_threads;
		thread_contexts[i].thread_contexts = thread_contexts;
		thread_contexts[i].inserts_done = 0;
		printf(".");
		fflush(stdout);
	}
	printf("\n");

	insert_kvs(trie, dataset.kvs, thread_contexts[0].workload.initial_num_keys);
	notify_critical_section_start();
	timer_start(&timer);
	run_multiple_threads(ycsb_thread, num_threads, thread_contexts, sizeof(ycsb_thread_ctx));
	timer_report_mt(&timer, spec.num_ops * num_threads, num_threads);
}

int main(int argc, char** argv) {
	int i;
	dataset_t dataset;
	char* benchmark_name;
	char* dataset_name = NULL;
	int num_insert_threads = DEFAULT_NUM_THREADS;
	int num_lookup_threads = DEFAULT_NUM_THREADS;
	int num_threads = DEFAULT_NUM_THREADS;
	uint64_t dataset_size = DATASET_ALL_KEYS;
	uint64_t trie_cells = TRIE_CELLS_AUTO;
	int use_uniform_dist = 0;
	uint64_t total_ycsb_ops = WORKLOAD_SIZE_DYNAMIC;
	ycsb_workload_spec ycsb_workload;

	if (argc < 3) {
		printf("Usage: %s <benchmark name> [options] <dataset>.\n", argv[0]);
		return 1;
	}
	benchmark_name = argv[1];

	for (i = 2;i < argc;i++) {
		if (!strcmp(argv[i], "--lookup-threads")) {
			num_lookup_threads = atoi(argv[i+1]);
			i++;
		} else if (!strcmp(argv[i], "--insert-threads")) {
			num_insert_threads = atoi(argv[i+1]);
			i++;
		} else if (!strcmp(argv[i], "--threads")) {
			num_threads = atoi(argv[i+1]);
			i++;
		} else if (!strcmp(argv[i], "--profiler-pid")) {
			profiler_pid = atoi(argv[i+1]);
			i++;
		} else if (!strcmp(argv[i], "--total-num-ops")) {
			total_ycsb_ops = strtoull(argv[i+1], NULL, 0);
			i++;
		} else if (!strcmp(argv[i], "--ycsb-uniform-dist")) {
			use_uniform_dist = 1;
		} else if (!strcmp(argv[i], "--dataset-size")) {
			dataset_size = strtoull(argv[i+1], NULL, 0);
			i++;
		} else if (!strcmp(argv[i], "--trie-cells")) {
			trie_cells = strtoull(argv[i+1], NULL, 0);
			i++;
		} else if (argv[i][0] == '-') {
			printf("Unknown flag '%s'\n", argv[i]);
			return 1;
		} else {
			dataset_name = argv[i];
		}
	}
	if (dataset_name == NULL) {
		printf("Missing dataset name.\n");
		return 1;
	}
	if (!strcmp(benchmark_name, "insert")) {
		bench_insert(dataset_name, trie_cells);
		return 0;
	}
	else if (!strcmp(benchmark_name, "pos-lookup")) {
		seed_from_time();
		init_dataset(&dataset, dataset_name, dataset_size);

		bench_pos_lookup(&dataset, trie_cells);
		return 0;
	} else if (!strcmp(benchmark_name, "mt-pos-lookup")) {
		bench_mt_pos_lookup(dataset_name, trie_cells, num_threads);
		return 0;
	} else if (!strcmp(benchmark_name, "mw-insert-pos-lookup")) {
		bench_mw_insert_pos_lookup(dataset_name, trie_cells, num_insert_threads, num_lookup_threads);
		return 0;
	} else if (!strcmp(benchmark_name, "range-read")) {
		bench_range_from_key(dataset_name, trie_cells, range_read_from_key);
		return 0;
	} else if (!strcmp(benchmark_name, "range-prefetch")) {
		bench_range_from_key(dataset_name, trie_cells, range_prefetch_from_key);
		return 0;
	} else if (!strcmp(benchmark_name, "range-skip")) {
		bench_range_from_key(dataset_name, trie_cells, range_skip_from_key);
		return 0;
	} else if (!strcmp(benchmark_name, "mem-usage")) {
		seed_from_time();
		init_dataset(&dataset, dataset_name, dataset_size);

		if (trie_cells != TRIE_CELLS_AUTO) {
			printf("Reporting memory consumption based on given trie size. Smaller size might be possible.\n");
			printf("RESULT: keys=%lu bytes=%lu\n", dataset.num_keys, trie_cells * sizeof(ct_bucket) / CUCKOO_BUCKET_SIZE);
			return 0;
		}

		bench_mem_usage(&dataset);
		return 0;
	} else if (!strcmp(benchmark_name, "mt-insert")) {
		bench_mw_insert(dataset_name, trie_cells, num_threads);
		return 0;
	}
	else if (!strcmp(benchmark_name, "ycsb-a")) {
		ycsb_workload = YCSB_A_SPEC;
		num_threads = 1;
	} else if (!strcmp(benchmark_name, "ycsb-b")) {
		ycsb_workload = YCSB_B_SPEC;
		num_threads = 1;
	} else if (!strcmp(benchmark_name, "ycsb-c")) {
		ycsb_workload = YCSB_C_SPEC;
		num_threads = 1;
	} else if (!strcmp(benchmark_name, "ycsb-d")) {
		ycsb_workload = YCSB_D_SPEC;
		num_threads = 1;
	} else if (!strcmp(benchmark_name, "ycsb-e")) {
		ycsb_workload = YCSB_E_SPEC;
		num_threads = 1;
	} else if (!strcmp(benchmark_name, "ycsb-f")) {
		ycsb_workload = YCSB_F_SPEC;
		num_threads = 1;
	} else if (!strcmp(benchmark_name, "mt-ycsb-a")) {
		ycsb_workload = YCSB_A_SPEC;
	} else if (!strcmp(benchmark_name, "mt-ycsb-b")) {
		ycsb_workload = YCSB_B_SPEC;
	} else if (!strcmp(benchmark_name, "mt-ycsb-c")) {
		ycsb_workload = YCSB_C_SPEC;
	} else if (!strcmp(benchmark_name, "mt-ycsb-d")) {
		ycsb_workload = YCSB_D_SPEC;
	} else if (!strcmp(benchmark_name, "mt-ycsb-e")) {
		ycsb_workload = YCSB_E_SPEC;
	} else if (!strcmp(benchmark_name, "mt-ycsb-f")) {
		ycsb_workload = YCSB_F_SPEC;
	} else {
		printf("Unknown benchmark name\n");
		return 1;
	}

	// Handle YCSB benchmarks
	if (use_uniform_dist)
		ycsb_workload.distribution = YCSB_UNIFORM;

	if (total_ycsb_ops != WORKLOAD_SIZE_DYNAMIC) {
		// Don't scale the total workload size based on number of threads
		ycsb_workload.num_ops = total_ycsb_ops / num_threads;
	}
	bench_ycsb(dataset_name, trie_cells, &ycsb_workload, num_threads);

	return 0;
}
