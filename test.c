#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "cuckoo_trie.h"
#include "random.h"
#include "dataset.h"

#define MAX_KEY_BYTES_TO_PRINT 20
#define DEFAULT_VALUE_SIZE 8

void print_bytes(uint64_t size, uint8_t* bytes) {
	int i;

	if (bytes == NULL) {
		printf("(NULL)");
		return;
	}

	for (i = 0;i < size;i++) {
		printf("%02x ", bytes[i]);

		if (i == MAX_KEY_BYTES_TO_PRINT) {
			printf("...");
			break;
		}
	}
}

void print_key(ct_kv* kv) {
	print_bytes(kv_key_size(kv), kv_key_bytes(kv));
}

void fill_random_kv(ct_kv* kv, uint64_t max_len) {
	uint64_t len = rand_uint64() % (max_len + 1);
	kv_init(kv, len, DEFAULT_VALUE_SIZE);
	random_bytes(kv_key_bytes(kv), len);
	memset(kv_value_bytes(kv), 0xAB, DEFAULT_VALUE_SIZE);
}

void random_len_bytes(uint64_t* len, uint8_t* bytes, uint64_t max_len) {
	*len = rand_uint64() % (max_len + 1);
	random_bytes(bytes, *len);
}

// Check whether <key> is identical to one of the keys stored in <keys_buf>.
// The keys are assumed to be tightly packed.
int key_in_buf(uint8_t* kvs_buf, uint64_t num_keys, ct_kv* kv) {
	uint64_t i;
	uint8_t* buf_pos = kvs_buf;

	for (i = 0;i < num_keys;i++) {
		ct_kv* cur_kv = (ct_kv*)buf_pos;

		if (kv_key_compare(cur_kv, kv) == 0)
			return 1;

		buf_pos += kv_size(cur_kv);
	}
	return 0;
}

// The buffer size should be at least num_keys * (sizeof(ct_key) + max_key_len) bytes
void gen_uniq_kvs(uint8_t* buf, uint64_t num_kvs, uint64_t max_key_len) {
	uint64_t i;
	uint8_t* buf_pos;

	buf_pos = buf;
	i = 0;
	while (i < num_kvs) {
		ct_kv* kv = (ct_kv*) buf_pos;
		fill_random_kv(kv, max_key_len);
		if (key_in_buf(buf, i, kv))
			continue;

		buf_pos += kv_size(kv);
		i++;
	}
}

// The buffer size should be at least
// num_kvs * kv_required_size(max_key_len, DEFAULT_VALUE_SIZE) bytes
void gen_random_kvs(uint8_t* buf, uint64_t num_kvs, uint64_t max_key_len) {
	uint64_t i;
	uint8_t* buf_pos;

	buf_pos = buf;
	i = 0;
	while (i < num_kvs) {
		ct_kv* kv = (ct_kv*) buf_pos;
		fill_random_kv(kv, max_key_len);

		buf_pos += kv_size(kv);
		i++;
	}
}

// Test that ct_insert returns the appropriate result
void test_insert(int verbose) {
	const uint64_t num_keys = 5000;
	const uint64_t max_key_len = 16;

	int result;
	int i;
	int key_exists;
	uint8_t* kvs_buf = malloc((kv_required_size(max_key_len, DEFAULT_VALUE_SIZE)) * num_keys);
	uint8_t* buf_pos = kvs_buf;
	cuckoo_trie* trie = ct_alloc(5000);

	for (i = 0;i < num_keys; i++) {
		ct_kv* kv = (ct_kv*) buf_pos;
		fill_random_kv(kv, max_key_len);

		key_exists = key_in_buf(kvs_buf, i, kv);

		if (verbose) {
			printf("Inserting key %p: ", kv);
			print_key(kv);
			printf("\n");
		}

		result = ct_insert(trie, kv);
		if (result == S_OVERFLOW) {
			printf("Trie full. Inserted %d keys.\n", i - 1);
			printf("OK!\n");
			break;
		}
		if (!ct_verify_trie(trie)) {
			printf("ERROR! Trie structure is broken.\n");
			break;
		}

		if (key_exists && result != S_ALREADYIN) {
			printf("ERROR! expected ALREADYIN but got %d.\n", result);
			break;
		}
		if (!key_exists && result != S_OK) {
			printf("ERROR! expected OK but got %d.\n", result);
			break;
		}

		buf_pos += kv_size(kv);
	}
}

int kv_ptr_compare(const void* k1_ptr, const void* k2_ptr) {
	return kv_key_compare(* (ct_kv**)k1_ptr,* (ct_kv**)k2_ptr);
}

// Test that iteration over the trie returns the expected keys
void test_iter() {
	const uint64_t num_kvs = 1000;
	const uint64_t max_key_len = 16;

	uint64_t i;
	int result;
	uint8_t range_start_buf[max_key_len];
	uint64_t range_start_size;
	uint8_t* kvs_buf = malloc(kv_required_size(max_key_len, DEFAULT_VALUE_SIZE) * num_kvs);
	ct_kv** kv_pointers = malloc(sizeof(ct_kv*) * num_kvs);
	uint8_t* buf_pos = kvs_buf;
	ct_kv* next_kv;
	cuckoo_trie* trie = ct_alloc(3000);

	// Generate a random dataset and insert into the trie
	i = 0;
	while (i < num_kvs) {
		ct_kv* kv = (ct_kv*) buf_pos;
		fill_random_kv(kv, max_key_len);
		if (key_in_buf(kvs_buf, i, kv))
			continue;    // Don't insert duplicate keys

		result = ct_insert(trie, kv);
		if (result != S_OK) {
			printf("Insertion error %d\n", result);
			return;
		}
		kv_pointers[i] = kv;
		buf_pos += kv_size(kv);
		i++;
	}

	// Sort the key pointers
	qsort(kv_pointers, num_kvs, sizeof(ct_kv*), kv_ptr_compare);

	// Generate range scan starting point
	random_len_bytes(&range_start_size, range_start_buf, max_key_len);

	// Find the rank of the starting point
	uint64_t expected_rank = 0;
	while (expected_rank < num_kvs) {
		if (kv_key_compare_to(kv_pointers[expected_rank], range_start_size, range_start_buf) >= 0)
			break;
		expected_rank++;
	}

	ct_iter* iter = ct_iter_alloc(trie);
	if (!iter) {
		printf("Error: Couldn't allocate iterator\n");
		return;
	}

	ct_iter_goto(iter, range_start_size, range_start_buf);
	while (expected_rank < num_kvs) {
		next_kv = ct_iter_next(iter);
		if (next_kv != kv_pointers[expected_rank]) {
			printf("Error: Got incorrect key\n");
			printf("\tStarted from: ");
			print_bytes(range_start_size, range_start_buf);
			printf("\n");
			printf("\tExpected:     ");
			print_key(kv_pointers[expected_rank]);
			printf("(#%lu in sorted order)\n", expected_rank);
			printf("\tGot:          ");
			print_key(next_kv);
			printf("\n");
			return;
		}
		expected_rank++;
	}

	next_kv = ct_iter_next(iter);
	if (next_kv != NULL) {
		printf("Error: Expected end-of-index, but got another key\n");
		return;
	}
	printf("OK!\n");
}

typedef struct {
	cuckoo_trie* trie;
	uint8_t* kvs;
	uint64_t num_kvs;
} mt_insert_lookup_ctx;

// Writer thread: Insert all keys into the trie
void* mt_insert_lookup_writer_thread(void* arg) {
	uint64_t i;
	int result;
	uint8_t* buf_pos;
	mt_insert_lookup_ctx* ctx = (mt_insert_lookup_ctx*)arg;

	buf_pos = ctx->kvs;
	for (i = 0;i < ctx->num_kvs;i++) {
		ct_kv* kv = (ct_kv*)buf_pos;
		result = ct_insert(ctx->trie, kv);
		if (result != S_OK) {
			printf("Error: ct_insert returned %d in writer\n", result);
			return NULL;
		}
		buf_pos += kv_size(kv);
	}
#ifdef TEST_DEBUG
	ct_mtdbg_set_enabled(0);
#endif
	return NULL;
}

// Reader thread: search for all keys in the trie while they're being inserted.
// We try to trigger more edge cases by searching for the key that is being inserted
// right now.
void* mt_insert_lookup_reader_thread(void* arg) {
	uint64_t pos;
	uint64_t i;
	uint64_t step;
	uint8_t* buf_pos;
	mt_insert_lookup_ctx* ctx = (mt_insert_lookup_ctx*)arg;

	step = 1;
	pos = 0;
	buf_pos = ctx->kvs;
	while (1) {
		ct_kv* kv = (ct_kv*)buf_pos;
		ct_kv* result = ct_lookup(ctx->trie, kv_key_size(kv), kv_key_bytes(kv));

		if (result == NULL) {
			// The key wasn't inserted yet, so we're ahead of the writer. Try this key again
			// until the writer reaches it.
			step = 1;
			continue;
		}

		if (pos == ctx->num_kvs - 1)
			break;  // We found the last key, so the writer should have finished by now

		// We found the key, so we're behind the writer. Advance <step> keys.
		for (i = 0;i < step && pos < ctx->num_kvs - 1;i++) {
			buf_pos += kv_size(kv);
			kv = (ct_kv*)buf_pos;
			pos++;
		}
		step *= 2;
	}

	// The writer should have finished. Verify that all keys are in the trie
	buf_pos = ctx->kvs;
	for (i = 0;i < ctx->num_kvs;i++) {
		ct_kv* kv = (ct_kv*)buf_pos;
		ct_kv* result = ct_lookup(ctx->trie, kv_key_size(kv), kv_key_bytes(kv));
		if (result == NULL) {
			printf("Error: key %lu not found after the writer should have finished\n", i);
			return NULL;
		}

		buf_pos += kv_size(kv);
	}

	return NULL;
}

// Perform lookups in parallel with inserts
void test_mt_insert_lookup() {
	const uint64_t num_kvs = 10000;
	const uint64_t max_key_len = 16;
	int result;
	pthread_t writer_thread;
	pthread_t reader_thread;
	mt_insert_lookup_ctx writer_ctx;
	mt_insert_lookup_ctx reader_ctx;
	uint64_t buf_size = num_kvs * kv_required_size(max_key_len, DEFAULT_VALUE_SIZE);
	uint8_t* writer_buf = malloc(buf_size);
	uint8_t* reader_buf = malloc(buf_size);
	cuckoo_trie* trie = ct_alloc(num_kvs * 4);

	gen_uniq_kvs(writer_buf, num_kvs, max_key_len);
	memcpy(reader_buf, writer_buf, buf_size);

	reader_ctx.kvs = reader_buf;
	reader_ctx.trie = trie;
	reader_ctx.num_kvs = num_kvs;
	writer_ctx.kvs = writer_buf;
	writer_ctx.trie = trie;
	writer_ctx.num_kvs = num_kvs;

#ifdef TEST_DEBUG
	// Enable MT debugging before starting the threads, or they'll perform non-debugged
	// reads when started until we enable it later.
	ct_mtdbg_set_enabled(1);
#endif

	result = pthread_create(&reader_thread, NULL, mt_insert_lookup_reader_thread, &reader_ctx);
	if (result != 0) {
		printf("Error creating reader thread\n");
		return;
	}

	result = pthread_create(&writer_thread, NULL, mt_insert_lookup_writer_thread, &writer_ctx);
	if (result != 0) {
		printf("Error creating reader thread\n");
		return;
	}

#ifdef TEST_DEBUG
	ct_mtdbg_register_thread(reader_thread);
	ct_mtdbg_register_thread(writer_thread);
	ct_mtdbg_start();
#endif

	result = pthread_join(reader_thread, NULL);
	if (result != 0) {
		printf("Error joining reader\n");
		return;
	}

	result = pthread_join(writer_thread, NULL);
	if (result != 0) {
		printf("Error joining writer\n");
		return;
	}

	printf("Done.\n");
}

typedef struct {
	cuckoo_trie* trie;
	uint8_t* kvs;
	uint64_t num_kvs;
	int writer_done;
	int verbose;
} mt_insert_scan_ctx;

void* mt_insert_scan_writer_thread(void* arg) {
	uint64_t i;
	int result;
	uint8_t* buf_pos;
	mt_insert_scan_ctx* ctx = (mt_insert_scan_ctx*)arg;

	buf_pos = ctx->kvs;
	for (i = 0;i < ctx->num_kvs;i++) {
		ct_kv* kv = (ct_kv*)buf_pos;
		if (ctx->verbose) {
			printf("Inserting key #%06lu: ", i);
			print_key(kv);
			printf("\n");
		}
		result = ct_insert(ctx->trie, kv);
		if (result != S_OK) {
			printf("Error: ct_insert returned %d in writer\n", result);
			return NULL;
		}
		buf_pos += kv_size(kv);
	}

	__atomic_store_n(&(ctx->writer_done), 1, __ATOMIC_RELEASE);

#ifdef TEST_DEBUG
	ct_mtdbg_thread_done();
#endif

	return NULL;
}

void* mt_insert_scan_scan_thread(void* arg) {
	uint64_t iterations = 0;
	uint64_t kvs_seen;
	ct_kv* prev_kv = NULL;
	ct_kv* cur_kv = NULL;
	mt_insert_scan_ctx* ctx = (mt_insert_scan_ctx*)arg;
	ct_iter* iter = ct_iter_alloc(ctx->trie);

	// Use atomic_load to force re-reading writer_done every iteration.
	while (!__atomic_load_n(&(ctx->writer_done), __ATOMIC_ACQUIRE)) {
		ct_iter_goto(iter, 0, NULL);  // Place the iterator before all the keys

		kvs_seen = 0;
		while (1) {
			prev_kv = cur_kv;
			cur_kv = ct_iter_next(iter);
			if (cur_kv == NULL)
				break;  // Reached the maximal key in the trie

			kvs_seen++;
			if (kvs_seen > ctx->num_kvs) {
				printf("Got more keys than there are in the trie!\n");
				return NULL;
			}

			if (prev_kv != NULL) {
				if (kv_key_compare(prev_kv, cur_kv) >= 0) {
					printf("Got keys in decreasing order!\n");
					printf("\tCurrent: ");
					print_key(cur_kv);
					printf("\n\tPrevious: ");
					print_key(prev_kv);
					printf("\n");
					return NULL;
				}
			}
		}
		iterations++;
	}
	printf("Scanning done. Completed %lu iterations.\n", iterations);
	return NULL;
}

// Scan the whole trie while performing inserts
void test_mt_insert_scan(int verbose) {
	const uint64_t num_kvs = 10000;
	const uint64_t max_key_len = 16;
	int result;
	pthread_t scan_thread;
	pthread_t writer_thread;
	mt_insert_scan_ctx ctx;
	uint8_t* kvs_buf = malloc(num_kvs * kv_required_size(max_key_len, DEFAULT_VALUE_SIZE));
	cuckoo_trie* trie = ct_alloc(num_kvs * 4);

	gen_uniq_kvs(kvs_buf, num_kvs, max_key_len);
	ctx.kvs = kvs_buf;
	ctx.num_kvs = num_kvs;
	ctx.trie = trie;
	ctx.writer_done = 0;
	ctx.verbose = verbose;

#ifdef TEST_DEBUG
	ct_mtdbg_set_enabled(1);
#endif

	result = pthread_create(&scan_thread, NULL, mt_insert_scan_scan_thread, &ctx);
	if (result != 0) {
		printf("Error creating scan thread\n");
		return;
	}

	result = pthread_create(&writer_thread, NULL, mt_insert_scan_writer_thread, &ctx);
	if (result != 0) {
		printf("Error creating writer thread\n");
		return;
	}

#ifdef TEST_DEBUG
	ct_mtdbg_register_thread(scan_thread);
	ct_mtdbg_register_thread(writer_thread);
	ct_mtdbg_start();
#endif

	result = pthread_join(scan_thread, NULL);
	if (result != 0) {
		printf("Error joining scan thread\n");
		return;
	}

	result = pthread_join(writer_thread, NULL);
	if (result != 0) {
		printf("Error joining writer\n");
		return;
	}
}

typedef struct {
	uint64_t num_kvs;
	uint64_t max_key_len;
	uint8_t* kvs;
	int writer_done;
	int verbose;
	cuckoo_trie* trie;
} mt_insert_succ_ctx;

void* mt_insert_succ_writer_thread(void* arg) {
	uint64_t i;
	int result;
	uint8_t* buf_pos;
	mt_insert_succ_ctx* ctx = (mt_insert_succ_ctx*)arg;

	buf_pos = ctx->kvs;
	for (i = 0;i < ctx->num_kvs;i++) {
		ct_kv* kv = (ct_kv*)buf_pos;
		if (ctx->verbose) {
			printf("Inserting key %p: ", kv);
			print_key(kv);
			printf("\n");
		}
		result = ct_insert(ctx->trie, kv);
		if (result == S_OVERFLOW) {
			printf("Trie full. Inserted %lu keys\n", i);
			break;
		}
		if (result != S_OK && result != S_ALREADYIN) {
			printf("Error: ct_insert returned %d in writer\n", result);
			return NULL;
		}
		buf_pos += kv_size(kv);
	}

	__atomic_store_n(&(ctx->writer_done), 1, __ATOMIC_RELEASE);

#ifdef TEST_DEBUG
	ct_mtdbg_thread_done();
#endif

	return NULL;
}

// Find the successor of random keys
void* mt_insert_succ_reader_thread(void* arg) {
	ct_kv* succ;
	uint64_t iters = 0;
	mt_insert_succ_ctx* ctx = (mt_insert_succ_ctx*)arg;
	uint64_t key_size;
	uint8_t* key = malloc(ctx->max_key_len);
	ct_iter* iter = ct_iter_alloc(ctx->trie);

	while (!__atomic_load_n(&(ctx->writer_done), __ATOMIC_ACQUIRE)) {
		random_len_bytes(&key_size, key, ctx->max_key_len);
		if (ctx->verbose) {
			printf("Setting iterator to ");
			print_bytes(key_size, key);
			printf("\n");
		}
		ct_iter_goto(iter, key_size, key);
		succ = ct_iter_next(iter);
		if (succ && kv_key_compare_to(succ, key_size, key) < 0) {
			printf("Got incorrect successor!\n");
			printf("\tString:    ");
			print_bytes(key_size, key);
			printf("\n\tSuccessor: ");
			print_key(succ);
			printf("\n");
			return NULL;
		}
		iters++;
	}
	printf("Reader done. Completed %lu iterations.\n", iters);
	return NULL;
}

void test_mt_insert_succ(int verbose) {
	const uint64_t num_kvs = 10000;
	const uint64_t max_key_len = 16;
	int result;
	pthread_t writer_thread;
	pthread_t reader_thread;
	mt_insert_succ_ctx ctx;
	uint8_t* kvs_buf = malloc(num_kvs * kv_required_size(max_key_len, DEFAULT_VALUE_SIZE));
	cuckoo_trie* trie = ct_alloc(num_kvs);

	// The reader thread uses the random generator. If the writer trhead will also use
	// it its output will depend on the scheduling of the threads. Therefore, we generate
	// the keys for the writer thread here and only use the random generator in the reader
	// thread.
	gen_random_kvs(kvs_buf, num_kvs, max_key_len);

	ctx.trie = trie;
	ctx.num_kvs = num_kvs;
	ctx.max_key_len = max_key_len;
	ctx.kvs = kvs_buf;
	ctx.verbose = verbose;
	ctx.writer_done = 0;

#ifdef TEST_DEBUG
	ct_mtdbg_set_enabled(1);
#endif

	result = pthread_create(&writer_thread, NULL, mt_insert_succ_writer_thread, &ctx);
	if (result != 0) {
		printf("Error creating writer thread\n");
		return;
	}

	result = pthread_create(&reader_thread, NULL, mt_insert_succ_reader_thread, &ctx);
	if (result != 0) {
		printf("Error creating reader thread\n");
		return;
	}

#ifdef TEST_DEBUG
	ct_mtdbg_register_thread(reader_thread);
	ct_mtdbg_register_thread(writer_thread);
	ct_mtdbg_start();
#endif

	result = pthread_join(writer_thread, NULL);
	if (result != 0) {
		printf("Error joining writer thread\n");
		return;
	}

	result = pthread_join(reader_thread, NULL);
	if (result != 0) {
		printf("Error joining reader thread\n");
		return;
	}
}

typedef struct {
	cuckoo_trie* trie;
	uint8_t* kvs;
	uint64_t num_kvs;
	int verbose;
} mt_insert_ctx;

void* mt_insert_thread(void* arg) {
	uint64_t i;
	int ret;

	mt_insert_ctx* ctx = (mt_insert_ctx*) arg;
	uint8_t* buf_pos = ctx->kvs;

	for (i = 0;i < ctx->num_kvs; i++) {
		ct_kv* kv = (ct_kv*) buf_pos;
		if (ctx->verbose) {
			printf("Inserting ");
			print_key(kv);
			printf("\n");
		}
		ret = ct_insert(ctx->trie, kv);
		if (ret == S_OVERFLOW) {
			// The mt-insert test expects the trie to be large enough to hold all keys, and
			// calls ct_verify_trie at the end. An overflow shouldn't happen.
			printf("Error: trie full after %lu keys.\n", i);
			break;
		}
		buf_pos += kv_size(kv);
	}
#ifdef TEST_DEBUG
	ct_mtdbg_thread_done();
#endif
	return NULL;
}

void test_mt_insert(char* dataset_name, int verbose) {
	const uint64_t num_kvs = 10000;
	const uint64_t num_threads = 8;

	int i;
	dataset_t dataset;
	mt_insert_ctx thread_contexts[num_threads];
	int result;
	pthread_t insert_threads[num_threads];
	cuckoo_trie* trie;

#ifdef TEST_DEBUG
	ct_mtdbg_seed(rand_dword());
#else
	rand_dword();
#endif

	result = init_dataset(&dataset, dataset_name, num_kvs);
	if (!result) {
		printf("Error creating dataset\n");
		return;
	}
	build_kvs(&dataset, DEFAULT_VALUE_SIZE);
	trie = ct_alloc(dataset.num_keys * 4);

	uint64_t workload_start = 0;
	uint64_t workload_end;
	for (i = 0; i < num_threads; i++) {
		mt_insert_ctx* ctx = &(thread_contexts[i]);
		workload_end = dataset.num_keys * (i+1) / num_threads;
		ctx->num_kvs = workload_end - workload_start;
		ctx->kvs = (uint8_t*) dataset.kv_pointers[workload_start];
		ctx->trie = trie;
		ctx->verbose = verbose;

		workload_start = workload_end;
	}

#ifdef TEST_DEBUG
	ct_mtdbg_set_enabled(1);
#endif

	for (i = 0;i < num_threads;i++) {
		result = pthread_create(&(insert_threads[i]), NULL, mt_insert_thread, &(thread_contexts[i]));
		if (result != 0) {
			printf("Error creating insert thread\n");
			return;
		}
#ifdef TEST_DEBUG
		ct_mtdbg_register_thread(insert_threads[i]);
#endif
	}

#ifdef TEST_DEBUG
	ct_mtdbg_start();
#endif

	for (i = 0;i < num_threads;i++) {
		result = pthread_join(insert_threads[i], NULL);
		if (result != 0) {
			printf("Error joining thread\n");
			return;
		}
	}

#ifdef TEST_DEBUG
	// Allow ct_verify_trie to access the trie
	ct_mtdbg_set_enabled(0);
#endif // TEST_DEBUG

	printf("Insertion done. Verifying trie...\n");
	if (!ct_verify_trie(trie)) {
		printf("ERROR! Trie structure is broken.\n");
		return;
	}

	printf("OK!\n");
}

int main(int argc, char** argv) {
	int i;
	char* num_end;
	char* test_name = NULL;
	char* dataset_name = "rand-var";
	uint64_t seed = 0;
	int verbose = 0;

	for (i = 1;i < argc;i++) {
		if (!strcmp(argv[i], "-s")) {
			if (i == argc - 1) {
				printf("Error: -s expects an argument\n");
				return 1;
			}
			seed = strtoul(argv[i+1], &num_end, 10);
			if (*num_end != '\0') {
				printf("Error: invalid argument to -s\n");
				return 1;
			}
			i++;
		} else if (!strcmp(argv[i], "-v")) {
			verbose = 1;
#ifdef TEST_DEBUG
		} else if (!strcmp(argv[i], "-vv")) {
			verbose = 1;
			ct_enable_debug_logs();
#endif
		} else if (test_name == NULL) {
			test_name = argv[i];
		} else {
			dataset_name = argv[i];
		}
	}

	if (seed)
		rand_seed(seed);
	else
		seed_and_print();

	if (test_name == NULL)
		test_name = "insert";

	if (!strcmp(test_name, "insert"))
		test_insert(verbose);
	else if (!strcmp(test_name, "iter"))
		test_iter();
	else if (!strcmp(test_name, "mt-insert-lookup"))
		test_mt_insert_lookup();
	else if (!strcmp(test_name, "mt-insert-scan"))
		test_mt_insert_scan(verbose);
	else if (!strcmp(test_name, "mt-insert-succ"))
		test_mt_insert_succ(verbose);
	else if (!strcmp(test_name, "mt-insert"))
		test_mt_insert(dataset_name, verbose);
	else
		printf("Unknown test name '%s'\n", test_name);
	return 0;
}
