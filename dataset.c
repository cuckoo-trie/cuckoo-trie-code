#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dataset.h"
#include "compiler.h"
#include "random.h"
#include "util.h"

#define DATASET_DEFAULT_SIZE 10000000
#define MAX_KEY_SIZE 256
#define RAND_VAR_MAX_SIZE 16

int random_dataset_read_key(dataset_t* dataset, blob_t* buf) {
	int key_len = (uintptr_t)(dataset->context);
	random_bytes(buf->bytes, key_len);
	buf->size = key_len;
	return 1;
}

int rand_var_read_key(dataset_t* dataset, blob_t* buf) {
	UNUSED_PARAMETER(dataset);
	int key_len = rand_uint64() % RAND_VAR_MAX_SIZE;
	random_bytes(buf->bytes, key_len);
	buf->size = key_len;
	return 1;
}

void do_nothing_close(dataset_t* dataset) {
	UNUSED_PARAMETER(dataset);
	// Do nothing
}

int file_dataset_read_key(dataset_t* dataset, blob_t* buf) {
	int items_read;
	uint32_t size;
	FILE* dataset_file = (FILE*)(dataset->context);

	items_read = fread(&size, sizeof(size), 1, dataset_file);
	if (items_read != 1) {
		printf("Error reading key\n");
		return 0;
	}
	if (size > MAX_KEY_SIZE) {
		printf("Key too long\n");
		return 0;
	}
	buf->size = size;

	items_read = fread(buf->bytes, buf->size, 1, dataset_file);
	if (items_read != 1) {
		printf("Error reading key\n");
		return 0;
	}
	return 1;
}

void file_dataset_close(dataset_t* dataset) {
	fclose((FILE*)(dataset->context));
}

int init_random_dataset(dataset_t* dataset, uint64_t num_keys, int key_len) {
	if (num_keys == DATASET_ALL_KEYS)
		num_keys = DATASET_DEFAULT_SIZE;

	if (key_len > MAX_KEY_SIZE)
		return 0;

	dataset->num_keys = num_keys;
	dataset->read_key = random_dataset_read_key;
	dataset->close = do_nothing_close;
	dataset->context = (void*)(uintptr_t)key_len;

	return 1;
}

// Initialize a dataset of variable-size keys
int init_rand_var_dataset(dataset_t* dataset, uint64_t num_keys) {
	if (num_keys == DATASET_ALL_KEYS)
		num_keys = DATASET_DEFAULT_SIZE;

	dataset->num_keys = num_keys;
	dataset->read_key = rand_var_read_key;
	dataset->close = do_nothing_close;
	dataset->context = NULL;

	return 1;
}

int init_dataset(dataset_t* dataset, const char* name, uint64_t keys_requested) {
	int items_read;
	int key_size;
	char* endptr;
	FILE* dataset_file;

	dataset->kvs = NULL;

	if (!strcmp(name, "rand-var")) {
		return init_rand_var_dataset(dataset, keys_requested);
	}

	if (!strncmp(name, "rand-", 5)) {
		key_size = strtol(name + 5, &endptr, 10);
		if (*endptr != 0)
			return 0;  // string was not a number
		return init_random_dataset(dataset, keys_requested, atoi(name + 5));
	}

	dataset_file = fopen(name, "rb");
	if (!dataset_file)
		return 0;

	items_read = fread(&(dataset->num_keys), sizeof(dataset->num_keys), 1, dataset_file);
	if (items_read != 1)
		goto close_and_fail;
	if (dataset->num_keys > keys_requested)
		dataset->num_keys = keys_requested;

	items_read = fread(&(dataset->total_size), sizeof(dataset->total_size), 1, dataset_file);
	if (items_read != 1)
		goto close_and_fail;

	dataset->read_key = file_dataset_read_key;
	dataset->close = file_dataset_close;
	dataset->context = dataset_file;
	return 1;

	close_and_fail:
	fclose(dataset_file);
	return 0;
}

// Write all dataset keys as ct_kv objects one after the other into a buffer
// and return it.
void build_kvs(dataset_t* dataset, int value_size) {
	uint64_t i;
	uint64_t max_key_size = 0;
	dynamic_buffer_t kvs_buf;
	blob_t* key_buf = malloc(sizeof(blob_t) + MAX_KEY_SIZE);
	uint64_t buf_pos = 0;
	if (dataset->kvs != NULL)
		return;   // We already read the dataset

	dynamic_buffer_init(&kvs_buf);
	dataset->kv_pointers = malloc(dataset->num_keys * sizeof(ct_kv*));

	for (i = 0;i < dataset->num_keys;i++) {
		int ok = dataset->read_key(dataset, key_buf);
		if (!ok)
			return;

		uint64_t kv_len = kv_required_size(key_buf->size, value_size);
		buf_pos = dynamic_buffer_extend(&kvs_buf, kv_len);

		ct_kv* cur_kv = (ct_kv*) (kvs_buf.ptr + buf_pos);
		kv_init(cur_kv, key_buf->size, value_size);
		memcpy(kv_key_bytes(cur_kv), key_buf->bytes, key_buf->size);
		memset(kv_value_bytes(cur_kv), 0xAB, value_size);
	}

	buf_pos = 0;
	for (i = 0;i < dataset->num_keys;i++) {
		dataset->kv_pointers[i] = (ct_kv*) (kvs_buf.ptr + buf_pos);
		buf_pos += kv_size(dataset->kv_pointers[i]);
	}

	dataset->kvs = kvs_buf.ptr;
	free(key_buf);
}
