#include <stdint.h>
#include "cuckoo_trie.h"

#define DATASET_ALL_KEYS 0xFFFFFFFFFFFFFFFFULL

typedef struct {
	int size;
	uint8_t bytes[];
} blob_t;

typedef struct dataset_t_struct {
	uint64_t num_keys;
	uint64_t total_size;  // The total length of all keys
	uint8_t* kvs;
	ct_kv** kv_pointers;
	int (*read_key)(struct dataset_t_struct* dataset, blob_t* buffer);
	void (*close)(struct dataset_t_struct* dataset);
	void* context;
} dataset_t;

int init_dataset(dataset_t* dataset, const char* name, uint64_t keys_requested);
void build_kvs(dataset_t* dataset, int value_size);
