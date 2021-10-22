#ifndef _INCLUDE_CUCKOO_TRIE_H_
#define _INCLUDE_CUCKOO_TRIE_H_

#include <stdint.h>
#include <pthread.h>
#include "key_object.h"

#define S_OK 0
#define S_ALREADYIN 1
#define S_OVERFLOW 2
#define S_KEYTOOLONG 3
#define S_NOTFOUND 4

#define MAX_KEY_BYTES 256
#define EXPORT __attribute__((visibility("default")))

struct cuckoo_trie;
typedef struct cuckoo_trie cuckoo_trie;

struct ct_iter;
typedef struct ct_iter ct_iter;

EXPORT int ct_insert(cuckoo_trie* trie, ct_kv* kv);
EXPORT int ct_upsert(cuckoo_trie* trie, ct_kv* kv, int* created_new);
EXPORT int ct_update(cuckoo_trie* trie, ct_kv* kv);
EXPORT ct_kv* ct_lookup(cuckoo_trie* trie, uint64_t key_size, uint8_t* key_bytes);
EXPORT void ct_iter_goto(ct_iter* iter, uint64_t key_size, uint8_t* key_bytes);
EXPORT ct_kv* ct_iter_next(ct_iter* iter);
EXPORT ct_iter* ct_iter_alloc(cuckoo_trie* trie);
EXPORT cuckoo_trie* ct_alloc(uint64_t num_cells);
EXPORT void ct_free(cuckoo_trie* trie);

// Internal APIs, for testing only
EXPORT int ct_verify_trie(cuckoo_trie* trie);
EXPORT void ct_enable_debug_logs();
EXPORT void ct_mtdbg_start();
EXPORT void ct_mtdbg_register_thread(pthread_t thread_id);
EXPORT void ct_mtdbg_set_enabled(int enabled);
EXPORT void ct_mtdbg_thread_done();
EXPORT void ct_mtdbg_seed(uint64_t seed);

#endif
