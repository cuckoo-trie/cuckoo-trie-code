#include "atomics.h"

typedef struct {
	ct_entry_local_copy entry;
	uint64_t prefix_hash;
} ct_path_entry;

typedef struct {
	ct_entry_local_copy containing_entry;
	ct_path_entry* last_path_entry;   // points inside finger.path
	uint64_t prefix_len;
	uint64_t prefix_hash;
	uint8_t last_prefix_symbol;

	// If the finger is in the middle of a jump node, how deep it is, in symbols
	uint64_t depth_in_jump;
	cuckoo_trie* trie;
	ct_lock_mgr lock_mgr;

	// Each entry is a different node. Includes the node the finger is currently in.
	ct_path_entry path[MAX_KEY_SYMBOLS];
} ct_finger;

// Finding the predecessor of a node consists of three stages: ascending until we can descend to the left,
// descending once to the left and going to the maximal leaf under that node. ct_pred_locator stores
// the output of the first stage. That is, the description of the node whose maximal descendant is the
// predecessor.
typedef struct {
	// subtree[0] is the maximal subtree smaller than the key, subtree[1] is the maximal
	// subtree smaller than subtree[0].
	struct {
		// The position of the parent bitmap of this subtree in the path of the associated finger
		ct_path_entry* path_pos;

		uint64_t primary_bucket;
		uint8_t parent_color;
		uint8_t last_symbol;
		uint8_t tag;
	} subtree[NUM_LINKED_LISTS];
	ct_entry_local_copy predecessor[NUM_LINKED_LISTS];
	ct_finger* finger;
} ct_pred_locator;

struct ct_iter {
	int is_exhausted;

	// If 0, fetch a new leaf and return it in ct_iter_next.
	// If 1, report the maximal leaf already stored in the iterator.
	int report_current;
	ct_entry_local_copy leaves[NUM_LINKED_LISTS];
	cuckoo_trie* trie;
};

uint64_t ptr_to_bucket(cuckoo_trie* trie, ct_entry_storage* entry);
uint64_t entry_index_in_bucket(ct_entry_storage* entry);
uint64_t hash_to_bucket(uint64_t x);
uint64_t hash_to_tag(uint64_t x);
uint64_t accumulate_hash(cuckoo_trie* trie, uint64_t x, uint64_t symbol);
uint64_t mix_bucket(cuckoo_trie* trie, uint64_t bucket_num, uint64_t tag);
uint64_t unmix_bucket(cuckoo_trie* trie, uint64_t bucket_num, uint64_t tag);
ct_entry_storage* find_entry_in_pair_by_parent(cuckoo_trie* trie, ct_entry_local_copy* result,
											   uint64_t primary_bucket, uint64_t tag,
											   uint64_t last_symbol, uint64_t parent_color);
ct_entry_storage* find_entry_in_pair_by_color(cuckoo_trie* trie, ct_entry_local_copy* result,
											  uint64_t primary_bucket, uint64_t tag,
											  uint8_t color);
uint64_t get_jump_symbol(ct_entry* entry, uint64_t symbol_idx);
