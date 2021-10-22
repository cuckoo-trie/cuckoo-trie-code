#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "main.h"
#include "util.h"

#define MAX_KEY_BYTES_TO_PRINT 20

static void print_key(ct_kv* kv) {
	int i;

	for (i = 0;i < kv_key_size(kv);i++) {
		printf("%02x ", kv_key_bytes(kv)[i]);

		if (i == MAX_KEY_BYTES_TO_PRINT) {
			printf("...");
			break;
		}
	}
}

// Similar to locator_to_entry, but the locator may point to nothing (locator_to_entry
// enters an infinite loop in this case).
ct_entry_storage* try_follow_locator(cuckoo_trie* trie, ct_entry_locator* locator) {
	ct_entry_storage* result;
	ct_entry_local_copy unused;

	//TODO: can enter infinite loop if locator not found?
	result = find_entry_in_pair_by_color(trie, &unused, locator->primary_bucket,
										 locator->tag, locator->color);
	assert(result);
	return result;
}

char* type_name(int type) {
	switch (type) {
		case TYPE_BITMAP: return "BITMAP";
		case TYPE_JUMP: return "JUMP";
		case TYPE_LEAF: return "LEAF";
		case TYPE_UNUSED: return "UNUSED";
		default: return "UNKNOWN";
	}
}

char* leaf_locator_error(cuckoo_trie* trie, ct_entry_locator* locator) {
#ifdef NO_LINKED_LIST
	return 0;
#else
	ct_entry_storage* pointed_entry;
	if (locator->primary_bucket >= trie->num_buckets)
		return "BUCKET_TOO_LARGE";

	pointed_entry = try_follow_locator(trie, locator);
	if (!pointed_entry)
		return "POINTS_TO_NOTHING";

	if (entry_type((ct_entry*) pointed_entry) != TYPE_LEAF)
		return "POINTS_TO_NON_LEAF";

	return 0;
#endif
}

void print_locator(ct_entry_locator* locator) {
	printf("\tLocator: primary_bucket=%u tag=%x color=%d\n",
				   locator->primary_bucket, locator->tag,
				   locator->color);
}

void print_entry(cuckoo_trie* trie, uint64_t bucket, int cell) {
	ct_entry* entry = (ct_entry*) &(trie->buckets[bucket].cells[cell]);
	printf("\tBucket %lu cell %d (%p): %s tag=0x%x last_symbol=0x%x\n",
					   bucket, cell, entry, type_name(entry_type(entry)), entry_tag(entry),
					   entry->last_symbol);
}

int verify_bitmap_children(cuckoo_trie* trie, uint64_t bucket, int cell) {
	int child;
	ct_entry* entry = (ct_entry*) &(trie->buckets[bucket].cells[cell]);
	uint64_t primary_bucket = bucket;
	uint64_t prefix_hash;

	if (entry_is_secondary(entry))
		primary_bucket = unmix_bucket(trie, bucket, entry_tag(entry));

	prefix_hash = (primary_bucket << TAG_BITS) + entry_tag(entry);

	for (child = 0;child < FANOUT + 1;child++) {
		if (!get_bit(entry->child_bitmap, child))
			continue;

		uint64_t child_prefix_hash = accumulate_hash(trie, prefix_hash, child);
		ct_entry_local_copy unused;
		ct_entry_storage* result = find_entry_in_pair_by_parent(trie, &unused,
																hash_to_bucket(child_prefix_hash),
																hash_to_tag(child_prefix_hash),
																child,
																entry_color(entry));
		if (!result) {
			printf("Error: bitmap claims to have child %x, but it doesn't exist\n", child);
			return 0;
		}
	}
	return 1;
}

int verify_jump_child(cuckoo_trie* trie, uint64_t bucket, int cell) {
	int i;
	ct_entry_storage* child;
	ct_entry_local_copy unused;
	ct_entry* entry = (ct_entry*) &(trie->buckets[bucket].cells[cell]);
	uint64_t primary_bucket = bucket;
	uint64_t prefix_hash;

	if (entry_is_secondary(entry))
		primary_bucket = unmix_bucket(trie, bucket, entry_tag(entry));

	prefix_hash = (primary_bucket << TAG_BITS) + entry_tag(entry);

	for (i = 0;i < entry_jump_size(entry);i++)
		prefix_hash = accumulate_hash(trie, prefix_hash, get_jump_symbol(entry, i));

	child = find_entry_in_pair_by_color(trie, &unused, hash_to_bucket(prefix_hash),
										hash_to_tag(prefix_hash), entry_child_color(entry));
	if (!child) {
		printf("Error: Jump child doesn't exist\n");
		return 0;
	}

	if (entry_type((ct_entry*) child) == TYPE_LEAF) {
		printf("Error: Jump child is leaf\n");
		return 0;
	}

	return 1;
}

// Should only be called by the writer thread
int verify_entry(cuckoo_trie* trie, uint64_t bucket, int cell) {
	int is_ok = 1;
	ct_entry* entry = (ct_entry*) &(trie->buckets[bucket].cells[cell]);

	if (entry_type(entry) != TYPE_LEAF) {
		// This entry has a max_leaf field. Verify it.
		char* max_leaf_error = leaf_locator_error(trie, &(entry->max_leaf));
		if (max_leaf_error != NULL) {
			printf("Error: max_leaf locator of bucket %lu cell %d is broken (%s).\n",
				   bucket, cell, max_leaf_error);
			print_locator(&(entry->max_leaf));
			is_ok = 0;
		}
	}

	if (entry_type(entry) == TYPE_BITMAP) {
		if (verify_bitmap_children(trie, bucket, cell) == 0)
			is_ok = 0;
	}
	if (entry_type(entry) == TYPE_JUMP) {
		if (verify_jump_child(trie, bucket, cell) == 0)
			is_ok = 0;
	}
	if (entry_type(entry) == TYPE_LEAF) {
		int is_max_leaf = (entry->next_leaf.primary_bucket == ((uint32_t)-1));
		if (!is_max_leaf) {
			char* next_leaf_error = leaf_locator_error(trie, &(entry->next_leaf));
			if (next_leaf_error != NULL) {
				printf("Error: next_leaf locator of bucket %lu cell %d is broken (%s).\n",
					   bucket, cell, next_leaf_error);
				print_locator(&(entry->next_leaf));
				is_ok = 0;
			}
		}
	}


	return is_ok;
}

int verify_linklist(cuckoo_trie* trie) {
	int cell;
	int leaf_cell;
	int is_ok = 1;
	uint64_t bucket;
	uint64_t leaf_bucket;
	uint64_t linklist_leaves = 0;
	uint64_t num_leaves = 0;
	uint8_t* unlinked_leaves = calloc(trie->num_buckets * CUCKOO_BUCKET_SIZE, 1);
	ct_kv* last_kv = NULL;
	ct_entry_locator next = ((ct_entry*) trie_min_leaf(trie))->next_leaf;

	for (bucket = 0; bucket < trie->num_buckets; bucket++) {
		for (cell = 0; cell < CUCKOO_BUCKET_SIZE; cell++) {
			if (entry_type((ct_entry*) &(trie->buckets[bucket].cells[cell])) == TYPE_LEAF) {
				unlinked_leaves[bucket * CUCKOO_BUCKET_SIZE + cell] = 1;
				num_leaves++;
			}
		}
	}

	while (next.primary_bucket != (uint32_t)-1) {
		ct_entry_storage* leaf = try_follow_locator(trie, &next);
		if (!leaf) {
			printf("Error: Reached a next_leaf locator that doesn't point anywhere.\n");
			print_locator(&next);
			is_ok = 0;
			goto ret;
		}
		if (entry_type((ct_entry*) leaf) != TYPE_LEAF) {
			printf("Error: Reached a next_leaf locator that doesn't point to a leaf.\n");
			print_locator(&next);
			is_ok = 0;
			goto ret;
		}
		if (last_kv != NULL) {
			if (kv_key_compare(entry_kv((ct_entry*) leaf), last_kv) <= 0) {
				printf("Error: Leaf %p key is smaller than previous\n", leaf);
				printf("\tKey of leaf:     ");
				print_key(entry_kv((ct_entry*) leaf));
				printf("\n");
				printf("\tKey of previous: ");
				print_key(last_kv);
				printf("\n");
				is_ok = 0;
				goto ret;
			}
		}

		leaf_bucket = ptr_to_bucket(trie, leaf);
		leaf_cell = entry_index_in_bucket(leaf);
		unlinked_leaves[leaf_bucket * CUCKOO_BUCKET_SIZE + leaf_cell] = 0;

		last_kv = entry_kv((ct_entry*) leaf);
		linklist_leaves++;
		if (linklist_leaves > num_leaves) {
			printf("Error: next_leaf linked-list entered a loop.\n");
			is_ok = 0;
			goto ret;
		}

		next = ((ct_entry*) leaf)->next_leaf;

	}

	for (bucket = 0; bucket < trie->num_buckets; bucket++) {
		for (cell = 0; cell < CUCKOO_BUCKET_SIZE; cell++) {
			if (unlinked_leaves[bucket * CUCKOO_BUCKET_SIZE + cell] == 1) {
				printf("Unlinked leaf\n");
				print_entry(trie, bucket, cell);
				is_ok = 0;
			}
		}
	}

ret:
	free(unlinked_leaves);
	return is_ok;
}

int ct_verify_trie(cuckoo_trie* trie) {
	int cell;
	uint64_t bucket;
	int is_ok = 1;

	for (bucket = 0; bucket < trie->num_buckets; bucket++) {
		if (trie->buckets[bucket].write_lock) {
			printf("Error: Bucket %lu left write-locked\n", bucket);
			is_ok = 0;
		}
		for (cell = 0; cell < CUCKOO_BUCKET_SIZE; cell++) {
			ct_entry* entry = (ct_entry*) &(trie->buckets[bucket].cells[cell]);
			if (entry_type(entry) == TYPE_UNUSED)
				continue;
			if (!verify_entry(trie, bucket, cell)) {
				print_entry(trie, bucket, cell);
				is_ok = 0;
			}
		}
	}

#ifndef NO_LINKED_LIST
	if (!verify_linklist(trie))
		is_ok = 0;
#endif

	return is_ok;
}
