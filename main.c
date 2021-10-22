#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/mman.h>
#include <stdio.h>

#include "cuckoo_trie.h"
#include "random.h"
#include "main.h"
#include "util.h"

// The root has to have a last symbol in order to have an alternate bucket.
// The following value was arbitrarily chosen.
#define ROOT_LAST_SYMBOL 0

// Children of jump nodes (and the root) use this as parent_color, so that
// they aren't mistakenly considered children of bitmap nodes.
// Note that valid colors are 0 .. 2 * CUCKOO_BUCKET_SIZE, /inclusive/, to
// make unused_color_in_pair more efficient
#define MAX_VALID_COLOR (2 * CUCKOO_BUCKET_SIZE)
#define INVALID_COLOR (MAX_VALID_COLOR + 1)

// Used to locate the root in find_root. Can be any valid color.
#define ROOT_COLOR 0

#define HASH_START_VALUE 0

#if (BITS_PER_SYMBOL == 5) && (TAG_BITS == 4)
#define HASH_MULTIPLIER 37 // A random small prime
#endif

#if (BITS_PER_SYMBOL == 4) && (TAG_BITS == 4)
#define HASH_MULTIPLIER 19
#endif

uint64_t ptr_to_bucket(cuckoo_trie* trie, ct_entry_storage* entry) {
	return ((uintptr_t)entry - (uintptr_t)(trie->buckets)) / sizeof(ct_bucket);
}


uint64_t entry_index_in_bucket(ct_entry_storage* entry) {
	assert(sizeof(ct_bucket) == 64 || sizeof(ct_bucket) == 128);

	// Optimize the common case
	if (sizeof(ct_entry_storage) == 15)
		return ((~((uintptr_t)entry)) + 1) & 0xf;

	// We assume that buckets are aligned to a multiple of sizeof(ct_bucket)
	ct_bucket* bucket_start = (ct_bucket*) ( ((uintptr_t)entry) & (~(sizeof(ct_bucket) - 1)) );
	uint8_t* entries_start = (uint8_t*)(bucket_start->cells);
	assert((((uint8_t*)entry) - entries_start) % sizeof(ct_entry_storage) == 0);
	return (((uint8_t*)entry) - entries_start) / sizeof(ct_entry_storage);
}

// Compute the secondary bucket number given the primary
uint64_t mix_bucket(cuckoo_trie* trie, uint64_t bucket_num, uint64_t tag) {
	uint64_t mix_value = trie->bucket_mix_table[tag];
	int64_t result = bucket_num - mix_value;
	result += trie->num_buckets & (result < 0 ? ((uint64_t)-1) : 0);
	return result;
}

// Compute the primary bucket number given the secondary
uint64_t unmix_bucket(cuckoo_trie* trie, uint64_t bucket_num, uint64_t tag) {
	int64_t result;
	uint64_t mix_value = trie->bucket_mix_table[tag];
	result = bucket_num + mix_value;
	if (result >= trie->num_buckets)
		result -= trie->num_buckets;

	assert(mix_bucket(trie, result, tag) == bucket_num);
	return result;
}

uint64_t accumulate_hash(cuckoo_trie* trie, uint64_t x, uint64_t symbol) {
	x ^= symbol;

	uint64_t block = x >> BITS_PER_SYMBOL;
	uint64_t depth = x & (FANOUT - 1);

	uint64_t result = depth * trie->num_shuffle_blocks + block;

	assert(result < trie->num_pairs);
	return result;
}

// Given that <entry> is currently in bucket <bucket_num>, return the other
// bucket in which <entry> can be stored.
uint64_t alternate_bucket(cuckoo_trie* trie, ct_entry_storage* entry, uint64_t bucket_num) {
	if (entry_is_secondary((ct_entry*) entry))
		return unmix_bucket(trie, bucket_num, entry_tag((ct_entry*) entry));
	else
		return mix_bucket(trie, bucket_num, entry_tag((ct_entry*) entry));
}

uint64_t hash_to_bucket(uint64_t x) {
	return (x >> TAG_BITS);
}

uint64_t hash_to_tag(uint64_t x) {
	return (x & ((1 << TAG_BITS) - 1));
}

int entries_equal(ct_entry_storage* a, ct_entry_storage* b) {
	assert(sizeof(ct_entry_storage) <= 16);  // We only compare 2 QWORDS
	assert(sizeof(ct_entry_storage) >= 8);   // Otherwise we'll compare past the entry's end
	uint64_t* a1 = (uint64_t*)a;
	uint64_t* a2 = (uint64_t*)(((uintptr_t)a) + sizeof(ct_entry_storage)-8);
	uint64_t* b1 = (uint64_t*)b;
	uint64_t* b2 = (uint64_t*)(((uintptr_t)b) + sizeof(ct_entry_storage)-8);
	return ((*a1 == *b1) && (*a2 == *b2));
}

// Check whether an entry in the trie changed since we first read it
int validate_entry(ct_entry_local_copy* local_copy) {
#ifndef MULTITHREADING
#ifdef NDEBUG
	UNUSED_PARAMETER(local_copy);
#endif
	assert(entries_equal(local_copy->last_pos, (ct_entry_storage*) &(local_copy->value)));
	return 1;
#else
	assert(sizeof(ct_bucket) == 64);
	ct_entry entry;
	int equal;
	ct_bucket* bucket = (ct_bucket*) (((uintptr_t)(local_copy->last_pos)) & (~63));
	uint64_t bucket_seq = read_int_atomic(&(bucket->write_lock_and_seq));
	equal = ((bucket_seq & (~0xFF)) == (local_copy->last_seq & (~0xFF)));

	return __builtin_expect(equal, 1);
#endif
}

int validate_path_from(ct_finger* finger, ct_path_entry* top_path_pos) {
	ct_path_entry* path_pos;

	for (path_pos = top_path_pos; path_pos <= finger->last_path_entry; path_pos++) {
		ct_entry_local_copy* local_copy = &(path_pos->entry);
		ct_entry_storage* shared_copy = path_pos->entry.last_pos;
		if (!validate_entry(local_copy))
			return 0;
	}
	return 1;
}

void read_min_leaf(cuckoo_trie* trie, ct_entry_local_copy* result) {
	uint32_t seq;
	ct_entry_storage* leaf_addr = trie_min_leaf(trie);
	seq = read_entry(leaf_addr, &(result->value));
	result->last_pos = leaf_addr;
	result->last_seq = seq;
	result->primary_bucket = -1ULL;  // Not supposed to be used
}

uint64_t get_jump_symbol(ct_entry* entry, uint64_t symbol_idx) {
	assert(MAX_JUMP_BITS <= 64);

	//  Make sure we don't read past the entry's end
	assert(offsetof(ct_entry, jump_bits) + 8 <= sizeof(ct_entry_storage));

	uint64_t jump_bits = *((uint64_t*) &(entry->jump_bits[0]));
	jump_bits = __builtin_bswap64(jump_bits);
	return ((jump_bits >> (64 - BITS_PER_SYMBOL - BITS_PER_SYMBOL * symbol_idx)) & SYMBOL_MASK) + 1;
}

// Get the <i>'th symbol of the key, zero-padding if neccessary
uint64_t get_string_symbol(uint64_t size, uint8_t* bytes, uint64_t symbol_idx) {
	assert(BITS_PER_SYMBOL <= 8);
	uint64_t symbol_pos = symbol_idx * BITS_PER_SYMBOL;
	uint64_t first_byte_idx = symbol_pos / 8;
	uint64_t offset = symbol_pos % 8;
	uint32_t word;
	uint8_t first_byte;
	uint8_t second_byte;

	assert(symbol_pos < size * 8 + BITS_PER_SYMBOL);  // We don't ask for symbols after the END symbol

	if (first_byte_idx >= size)
		return SYMBOL_END;

	first_byte = bytes[first_byte_idx];
	if (first_byte_idx + 1 < size)
		second_byte = bytes[first_byte_idx + 1];
	else
		second_byte = 0;

	word = first_byte * 256 + second_byte;
	return ((word >> (16 - BITS_PER_SYMBOL - offset)) & SYMBOL_MASK) + 1;
}

uint64_t get_key_symbol(ct_kv* kv, int symbol_idx) {
	return get_string_symbol(kv_key_size(kv), kv_key_bytes(kv), symbol_idx);
}

void prefetch_bucket_pair(cuckoo_trie* trie, uint64_t primary_bucket, uint8_t tag) {
	uint64_t i;
	uint64_t secondary_bucket = mix_bucket(trie, primary_bucket, tag);

	for (i = 0;i < sizeof(ct_bucket); i += CACHELINE_BYTES) {
		__builtin_prefetch((uint8_t*)(&(trie->buckets[primary_bucket])) + i);
		__builtin_prefetch((uint8_t*)(&(trie->buckets[secondary_bucket])) + i);
	}
}

ct_entry_storage* find_entry_in_bucket_by_color(ct_bucket* bucket,
												ct_entry_local_copy* result, uint64_t is_secondary,
												uint64_t tag, uint64_t color) {
	int i;
	uint64_t header_mask = 0;
	uint64_t header_values = 0;

	header_mask |= ((1ULL << TAG_BITS) - 1) << (8*offsetof(ct_entry, color_and_tag));
	header_values |= tag << (8*offsetof(ct_entry, color_and_tag));

	header_mask |= ((uint64_t)((0xFF << TAG_BITS) & 0xFF)) << (8*offsetof(ct_entry, color_and_tag));
	header_values |= color << (8*offsetof(ct_entry, color_and_tag) + TAG_BITS);

	header_mask |= FLAG_SECONDARY_BUCKET << (8*offsetof(ct_entry, parent_color_and_flags));
	if (is_secondary)
		header_values |= FLAG_SECONDARY_BUCKET << (8*offsetof(ct_entry, parent_color_and_flags));

#ifdef MULTITHREADING
	uint32_t start_counter = read_int_atomic(&(bucket->write_lock_and_seq));
	if (start_counter & SEQ_INCREMENT)
		return NULL;   // Bucket is being written. The retry loop will call us again.
#else
	assert(bucket->write_lock_and_seq == 0);
#endif

	for (i = 0;i < CUCKOO_BUCKET_SIZE;i++) {
		read_entry_non_atomic(&(bucket->cells[i]), &(result->value));

		uint64_t header = *((uint64_t*) (&(result->value)));
		if ((header & header_mask) == header_values)
			break;
	}
	if (i == CUCKOO_BUCKET_SIZE)
		return NULL;

#ifdef MULTITHREADING
	if (read_int_atomic(&(bucket->write_lock_and_seq)) != start_counter) {
		// The bucket changed while we read it. We rely on the retry loop in
		// find_entry_in_pair_by_color to call us again
		return NULL;
	}
	result->last_seq = start_counter;
#endif

	result->last_pos = &(bucket->cells[i]);
	if (!result->last_pos)
		__builtin_unreachable();
	return result->last_pos;
}

ct_entry_storage* find_entry_in_bucket_by_parent(ct_bucket* bucket,
												 ct_entry_local_copy* result, uint64_t is_secondary,
												 uint64_t tag, uint64_t last_symbol, uint64_t parent_color) {
	int i;

	uint64_t header_mask = 0;
	uint64_t header_values = 0;

	header_mask |= ((1ULL << TAG_BITS) - 1) << (8*offsetof(ct_entry, color_and_tag));
	header_values |= tag << (8*offsetof(ct_entry, color_and_tag));

	header_mask |= 0xFFULL << (8*offsetof(ct_entry, last_symbol));
	header_values |= last_symbol << (8*offsetof(ct_entry, last_symbol));

	const uint64_t parent_color_mask = (0xFFULL << PARENT_COLOR_SHIFT) & 0xFF;
	header_mask |= parent_color_mask << (8*offsetof(ct_entry, parent_color_and_flags));
	header_values |= parent_color << (8*offsetof(ct_entry, parent_color_and_flags) + PARENT_COLOR_SHIFT);

	header_mask |= FLAG_SECONDARY_BUCKET << (8*offsetof(ct_entry, parent_color_and_flags));
	if (is_secondary)
		header_values |= FLAG_SECONDARY_BUCKET << (8*offsetof(ct_entry, parent_color_and_flags));

#ifdef MULTITHREADING
	uint32_t start_counter = read_int_atomic(&(bucket->write_lock_and_seq));
	if (start_counter & SEQ_INCREMENT)
		return NULL;   // Bucket is being written. The retry loop will call us again.
#else
	assert(bucket->write_lock_and_seq == 0);
#endif

	for (i = 0;i < CUCKOO_BUCKET_SIZE;i++) {
		read_entry_non_atomic(&(bucket->cells[i]), &(result->value));

		uint64_t header = *((uint64_t*) (&(result->value)));
		if ((header & header_mask) == header_values) {
			assert(entry_type(&(result->value)) != TYPE_UNUSED);
			break;
		}
	}

	if (i == CUCKOO_BUCKET_SIZE) {
		return NULL;
	}

#ifdef MULTITHREADING
	if (read_int_atomic(&(bucket->write_lock_and_seq)) != start_counter) {
		// The bucket changed while we read it. We rely on the retry loop in
		// find_entry_in_pair_by_parent to call us again
		return NULL;
	}
	result->last_seq = start_counter;
#endif

	result->last_pos = &(bucket->cells[i]);
	if (!result->last_pos)
		__builtin_unreachable();
	return result->last_pos;
}

// Searches for an entry with color <color> in the specified pair. Copies the entry
// found to <result> and also returns its address. Assumes the entry is in the pair.
// Note: When multithreading, the returned address is meaningless, as the entry might
//       have been moved since it was read. Use only the value written into <result>
ct_entry_storage* find_entry_in_pair_by_color(cuckoo_trie* trie, ct_entry_local_copy* result,
											  uint64_t primary_bucket, uint64_t tag,
											  uint8_t color) {
	ct_entry_storage* entry_addr;
	uint64_t count = 0;

	while (1) {
		entry_addr = find_entry_in_bucket_by_color(&(trie->buckets[primary_bucket]), result, 0, tag, color);
		if (entry_addr)
			break;

		uint64_t secondary_bucket = mix_bucket(trie, primary_bucket, tag);
		entry_addr = find_entry_in_bucket_by_color(&(trie->buckets[secondary_bucket]), result, 1, tag, color);
		if (entry_addr)
			break;

		// The entry might have been relocated from the secondary to the primary bucket
		// just after we searched the primary bucket. Try searching both buckets again.

		count++;
		assert(count < 100);
	}

	result->primary_bucket = primary_bucket;
	return entry_addr;
}

// Assumes the entry is in the pair
inline
ct_entry_storage* find_entry_in_pair_by_parent(cuckoo_trie* trie, ct_entry_local_copy* result,
											   uint64_t primary_bucket, uint64_t tag,
											   uint64_t last_symbol, uint64_t parent_color) {
	ct_entry_storage* entry_addr;
	uint64_t count = 0;

	while (1) {
		entry_addr = find_entry_in_bucket_by_parent(&(trie->buckets[primary_bucket]), result, 0, tag,
													last_symbol, parent_color);
		if (entry_addr)
			break;

		uint64_t secondary_bucket_num = mix_bucket(trie, primary_bucket, tag);
		entry_addr = find_entry_in_bucket_by_parent(&(trie->buckets[secondary_bucket_num]), result, 1, tag,
													last_symbol, parent_color);
		if (entry_addr)
			break;

		count++;
		assert(count < 100);
	}

	result->primary_bucket = primary_bucket;
	return entry_addr;
}

ct_entry_storage* find_free_cell_in_bucket(ct_bucket* bucket) {
	int i;

	for (i = 0;i < CUCKOO_BUCKET_SIZE;i++) {
		ct_entry_storage* entry = &(bucket->cells[i]);
		if (entry_type((ct_entry*) entry) == TYPE_UNUSED)
			return entry;
	}

	return NULL;
}

ct_entry_storage* find_root(cuckoo_trie* trie, ct_entry_local_copy* result) {
	uint64_t root_primary_bucket = hash_to_bucket(HASH_START_VALUE);
	ct_entry_storage* root_pos = &(trie->buckets[root_primary_bucket].cells[0]);
	result->last_seq = read_entry(root_pos, &(result->value));
	result->last_pos = root_pos;
	result->primary_bucket = root_primary_bucket;
	return result->last_pos;
}

void locator_to_entry(cuckoo_trie* trie, ct_entry_locator* locator, ct_entry_local_copy* result) {
	ct_entry_storage* addr;
	addr = find_entry_in_pair_by_color(trie, result,
									   locator->primary_bucket,
									   locator->tag, locator->color);
	assert(addr);
}

void store_path_entry(ct_finger* finger) {
	finger->last_path_entry++;
	ct_path_entry* slot = finger->last_path_entry;
	copy_as_qwords(&(slot->entry), &(finger->containing_entry), sizeof(finger->containing_entry));

	// It is not always the case that hash_to_bucket(finger->prefix_hash) is the
	// primary bucket of the containing entry, as the finger can descend inside
	// a jump node, changing prefix_hash while staying with the same containing_entry.
	// However, store_path_entry is always called when the finger is at the top
	// of a jump node.
	assert(finger->depth_in_jump == 0);
	slot->prefix_hash = finger->prefix_hash;
}

// Handle the case where the entry was relocated since we read it, and has to be found again
void update_entry_slow_path(cuckoo_trie* trie, ct_entry_local_copy* local_copy, ct_entry* new_value) {
	ct_entry_storage* cur_entry_pos;
	ct_entry_local_copy unused;
	ct_entry adjusted_new_value;
	uint32_t new_seq;
	cur_entry_pos = find_entry_in_pair_by_color(trie, &unused, local_copy->primary_bucket,
												entry_tag(&(local_copy->value)),
												entry_color(&(local_copy->value)));

	// The entry might have been relocated since the local copy was read. Write the new
	// value with a FLAG_SECONDARY_BUCKET according to its current location.
	adjusted_new_value = *new_value;
	adjusted_new_value.parent_color_and_flags &= ~FLAG_SECONDARY_BUCKET;
	adjusted_new_value.parent_color_and_flags |= ((ct_entry*) cur_entry_pos)->parent_color_and_flags & FLAG_SECONDARY_BUCKET;
	new_seq = write_entry(cur_entry_pos, &(adjusted_new_value));
	local_copy->value = adjusted_new_value;
	local_copy->last_pos = cur_entry_pos;
	local_copy->last_seq = new_seq;
}

// Update an entry we previously read. Will search again for the entry if it was relocated since
// it was read.
void update_entry(cuckoo_trie* trie, ct_entry_local_copy* local_copy, ct_entry* new_value) {
	int entry_didnt_move;

#ifdef MULTITHREADING
	// This is an overestimate. validate_entry will fail even if another entry in the same bucket
	// changed.
	entry_didnt_move = validate_entry(local_copy);
#else
	// In single-threaded mode, bucket sequence numbers aren't updated, so we cannot rely
	// on them. Compare the entry bytes.
	entry_didnt_move = entries_equal(local_copy->last_pos, (ct_entry_storage*) &(local_copy->value));
#endif
	if (entry_didnt_move) {
		uint32_t new_seq = write_entry(local_copy->last_pos, new_value);
		local_copy->value = *new_value;
		local_copy->last_seq = new_seq;
		return;
	}

	// The entry was relocated since we read it. Find it again.
	update_entry_slow_path(trie, local_copy, new_value);
}

void remove_entry_by_address(ct_lock_mgr* lock_mgr, ct_entry_storage* entry_pos) {
	const ct_entry unused_entry = {
		.parent_color_and_flags = (INVALID_COLOR << PARENT_COLOR_SHIFT) | TYPE_UNUSED,
		.color_and_tag = INVALID_COLOR << TAG_BITS
	};

#ifdef NDEBUG
	UNUSED_PARAMETER(lock_mgr);
#endif
	ct_bucket* entry_bucket = bucket_containing(entry_pos);
	assert(bucket_write_locked(lock_mgr, entry_bucket));

	write_entry(entry_pos, &unused_entry);
}

void remove_entry_by_value(ct_lock_mgr* lock_mgr, ct_entry* entry, uint64_t prefix_hash) {
	ct_entry_local_copy unused;
	ct_entry_storage* entry_pos = find_entry_in_pair_by_color(lock_mgr->trie,
															  &unused,
															  hash_to_bucket(prefix_hash),
															  hash_to_tag(prefix_hash),
															  entry_color(entry));
	assert(entry_pos);

	remove_entry_by_address(lock_mgr, entry_pos);
}

void mark_entry_dirty(cuckoo_trie* trie, ct_entry_local_copy* local_copy) {
	ct_entry new_value = local_copy->value;
	entry_set_dirty(&new_value);
	update_entry(trie, local_copy, &new_value);
}

void mark_entry_clean(cuckoo_trie* trie, ct_entry_local_copy* local_copy) {
	ct_entry new_value = local_copy->value;
	entry_set_clean(&new_value);
	update_entry(trie, local_copy, &new_value);
}

ct_entry_storage* init_finger(ct_finger* finger, cuckoo_trie* trie) {
	ct_entry_storage* root_addr;

	if (read_int_atomic(&(trie->is_empty)))
		root_addr = NULL;
	else {
		root_addr = find_root(trie, &(finger->containing_entry));
	}
	finger->trie = trie;
	finger->last_prefix_symbol = ROOT_LAST_SYMBOL;
	finger->prefix_hash = HASH_START_VALUE;
	finger->prefix_len = 0;
	finger->depth_in_jump = 0;
	finger->last_path_entry = &(finger->path[-1]);

	// We must initialize the lock_mgr even when compiling without multithreading support,
	// as add_entry relies on lock_mgr->trie to avoid passing the trie as another parameter
	// (and exceeding the 6-parameters limit for passing parameters in registers)
	init_lock_mgr(&(finger->lock_mgr), trie);

	store_path_entry(finger);
	return root_addr;
}

void finger_extend_prefix_known_hash(ct_finger* finger, uint8_t symbol, uint64_t new_hash) {
	finger->prefix_hash = new_hash;
	finger->last_prefix_symbol = symbol;
	finger->prefix_len++;
}

void finger_extend_prefix(ct_finger* finger, uint8_t symbol) {
	uint64_t new_hash = accumulate_hash(finger->trie, finger->prefix_hash, symbol);
	finger_extend_prefix_known_hash(finger, symbol, new_hash);
}

void finger_node_changed(ct_finger* finger, int extend_path) {
	finger->depth_in_jump = 0;
	if (extend_path)
		store_path_entry(finger);
}

// This thread changed the last node in the finger's path (the one that contains
// the finger). Update its copy in finger->containing_entry;
void reread_path_end(ct_finger* finger) {
	ct_path_entry* slot = finger->last_path_entry;
	finger->containing_entry = slot->entry;
}

int create_root(ct_finger* finger, ct_kv* kv) {
	int ret;
	ct_entry root;
	ct_bucket_write_lock* lock;
	uint64_t tag = hash_to_tag(HASH_START_VALUE);
	uint64_t primary_bucket_num = hash_to_bucket(HASH_START_VALUE);
	ct_bucket* root_primary_bucket = &(finger->trie->buckets[primary_bucket_num]);

	// We're inserting the first kv into the trie, so the root is a leaf
	root.parent_color_and_flags = (INVALID_COLOR << PARENT_COLOR_SHIFT) | TYPE_LEAF;
	root.color_and_tag = (ROOT_COLOR << TAG_BITS) | tag;
	entry_set_kv(&root, kv);
	root.next_leaf.primary_bucket = -1;  // This leaf is, currently, the maximal one

	// Lock the root's bucket so no other thread tries to create the root simultaneously.
	lock = write_lock_bucket(&(finger->lock_mgr), root_primary_bucket);
	if (!lock) {
		// Another thread is currently creating the root. When we return, the root
		// should exist, so wait until the other thread is done creating it.
		while (read_int_atomic(&(finger->trie->is_empty)))
			;
	}
	if (read_int_atomic(&(finger->trie->is_empty)) == 0) {
		// Another thread created the root in the meantime. We might have succeeded to lock
		// the root bucket immediately after the root was created. In that case, release
		// it now.
		release_all_locks(&(finger->lock_mgr));
		return SI_EXISTS;
	}
	write_entry(&(root_primary_bucket->cells[0]), &root);

	((ct_entry*) trie_min_leaf(finger->trie))->next_leaf.primary_bucket = primary_bucket_num;
	((ct_entry*) trie_min_leaf(finger->trie))->next_leaf.tag = tag;
	((ct_entry*) trie_min_leaf(finger->trie))->next_leaf.color = ROOT_COLOR;

	// Make sure the root is completely set-up before allowing readers to look at it
	write_int_atomic(&(finger->trie->is_empty),0);
	release_all_locks(&(finger->lock_mgr));
	return SI_OK;
}

uint64_t bitmap_child_before(ct_entry* bitmap_node, uint64_t symbol) {
	assert(SYMBOL_END == 0);
	return last_bit_before(bitmap_node->child_bitmap, symbol);
}

int upgrade_locks_on_left_parents_above(ct_finger* finger, ct_path_entry* bitmap_path_pos) {
	assert(entry_type(&(bitmap_path_pos->entry.value)) == TYPE_BITMAP);
	ct_path_entry* path_pos = bitmap_path_pos;
	int result = SI_OK;

	while (path_pos > &(finger->path[0])) {
		uint64_t backtrack_symbol = path_pos->entry.value.last_symbol;
		ct_entry_local_copy* parent = &((path_pos - 1)->entry);
		if (entry_type(&(parent->value)) == TYPE_JUMP) {
			result = upgrade_lock(&(finger->lock_mgr), parent);
		} else {
			assert(entry_type(&(parent->value)) == TYPE_BITMAP);
			if (backtrack_symbol != parent->value.max_child)
				break;  // We reached a node where we're not maximal
			result = upgrade_lock(&(finger->lock_mgr), parent);
		}
		if (result != SI_OK)
			break;
		path_pos--;
	}

	if (result != SI_OK) {
		// Release all locks we already took
		while (path_pos < bitmap_path_pos) {
			path_pos++;
			write_unlock(&(finger->lock_mgr), (path_pos - 1)->entry.last_pos);
		}
	}

	return result;
}

// Get the leaf described by pred_locator
int get_predecessor_atomic(cuckoo_trie* trie, ct_pred_locator* pred_locator, ct_entry_local_copy* result) {
	ct_entry_local_copy subtree_root;
	if (pred_locator->subtree[0].primary_bucket == -1ULL) {
		// <pred_locator> points to the leaf before the minimal one
		read_min_leaf(trie, result);

		if (!validate_path_from(pred_locator->finger, &(pred_locator->finger->path[0])))
			return 0;

		return 1;
	}

	find_entry_in_pair_by_parent(trie, &subtree_root,
								 pred_locator->subtree[0].primary_bucket,
								 pred_locator->subtree[0].tag,
								 pred_locator->subtree[0].last_symbol,
								 pred_locator->subtree[0].parent_color);

	if (entry_type(&(subtree_root.value)) == TYPE_LEAF) {
		if (!validate_path_from(pred_locator->finger, pred_locator->subtree[0].path_pos))
			return 0;

		if (entry_dirty(&(subtree_root.value)))
			return 0;
		*result = subtree_root;
		return 1;
	}

	locator_to_entry(trie, &(subtree_root.value.max_leaf), result);
	if (entry_type(&(result->value)) != TYPE_LEAF) {
		// Failure - more keys were added under the subtree max leaf since we read it
		return 0;
	}

	if (!validate_path_from(pred_locator->finger, pred_locator->subtree[0].path_pos))
		return 0;
	if (!validate_entry(&subtree_root))
		return 0;

	if (entry_dirty(&(result->value)))
		return 0;

	return 1;
}

// Find the predecessor described by pred_locator
void find_predecessor(cuckoo_trie* trie, ct_pred_locator* pred_locator) {
	ct_entry_storage* subtree_root;

	if (pred_locator->subtree[0].primary_bucket == -1ULL) {
		// The key is minimal - the predecessor is the linklist head
		read_min_leaf(trie, &(pred_locator->predecessor[0]));
		return;
	}

	find_entry_in_pair_by_parent(trie,
								 &(pred_locator->predecessor[0]),
								 pred_locator->subtree[0].primary_bucket,
								 pred_locator->subtree[0].tag,
								 pred_locator->subtree[0].last_symbol,
								 pred_locator->subtree[0].parent_color);

	if (entry_type(&(pred_locator->predecessor[0].value)) == TYPE_LEAF)
		return;

	// The subtree root is a bitmap / jump node, so the predecessor is tha maximal leaf under it
	locator_to_entry(trie, &(pred_locator->predecessor[0].value.max_leaf), &(pred_locator->predecessor[0]));
	assert(entry_type(&(pred_locator->predecessor[0].value)) == TYPE_LEAF);
}

// Insert <new_entry> just after <predecessor> in the linked list. The <next> field of
// <new_entry> should already be set to the correct value
void linklist_insert(cuckoo_trie* trie, ct_pred_locator* pred_locator,
					 ct_entry_storage* new_entry, uint64_t primary_bucket) {
#ifndef NO_LINKED_LIST
	ct_entry_locator new_entry_locator;
	ct_entry new_prev;
	new_entry_locator.primary_bucket = primary_bucket;
	new_entry_locator.color = entry_color((ct_entry*) new_entry);
	new_entry_locator.tag = entry_tag((ct_entry*) new_entry);

	new_prev = pred_locator->predecessor[0].value;
	new_prev.next_leaf = new_entry_locator;
	update_entry(trie, &(pred_locator->predecessor[0]), &new_prev);
#endif
}

// Insert two consecutive entries into the linked list, just after the node(s)
// obtained from pred_locator.
// The <next> field of entry_1 and entry_2 should already be set correctly.
void linklist_insert_two(cuckoo_trie* trie, ct_pred_locator* pred_locator,
						 uint64_t entry_1_hash, uint8_t entry_1_color) {
#ifndef NO_LINKED_LIST
	ct_entry new_prev;
	ct_entry_locator first_entry_locator;
	first_entry_locator.primary_bucket = hash_to_bucket(entry_1_hash);
	first_entry_locator.color = entry_1_color;
	first_entry_locator.tag = hash_to_tag(entry_1_hash);

	// Connect the prev to the first entry
	new_prev = pred_locator->predecessor[0].value;
	new_prev.next_leaf = first_entry_locator;
	update_entry(trie, &(pred_locator->predecessor[0]), &new_prev);
#endif
}

void extend_jump_node(ct_entry* jump_node, uint64_t symbol) {
	assert(symbol != SYMBOL_END);  // The END symbol should never appear in jumps
	uint64_t offset = entry_jump_size(jump_node) * BITS_PER_SYMBOL;

	put_bits(jump_node->jump_bits, offset, BITS_PER_SYMBOL, symbol - 1);
	jump_node->child_color_and_jump_size++;
}

uint8_t unused_color_in_pair(ct_bucket* bucket1, ct_bucket* bucket2) {
	assert(MAX_VALID_COLOR < 63);  // Otherwise all_valid_colors_will overflow
	uint64_t used_colors = 0;
	int i;

	for (i = 0;i < CUCKOO_BUCKET_SIZE;i++) {
		ct_entry_storage* entry = &(bucket1->cells[i]);

		// Turn on the bit corresponding to the entry's color.
		used_colors |= 1ULL << entry_color((ct_entry*) entry);

		entry = &(bucket2->cells[i]);
		used_colors |= 1ULL << entry_color((ct_entry*) entry);
	}

	const uint64_t all_valid_colors = (1ULL << (MAX_VALID_COLOR + 1)) - 1;
	assert((used_colors & all_valid_colors) != all_valid_colors);   // There must be a free color
	return __builtin_ctzll(~used_colors);
}

typedef struct {
	uint64_t bucket;
	ct_bucket_read_lock read_lock;
	int parent_queue_pos;  // The position in the queue of the entry that generated this one
	int child_idx;         // Which child generated this entry
} relocation_queue_entry;

#define RELOCATE_QUEUE_SIZE 1000

// Relocate an entry from bucket <bucket_num> to create a free cell in it.
// Immovable entry - an entry that should not be moved while relocating
int relocate_entry(cuckoo_trie* trie, ct_lock_mgr* lock_mgr, uint64_t bucket_num,
				   ct_entry_storage* immovable_entry, ct_entry_storage** output) {
	int i, j;
	int ret;
	int return_value = SI_OK;
	relocation_queue_entry queue[RELOCATE_QUEUE_SIZE];
	ct_entry_storage* free_cell;
	ct_entry_storage* occupied_cell;
	ct_entry_storage* root = &(trie->buckets[hash_to_bucket(HASH_START_VALUE)].cells[0]);
	ct_bucket_read_lock read_lock;
	int free_cell_found = 0;
	int queue_pos = 0;
	int queue_size = 0;
	int buckets_read_locked = 0;
	uint64_t child_bucket_num;
	int occupied_queue_pos, child_idx;

	assert(bucket_write_locked(lock_mgr, &(trie->buckets[bucket_num])));
	queue[0].bucket = bucket_num;
	queue[0].parent_queue_pos = -1;
	queue_size++;

	while (queue_pos < queue_size && !free_cell_found) {
		// we know that the bucket queue[queue_pos] is full (otherwise we
		// wouldn't have inserted it). scan the alternate positions of the entries
		// in it.

		for (i = 0;i < CUCKOO_BUCKET_SIZE;i++) {
			ct_entry_storage* entry = &(trie->buckets[queue[queue_pos].bucket].cells[i]);

			if (entry == immovable_entry)
				continue;

			if (entry == root)
				continue;

			child_bucket_num = alternate_bucket(trie, entry, queue[queue_pos].bucket);

			int already_inserted = 0;
			for (j = 0;j < queue_size;j++) {
				if (queue[j].bucket == child_bucket_num) {
					already_inserted = 1;
					break;
				}
			}
			if (already_inserted)
				continue;

			read_lock_bucket(&(trie->buckets[child_bucket_num]), &read_lock);
			free_cell = find_free_cell_in_bucket(&(trie->buckets[child_bucket_num]));

			if (free_cell == NULL) {
				// The alternate bucket has no free cells. Put it in the queue for later.
				if (queue_size < RELOCATE_QUEUE_SIZE) {
					queue[queue_size].bucket = child_bucket_num;
					queue[queue_size].read_lock = read_lock;
					queue[queue_size].parent_queue_pos = queue_pos;
					queue[queue_size].child_idx = i;
					queue_size++;
				}
			} else {
				// We found a free cell.
				free_cell_found = 1;

				// Remember which child generated it
				child_idx = i;
				break;
			}
		}
		queue_pos++;
	}

	if (!free_cell_found)
		return SI_FAIL;  // Enlarging the table isn't implemented yet

	// Upgrade locks on all buckets in the path
	ret = upgrade_bucket_lock(lock_mgr, &read_lock);
	if (ret == SI_RETRY)
		return SI_RETRY;
	buckets_read_locked++;
	occupied_queue_pos = queue_pos - 1;
	while (1) {
		if (occupied_queue_pos == 0)
			break;

		ret = upgrade_bucket_lock(lock_mgr, &(queue[occupied_queue_pos].read_lock));
		if (ret == SI_RETRY) {
			return_value = SI_RETRY;
			goto release_locks;
		}
		buckets_read_locked++;
		occupied_queue_pos = queue[occupied_queue_pos].parent_queue_pos;
	}

	// Move entries one position along the path
	ct_entry entry_buf;
	occupied_queue_pos = queue_pos - 1;
	while (1) {
		occupied_cell = &(trie->buckets[queue[occupied_queue_pos].bucket].cells[child_idx]);

		// The read here is non-atomic, but that's fine as the bucket is write-locked
		debug_log("relocate_entry: Moving %p -> %p\n", occupied_cell, free_cell);
		read_entry_non_atomic(occupied_cell, &entry_buf);
		entry_buf.parent_color_and_flags ^= FLAG_SECONDARY_BUCKET;
		write_entry(free_cell, &entry_buf);
		move_entry_lock(lock_mgr, free_cell, occupied_cell);

		if (occupied_queue_pos == 0)
			break;   // We reached the first queue entry

		child_idx = queue[occupied_queue_pos].child_idx;
		occupied_queue_pos = queue[occupied_queue_pos].parent_queue_pos;
		free_cell = occupied_cell;
	}

	// Mark the cell we freed as empty
	entry_buf.parent_color_and_flags = (INVALID_COLOR << PARENT_COLOR_SHIFT) | TYPE_UNUSED;
	entry_buf.color_and_tag = INVALID_COLOR << TAG_BITS;
	write_entry(occupied_cell, &entry_buf);

	// Release write locks
release_locks:
	release_bucket_lock(lock_mgr, &(trie->buckets[child_bucket_num]));
	buckets_read_locked--;
	occupied_queue_pos = queue_pos - 1;
	while (buckets_read_locked) {
		release_bucket_lock(lock_mgr, &(trie->buckets[queue[occupied_queue_pos].bucket]));
		buckets_read_locked--;
		occupied_queue_pos = queue[occupied_queue_pos].parent_queue_pos;
	}
	// By now we should've reached the path start (the first entry in the queue is the
	// original bucket passed to this function, which was already locked, so we don't
	// release it).
	assert(occupied_queue_pos == 0);

	if (return_value == SI_OK)
		*output = occupied_cell;

	return return_value;
}

// Finds an empty slot for <entry> in the hash and puts it there. Sets entry->color and entry->tag
// to the correct values. Everything else should be set by the caller.
int add_entry(ct_lock_mgr* lock_mgr,
			  uint64_t prefix_hash, ct_entry* entry,
			  ct_entry_storage* immovable_entry, ct_entry_storage** new_entry,
			  int lock) {
	int ret;
	ct_bucket_write_lock* bucket_lock;
	ct_bucket_read_lock primary_read_lock, secondary_read_lock;
	ct_entry_storage* result;
	uint8_t flags_to_add = 0;
	uint8_t unused_color;
	ct_bucket* result_bucket = NULL;
	ct_bucket_read_lock* alternate_bucket_lock;
	uint64_t primary_bucket_num = hash_to_bucket(prefix_hash);
	uint64_t secondary_bucket_num = mix_bucket(lock_mgr->trie, primary_bucket_num, hash_to_tag(prefix_hash));
	ct_bucket* primary_bucket = &(lock_mgr->trie->buckets[primary_bucket_num]);
	ct_bucket* secondary_bucket = &(lock_mgr->trie->buckets[secondary_bucket_num]);

	read_lock_bucket(primary_bucket, &primary_read_lock);
	read_lock_bucket(secondary_bucket, &secondary_read_lock);

	result = find_free_cell_in_bucket(primary_bucket);
	if (result) {
		// We'll write to the primary bucket, lock it.
		ret = upgrade_bucket_lock(lock_mgr, &primary_read_lock);
		if (ret == SI_RETRY)
			return SI_RETRY;
		result_bucket = primary_bucket;
		alternate_bucket_lock = &secondary_read_lock;
		goto cell_found;
	}

	result = find_free_cell_in_bucket(secondary_bucket);
	if (result) {
		flags_to_add = FLAG_SECONDARY_BUCKET;

		// We'll write to the secondary bucket
		ret = upgrade_bucket_lock(lock_mgr, &secondary_read_lock);
		if (ret == SI_RETRY)
			return SI_RETRY;
		result_bucket = secondary_bucket;
		alternate_bucket_lock = &primary_read_lock;
		goto cell_found;
	}

	// Both buckets full, try relocating from the primary bucket
	ret = upgrade_bucket_lock(lock_mgr, &primary_read_lock);
	if (ret == SI_RETRY)
		return SI_RETRY;
	result_bucket = primary_bucket;
	alternate_bucket_lock = &secondary_read_lock;

	ret = relocate_entry(lock_mgr->trie, lock_mgr, primary_bucket_num, immovable_entry, &result);
	if (ret == SI_FAIL || ret == SI_RETRY) {
		release_bucket_lock(lock_mgr, result_bucket);
		return ret;
	}

	cell_found:
	if (lock)
		write_lock_entry_in_locked_bucket(lock_mgr, result);
	unused_color = unused_color_in_pair(primary_bucket, secondary_bucket);
	entry_add_flags(entry, flags_to_add);
	entry_set_color_and_tag(entry, (unused_color << TAG_BITS) | hash_to_tag(prefix_hash));
	write_entry(result, entry);
	ret = read_unlock_bucket(alternate_bucket_lock);
	if (ret != SI_OK) {
		// The alternate bucket changed while we did the write. Specifically, another thread
		// might have added an entry there with the same color as ours. Remove our entry and
		// retry.
		remove_entry_by_address(lock_mgr, result);
		release_bucket_lock(lock_mgr, result_bucket);
		return SI_RETRY;
	}
	release_bucket_lock(lock_mgr, result_bucket);
	*new_entry = result;
	return SI_OK;
}

int try_descend(ct_finger* finger, uint64_t symbol, int save_path, uint64_t expected_hash) {
	ct_entry* containing_entry = &(finger->containing_entry.value);

	if (entry_type(containing_entry) == TYPE_LEAF)
		return 0; // We cannot descend a leaf

	if (entry_type(containing_entry) == TYPE_JUMP) {
		// The finger is inside a jump node

		// Bring the next jump symbol from the node
		uint8_t next_symbol = get_jump_symbol(containing_entry, finger->depth_in_jump);
		if (next_symbol != symbol)
			return 0;

		// Descend
		finger_extend_prefix_known_hash(finger, symbol, expected_hash);
		finger->depth_in_jump++;
		if (finger->depth_in_jump == entry_jump_size(containing_entry)) {
			// We reached the end of the jump node - move to the child
			find_entry_in_pair_by_color(finger->trie, &(finger->containing_entry),
										hash_to_bucket(finger->prefix_hash),
										hash_to_tag(finger->prefix_hash),
										entry_child_color(containing_entry));
			finger_node_changed(finger, save_path);
		}
		return 1;
	} else {
		// The finger is inside a bitmap node
		if (!get_bit(containing_entry->child_bitmap, symbol))
			return 0;    // The bitmap doesn't have the requested child

		finger_extend_prefix_known_hash(finger, symbol, expected_hash);
		find_entry_in_pair_by_parent(finger->trie, &(finger->containing_entry),
									 hash_to_bucket(finger->prefix_hash),
									 hash_to_tag(finger->prefix_hash),
									 symbol,
									 entry_color(containing_entry));
		finger_node_changed(finger, save_path);
		return 1;
	}
}

// Create a leaf that is a child of the bitmap pointed by the finger and contains the given key
// Doesn't update the bitmap
uint64_t create_bitmap_child(ct_finger* finger, uint8_t bitmap_color,
									  uint64_t symbol, ct_kv* kv, ct_entry_storage** child_addr) {
	uint64_t child_prefix_hash;
	ct_entry child;
	ct_entry_storage* bitmap_in_trie = finger->containing_entry.last_pos;

	child_prefix_hash = accumulate_hash(finger->trie, finger->prefix_hash, symbol);

	child.parent_color_and_flags = (bitmap_color << PARENT_COLOR_SHIFT) | TYPE_LEAF;
	child.last_symbol = symbol;
	entry_set_kv(&child, kv);
	uint64_t ret = add_entry(&(finger->lock_mgr),
							 child_prefix_hash,
							 &child,
							 bitmap_in_trie,
							 child_addr, 1);

	return ret;
}

void mark_bitmap_child(cuckoo_trie* trie, ct_entry_local_copy* bitmap_local_copy,
					   uint64_t symbol, uint64_t child_prefix_hash, uint8_t child_color) {
	ct_entry new_bitmap = bitmap_local_copy->value;
	entry_set_child_bit(&new_bitmap, symbol);
	if (bitmap_local_copy->value.max_child < symbol) {
		new_bitmap.max_child = symbol;
		new_bitmap.max_leaf.primary_bucket = hash_to_bucket(child_prefix_hash);
		new_bitmap.max_leaf.tag = hash_to_tag(child_prefix_hash);
		new_bitmap.max_leaf.color = child_color;
	}
	update_entry(trie, bitmap_local_copy, &new_bitmap);
}

// <finger> points to a node whose max_leaf was just changed to the correct value
// Propagate the change up the tree as much as required, but no higher than
// finger->path[top_path_pos]
void propagate_max_leaf(ct_finger* finger, ct_path_entry* top_path_pos) {
	ct_entry* parent;
	ct_path_entry* path_pos = finger->last_path_entry;

	while (path_pos > top_path_pos) {
		// Propagate from path[path_pos] to path[path_pos - 1]
		ct_path_entry* child_path_entry = path_pos;
		ct_path_entry* parent_path_entry = path_pos - 1;
		parent = &(parent_path_entry->entry.value);

		// If we're coming from a non-maximal child, we're done.
		if (entry_type(parent) == TYPE_BITMAP) {
			if (child_path_entry->entry.value.last_symbol < parent->max_child)
				break;
		}

		// Propagate
		ct_entry new_parent = *parent;
		new_parent.max_leaf = child_path_entry->entry.value.max_leaf;
		update_entry(finger->trie, &(parent_path_entry->entry), &new_parent);

		path_pos--;
	}
}

// Start from child <symbol> of the entry <path_pos> in the path of <finger>, and ascend
// one entry at a time, until reaching a bitmap where we can descend to the left.
// Returns the path position of that bitmap and the symbol of the child we can descend
// to. If the given child turns out to be minimal, returns path_pos_out = -1.
void find_left_descend(ct_finger* finger, ct_path_entry* path_pos, uint64_t symbol,
					   ct_path_entry** path_pos_out, uint64_t* symbol_out) {
	uint64_t backtrack_symbol = symbol;
	uint64_t prev_child_symbol;
	ct_entry* entry;

	while (1) {
		entry = &(path_pos->entry.value);

		prev_child_symbol = bitmap_child_before(entry, backtrack_symbol);
		if (prev_child_symbol != -1ULL) {
			// This bitmap has a child smaller than us
			*symbol_out = prev_child_symbol;
			*path_pos_out = path_pos;
			return;
		}

		// The finger is in the minimal child of this bitmap. Continue scanning the path upwards
		path_pos--;
		while (path_pos >= &(finger->path[0])) {
			entry = &(path_pos->entry.value);
			if (entry_type(entry) == TYPE_BITMAP) {
				backtrack_symbol = (path_pos + 1)->entry.value.last_symbol;
				break;
			}
			path_pos--;
		}

		if (path_pos < &(finger->path[0])) {
			// We reached the root, so the finger is minimal
			*path_pos_out = NULL;
			return;
		}
	}
}

void init_pred_locator(ct_pred_locator* pred_locator, ct_finger* finger) {
	pred_locator->finger = finger;
}

// Prefetch the predecessor of the <symbol> child of the bitmap at finger->path[path_pos].
// That child doesn't neccessarily exist.
// When called from a reader thread with a writer running concurrently, new keys can be
// added between the child <symbol> and its predecessor. We only guarantee that
// the returned ct_pred_locator struct will describe /some/ leaf that is before the
// child <symbol>, and after the predecessor it had when the function was called.
void prefetch_path_child_predecessor(ct_finger* finger, ct_path_entry* path_pos, uint64_t symbol,
									 ct_pred_locator* predecessor) {
#ifndef NO_LINKED_LIST
	int i;
	uint64_t left_symbol = symbol;
	ct_path_entry* bitmap_path_pos = path_pos;
	uint64_t bitmap_prefix_hash;

	init_pred_locator(predecessor, finger);
	for (i = 0; i < NUM_LINKED_LISTS; i++) {
		find_left_descend(finger, bitmap_path_pos, left_symbol, &bitmap_path_pos, &left_symbol);
		if (bitmap_path_pos == NULL) {
			// We cannot descend to the left - the finger is minimal
			predecessor->subtree[i].path_pos = NULL;
			predecessor->subtree[i].primary_bucket = -1ULL;
			return;
		}

		bitmap_prefix_hash = bitmap_path_pos->prefix_hash;

		uint64_t child_prefix_hash = accumulate_hash(finger->trie, bitmap_prefix_hash, left_symbol);
		prefetch_bucket_pair(finger->trie,
							 hash_to_bucket(child_prefix_hash),
							 hash_to_tag(child_prefix_hash));
		predecessor->subtree[i].path_pos = bitmap_path_pos;
		predecessor->subtree[i].primary_bucket = hash_to_bucket(child_prefix_hash);
		predecessor->subtree[i].tag = hash_to_tag(child_prefix_hash);
		predecessor->subtree[i].parent_color = entry_color(&(bitmap_path_pos->entry.value));
		predecessor->subtree[i].last_symbol = left_symbol;
	}
#endif
}

// Prefetch the predecessor of the leaf pointed by the finger
// Return in predecessor_subtree one of:
// 1. a locator of a leaf which is the predecessor
// 2. a locator of a bitmap/jump node N, where the predecessor is the maximal leaf under N
// 3. an invalid locator (primary_bucket = -1), if the leaf is minimal
void prefetch_leaf_predecessor(ct_finger* finger, ct_pred_locator* pred_locator) {
	if (finger->last_path_entry <= finger->path) {
		// The leaf pointed by the finger is the root
		assert(entry_color(&(finger->containing_entry.value)) == ROOT_COLOR);
		init_pred_locator(pred_locator, finger);
		pred_locator->subtree[0].primary_bucket = -1ULL;
		return;
	}
	prefetch_path_child_predecessor(finger, finger->last_path_entry - 1, finger->last_prefix_symbol, pred_locator);
}

void prefetch_bitmap_child_predecessor(ct_finger* finger, uint64_t symbol, ct_pred_locator* predecessor_loc) {
	prefetch_path_child_predecessor(finger, finger->last_path_entry, symbol, predecessor_loc);
}



// The finger is in a leaf <leaf>, and <leaf>->key != <key>. Create a path of
// jump nodes for the common part of <key> and <leaf>->key, with a bitmap node
// at the bottom to separate them.
// Moves the finger to the created bitmap node.
// is_maximal - whether <key> is larger than the key in the leaf pointed by the finger
// min_child_symbol - of the two bitmap children, which one is the minimal
// pred_locator - describes the predecessor of the leaf pointed by the finger
int split_leaf(ct_finger* finger, ct_kv* kv, int is_maximal, ct_pred_locator* pred_locator) {
	int i, ret;
	ct_entry path_nodes[MAX_KEY_SYMBOLS / MAX_JUMP_SYMBOLS + 1];
	uint64_t path_prefix_hashes[MAX_KEY_SYMBOLS / MAX_JUMP_SYMBOLS + 1];
	uint64_t num_path_nodes = 0;
	uint64_t path_nodes_written = 0;
	uint64_t prefix_len = finger->prefix_len;
	uint64_t last_symbol = finger->last_prefix_symbol;
	uint64_t prefix_hash = finger->prefix_hash;
	uint64_t existing_key_symbol;
	uint64_t new_key_symbol;
	uint64_t minimal_child;
	uint64_t maximal_child;
	uint64_t maximal_leaf_hash = -1; // Just to please GCC, will be initialized later
	uint64_t minimal_leaf_hash = -1; // Just to please GCC, will be initialized later
	ct_kv* minimal_kv;
	ct_kv* maximal_kv;
	ct_entry minimal_leaf_content;
	ct_entry maximal_leaf_content;
	ct_entry_storage* minimal_leaf = NULL;
	ct_entry_storage* maximal_leaf = NULL;
	uint8_t maximal_leaf_color;
	uint8_t minimal_leaf_color;
	uint8_t maximal_leaf_tag;
	ct_kv* existing_kv = entry_kv(&(finger->containing_entry.value));
	ct_entry* cur_jump_node = NULL;
	ct_entry_locator original_leaf_next = finger->containing_entry.value.next_leaf;

	// Take all required locks

	if (finger->last_path_entry > finger->path) {
		ret = upgrade_lock(&(finger->lock_mgr), &((finger->last_path_entry - 1)->entry));
		if (ret == SI_RETRY)
			goto locking_failed;
	}

	// TODO: only if the leaf is maximal
	if (finger->last_path_entry > finger->path) {
		ret = upgrade_locks_on_left_parents_above(finger, finger->last_path_entry - 1);
		if (ret == SI_RETRY)
			goto locking_failed;
	}

	// Lock the leaf to be split
	ret = upgrade_lock(&(finger->lock_mgr), &(finger->containing_entry));
	if (ret == SI_RETRY)
		goto locking_failed;

#ifndef NO_LINKED_LIST
	// Lock the predecessor leaf
	ret = get_predecessor_atomic(finger->trie, pred_locator, &(pred_locator->predecessor[0]));
	if (ret == 0)
		goto locking_failed;

	ret = upgrade_lock(&(finger->lock_mgr), &(pred_locator->predecessor[0]));
	if (ret == SI_RETRY)
		goto locking_failed;
#endif

	// Create all jump nodes in the path in a local buffer
	// The <color>, <child_color> and <max_leaf> fields will be set later
	while (1) {
		existing_key_symbol = get_key_symbol(existing_kv, prefix_len);
		new_key_symbol = get_key_symbol(kv, prefix_len);

		if (existing_key_symbol != new_key_symbol)
			break;    // We found the splitting point

		if (num_path_nodes == 0 ||
			entry_jump_size(&(path_nodes[num_path_nodes - 1])) == MAX_JUMP_SYMBOLS) {
			// Create a new jump node
			cur_jump_node = &(path_nodes[num_path_nodes]);
			path_prefix_hashes[num_path_nodes] = prefix_hash;

			// Set the parent color to INVALID_COLOR. The parent color of
			// the first jump will be overwritten later
			cur_jump_node->parent_color_and_flags = (INVALID_COLOR << PARENT_COLOR_SHIFT) | TYPE_JUMP;
			cur_jump_node->last_symbol = last_symbol;
			cur_jump_node->color_and_tag = hash_to_tag(prefix_hash);
			cur_jump_node->child_color_and_jump_size = 0;
			num_path_nodes++;
		}

		extend_jump_node(cur_jump_node, new_key_symbol);

		last_symbol = existing_key_symbol;
		prefix_hash = accumulate_hash(finger->trie, prefix_hash, existing_key_symbol);
		prefix_len++;
	}

	if (is_maximal) {
		minimal_child = existing_key_symbol;
		maximal_child = new_key_symbol;
		minimal_kv = existing_kv;
		maximal_kv = kv;
	} else {
		minimal_child = new_key_symbol;
		maximal_child = existing_key_symbol;
		minimal_kv = kv;
		maximal_kv = existing_kv;
	}

	// Add the bitmap node at the end of the local path buffer
	ct_entry* bitmap_node = &(path_nodes[num_path_nodes]);
	path_prefix_hashes[num_path_nodes] = prefix_hash;
	num_path_nodes++;
	bitmap_node->parent_color_and_flags = (INVALID_COLOR << PARENT_COLOR_SHIFT) | TYPE_BITMAP;
	bitmap_node->last_symbol = last_symbol;
	memset(bitmap_node->child_bitmap, 0, CHILD_BITMAP_BYTES);

	// The first path node will replace the existing leaf, so it has to have the same color,
	// tag and parent_color.
	entry_set_parent_color(&(path_nodes[0]), entry_parent_color(&(finger->containing_entry.value)));
	path_nodes[0].color_and_tag = finger->containing_entry.value.color_and_tag;
	if (finger->containing_entry.value.parent_color_and_flags & FLAG_SECONDARY_BUCKET)
		path_nodes[0].parent_color_and_flags |= FLAG_SECONDARY_BUCKET;

	minimal_leaf_hash = accumulate_hash(finger->trie, prefix_hash, minimal_child);
	maximal_leaf_hash = accumulate_hash(finger->trie, prefix_hash, maximal_child);

	// Parent color isn't known yet, will be set later
	maximal_leaf_content.parent_color_and_flags = TYPE_LEAF;
	maximal_leaf_content.last_symbol = maximal_child;

	// Create the maximal bitmap child
	ret = add_entry(&(finger->lock_mgr),
					maximal_leaf_hash,
					&maximal_leaf_content,
					NULL, &maximal_leaf, 1);

	if (ret == SI_RETRY)
		goto locking_failed;
	if (ret == SI_FAIL)
		goto trie_full;

	entry_set_kv((ct_entry*) maximal_leaf, maximal_kv);
	((ct_entry*) maximal_leaf)->next_leaf = original_leaf_next;
	maximal_leaf_color = entry_color((ct_entry*) maximal_leaf);
	maximal_leaf_tag = hash_to_tag(maximal_leaf_hash);

	// Mark the two children in the bitmap
	set_bit(bitmap_node->child_bitmap, minimal_child, 1);
	set_bit(bitmap_node->child_bitmap, maximal_child, 1);
	bitmap_node->max_child = maximal_child;

	// Set maximal_leaf as the max_leaf of all path_nodes
	for (i = 0;i < num_path_nodes;i++) {
		path_nodes[i].max_leaf.color = maximal_leaf_color;
		path_nodes[i].max_leaf.tag = maximal_leaf_tag;
		path_nodes[i].max_leaf.primary_bucket = hash_to_bucket(maximal_leaf_hash);
	}

	// Put all path nodes except the head in the hashtable, bottom-to-top
	for (i = num_path_nodes - 1;i >= 1;i--) {
		ct_entry_storage* entry;
		ret = add_entry(&(finger->lock_mgr),
						path_prefix_hashes[i],
						&(path_nodes[i]),
						NULL, &entry, 1);
		if (ret == SI_RETRY)
			goto locking_failed;

		if (ret == SI_FAIL)
			goto trie_full;

		path_nodes_written++;
		debug_log("split_leaf: Added jump node %p\n", entry);
		entry_set_child_color(&(path_nodes[i-1]), entry_color(&(path_nodes[i])));
	}

	entry_set_parent_color((ct_entry*) maximal_leaf, entry_color(bitmap_node));

	// Create the minimal bitmap child
	ct_entry_locator minimal_leaf_next;
	minimal_leaf_next.primary_bucket = hash_to_bucket(maximal_leaf_hash);
	minimal_leaf_next.color = maximal_leaf_color;
	minimal_leaf_next.tag = maximal_leaf_tag;

	minimal_leaf_content.last_symbol = minimal_child;
	minimal_leaf_content.parent_color_and_flags = (entry_color(bitmap_node) << PARENT_COLOR_SHIFT) | TYPE_LEAF;
	entry_set_kv(&minimal_leaf_content, minimal_kv);
	minimal_leaf_content.next_leaf = minimal_leaf_next;
	ret = add_entry(&(finger->lock_mgr), minimal_leaf_hash, &minimal_leaf_content,
					maximal_leaf, &minimal_leaf, 1);
	if (ret == SI_RETRY)
		goto locking_failed;
	if (ret == SI_FAIL)
		goto trie_full;
	minimal_leaf_color = entry_color(&minimal_leaf_content);

	debug_log("split_leaf: created leaves %p, %p\n", minimal_leaf, maximal_leaf);
#ifndef NO_LINKED_LIST
	mark_entry_dirty(finger->trie, &(pred_locator->predecessor[0]));
#endif

	// Write the path head in place of the leaf, making the whole path reachable
	// This also updates the copy of the path head inside finger->path
	update_entry(finger->trie, &(finger->last_path_entry->entry), &(path_nodes[0]));

	linklist_insert_two(finger->trie, pred_locator, minimal_leaf_hash, minimal_leaf_color);

	// Update max_leaf of nodes above the path
	propagate_max_leaf(finger, &(finger->path[0]));

#ifndef NO_LINKED_LIST
	mark_entry_clean(finger->trie, &(pred_locator->predecessor[0]));
#endif
	release_all_locks(&(finger->lock_mgr));
	return SI_OK;

locking_failed:
	// Remove all already-written path nodes
	for (i = 0; i < path_nodes_written; i++) {
		uint64_t path_idx = num_path_nodes - 1 - i;
		remove_entry_by_value(&(finger->lock_mgr), &(path_nodes[path_idx]), path_prefix_hashes[path_idx]);
	}

	// If we already created the maximal leaf, remove it
	if (maximal_leaf) {
		remove_entry_by_value(&(finger->lock_mgr), &maximal_leaf_content, maximal_leaf_hash);
	}

	// The minimal leaf is created last. If we succeed in creating it, it means that all locks
	// were taken successfully. Since we're here, this couldn't have been the case.
	assert(!minimal_leaf);

	release_all_locks(&(finger->lock_mgr));
	return SI_RETRY;

trie_full:
	// TODO: Remove the nodes we already added
	release_all_locks(&(finger->lock_mgr));
	return SI_FAIL;
}

// Assuming the finger is inside a jump node, changes the symbol just after
// the finger to a bitmap node, and moves the finger to that node.
// If there are more symbols after the bitmap node, a new jump node
// is created for them.
int split_jump_node(ct_finger* finger) {
	ct_entry* bitmap_node = NULL; // Just to please GCC, will be initialized later
	ct_entry new_head;
	ct_entry new_bitmap;
	int ret;
	int created_new_bitmap = 0;
	ct_entry_storage* bitmap_node_in_trie = NULL;
	ct_entry_local_copy bitmap_child;
	uint32_t bitmap_seq = -1;  // Just to please GCC, will be initialized later
	uint64_t split_symbol;
	uint64_t tail_prefix_hash;
	uint64_t remaining_jump_symbols = finger->depth_in_jump;
	ct_entry jump_node_backup = finger->containing_entry.value;
	ct_entry_locator orig_max_leaf = finger->containing_entry.value.max_leaf;
	int has_tail = (remaining_jump_symbols + 1 < entry_jump_size(&jump_node_backup));

	assert(remaining_jump_symbols < entry_jump_size(&jump_node_backup));
	split_symbol = get_jump_symbol(&jump_node_backup, remaining_jump_symbols);
	tail_prefix_hash = accumulate_hash(finger->trie, finger->prefix_hash, split_symbol);

	if (!has_tail) {
		// If no tail remains we'll have to change the parent_color of the current
		// child of the jump node. Find and lock it.
		find_entry_in_pair_by_color(finger->trie, &bitmap_child,
									hash_to_bucket(tail_prefix_hash),
									hash_to_tag(tail_prefix_hash),
									entry_child_color(&jump_node_backup));

		ret = upgrade_lock(&(finger->lock_mgr), &bitmap_child);
		if (ret == SI_RETRY)
			goto locking_failed;   // The child's bucket changed since we found the child
	}
	// Write-lock the jump node that will be splitted, so no other thread
	// tries to split it.
	ret = upgrade_lock(&(finger->lock_mgr), &(finger->containing_entry));
	if (ret == SI_RETRY)
		goto locking_failed;
	debug_log("split_jump_node: Splitting jump node. %d symbols remain\n",
			  remaining_jump_symbols);

	// new_head will replace the old jump node, and so should have the same
	// color, tag, last_symbol and max_leaf
	new_head = finger->containing_entry.value;
	entry_set_jump_size(&new_head, remaining_jump_symbols);

	// Create the bitmap node
	if (remaining_jump_symbols == 0) {
		// Transform the jump into a bitmap node
		entry_set_type(&new_head, TYPE_BITMAP);
		bitmap_node = &new_head;
		bitmap_node_in_trie = NULL;
	} else {
		// Create a new bitmap node
		bitmap_node = &new_bitmap;

		// Set parent color to INVALID_COLOR, as the bitmap is the child of a jump node
		bitmap_node->parent_color_and_flags = (INVALID_COLOR << PARENT_COLOR_SHIFT) | TYPE_BITMAP;
		bitmap_node->last_symbol = finger->last_prefix_symbol;
		bitmap_node->max_leaf = orig_max_leaf;

		created_new_bitmap = 1;
	}
	memset(bitmap_node->child_bitmap, 0, CHILD_BITMAP_BYTES);

	set_bit(bitmap_node->child_bitmap, split_symbol, 1);
	bitmap_node->max_child = split_symbol;

	if (created_new_bitmap) {
		ret = add_entry(&(finger->lock_mgr),
						finger->prefix_hash,
						bitmap_node,
						NULL,
						&bitmap_node_in_trie, 1);
		if (ret == SI_RETRY)
			goto locking_failed;
		if (ret == SI_FAIL)
			goto trie_full;

		bitmap_seq = *counter_ptr(bitmap_node_in_trie);
		entry_set_child_color(&new_head, entry_color(bitmap_node));
	}

	if (has_tail) {
		// Create the tail jump node
		uint64_t num_tail_symbols = entry_jump_size(&jump_node_backup) - remaining_jump_symbols - 1;
		ct_entry tail_entry;
		ct_entry_storage* tail_addr;

		tail_entry.parent_color_and_flags = (entry_color(bitmap_node) << PARENT_COLOR_SHIFT) | TYPE_JUMP;
		tail_entry.child_color_and_jump_size = entry_child_color(&jump_node_backup) << CHILD_COLOR_SHIFT;
		tail_entry.child_color_and_jump_size |= num_tail_symbols;
		tail_entry.last_symbol = split_symbol;
		tail_entry.max_leaf = orig_max_leaf;
		copy_bits(tail_entry.jump_bits, jump_node_backup.jump_bits,
				  (remaining_jump_symbols + 1) * BITS_PER_SYMBOL,
				  num_tail_symbols * BITS_PER_SYMBOL);

		ret = add_entry(&(finger->lock_mgr),
						tail_prefix_hash,
						&tail_entry,
						bitmap_node_in_trie,
						&tail_addr, 0);
		if (ret == SI_RETRY)
			goto locking_failed;
		if (ret == SI_FAIL)
			goto trie_full;
	} else {
		// We don't have a tail, so what was once the child of the target
		// jump node is now a child of the bitmap node. Mark it accordingly.

		entry_set_parent_color_atomic(bitmap_child.last_pos, entry_color(bitmap_node));
	}

	// Write the new head node, making the added nodes accessible
	update_entry(finger->trie, &(finger->last_path_entry->entry), &new_head);

	// We changed contents of the jump node pointed by the finger (either truncated it or made it
	// a bitmap). Update its copy inside the finger.
	reread_path_end(finger);

	// Move the finger to the bitmap
	if (created_new_bitmap) {
		// TODO: Creating the entry_local_copy here is hacky. add_entry should return
		// an entry_local_copy for the entry it created.
		finger->containing_entry.value = *bitmap_node;
		finger->containing_entry.last_pos = bitmap_node_in_trie;
		finger->containing_entry.primary_bucket = hash_to_bucket(finger->prefix_hash);
		finger->containing_entry.last_seq = bitmap_seq;
		finger_node_changed(finger, 1);
	}

	release_all_locks(&(finger->lock_mgr));
	return SI_OK;

locking_failed:
	// If we already created the bitmap, remove it
	if (bitmap_node_in_trie)
		remove_entry_by_value(&(finger->lock_mgr), bitmap_node, finger->prefix_hash);

	release_all_locks(&(finger->lock_mgr));
	return SI_RETRY;

trie_full:
	// TODO: Remove the nodes we already added
	release_all_locks(&(finger->lock_mgr));
	return SI_FAIL;
}

// Create a new leaf in the trie for <key>
// <key> is a key that is not in the trie, and <finger> points
// to the longest prefix of <key> in the trie. <next_symbol> is
// the next symbol of <key>, after the prefix that the finger
// points to.
int create_leaf(ct_finger* finger, ct_kv* kv, uint64_t next_symbol) {
	ct_entry_storage* new_leaf;
	ct_pred_locator pred_locator;
	int result, ret;

	if (entry_type(&(finger->containing_entry.value)) == TYPE_JUMP) {
		assert(finger->depth_in_jump != entry_jump_size(&(finger->containing_entry.value)));

		// We're at the middle of a jump node. Split it.
		ret = split_jump_node(finger);
		if (ret == SI_RETRY)
			goto locking_failed;

		if (ret == SI_FAIL) {
			debug_log("create_leaf: splitting leaf failed\n", next_symbol);
			return SI_FAIL;
		}

		// The finger is now at the newly-created bitmap node, and
		// we continue with the bitmap flow.
	}

	if (entry_type(&(finger->containing_entry.value)) == TYPE_BITMAP) {
		// The finger is at a bitmap node, which doesn't have the required child
		uint64_t new_leaf_hash;
		ct_entry_locator new_leaf_next;
		prefetch_bitmap_child_predecessor(finger, next_symbol, &pred_locator);
		new_leaf_hash = accumulate_hash(finger->trie, finger->prefix_hash, next_symbol);

		// Write-lock the bitmap, s.t. no other thread will try to create the child
		ret = upgrade_lock(&(finger->lock_mgr), &(finger->containing_entry));
		if (ret == SI_RETRY)
			goto locking_failed;

		// Take all required locks
		// TODO: Can be done later, to give the predecessor prefetch more time to be performed

		// TODO: Only if the new child is maximal
		ret = upgrade_locks_on_left_parents_above(finger, finger->last_path_entry);
		if (ret == SI_RETRY)
			goto locking_failed;

#ifndef NO_LINKED_LIST
		ret = get_predecessor_atomic(finger->trie, &pred_locator, &(pred_locator.predecessor[0]));
		if (ret == 0)
			goto locking_failed;

		// Lock the predecessor leaf
		ret = upgrade_lock(&(finger->lock_mgr), &(pred_locator.predecessor[0]));
		if (ret == SI_RETRY)
			goto locking_failed;
#endif

		ret = create_bitmap_child(finger, entry_color(&(finger->containing_entry.value)),
								  next_symbol, kv, &new_leaf);
		if (ret == SI_RETRY)
			goto locking_failed;
		if (ret == SI_FAIL) {
			debug_log("create_leaf: Creating new child 0x%x failed\n", next_symbol);
			release_all_locks(&(finger->lock_mgr));
			return SI_FAIL;
		}
		debug_log("create_leaf: Created new child 0x%x of bitmap @ %p\n",
				  next_symbol, new_leaf);

		// The new child was created, but is still unreachable, as it is not marked
		// in the parent bitmap and not set as the max_leaf or next_leaf of any node

		// Update the next_leaf field of the new leaf. The new leaf is currently unreachable,
		// so we don't have to increment the sequence of its bucket.
		new_leaf_next = pred_locator.predecessor[0].value.next_leaf;
		((ct_entry*) new_leaf)->next_leaf = new_leaf_next;

#ifndef NO_LINKED_LIST
		mark_entry_dirty(finger->trie, &(pred_locator.predecessor[0]));
#endif
		linklist_insert(finger->trie, &pred_locator, new_leaf, hash_to_bucket(new_leaf_hash));
		mark_bitmap_child(finger->trie, &(finger->last_path_entry->entry),
						  next_symbol, new_leaf_hash, entry_color((ct_entry*) new_leaf));

		// Marking the child changed the bitmap. Update the finger.
		reread_path_end(finger);
		propagate_max_leaf(finger, &(finger->path[0]));
#ifndef NO_LINKED_LIST
		mark_entry_clean(finger->trie, &(pred_locator.predecessor[0]));
#endif
		release_all_locks(&(finger->lock_mgr));
	} else {
		// The finger is at a leaf
		prefetch_leaf_predecessor(finger, &pred_locator);

		ct_kv* leaf_kv = entry_kv(&(finger->containing_entry.value));
		int leaf_cmp = kv_key_compare(leaf_kv, kv);

		if (leaf_cmp == 0)
			return SI_EXISTS;  // The leaf contains the key we're about to insert

		// If not, convert this leaf to a path.
		// split_leaf handles all linklist maintenance.
		debug_log("create_leaf: Will split leaf\n");

		result = split_leaf(finger, kv, leaf_cmp < 0, &pred_locator);
		if (result != SI_OK)
			return result;
	}

	return SI_OK;

locking_failed:
	release_all_locks(&(finger->lock_mgr));
	return SI_RETRY;
}

uint64_t read_qword_zfill(const uint8_t* from, uint64_t size) {
	uint64_t tmp;
	if (size >= 8)
		return *((uint64_t*)from);

	if (likely((((uintptr_t)from) & 0xFFF) > 8)) {
		tmp = *((uint64_t*)(from - 8 + size));
		tmp >>= 64 - 8*size;
		return tmp;
	}

	tmp = *((uint64_t*)from);
	return __builtin_ia32_bzhi_di(tmp, 8*size);
}

void key_to_symbols(const uint8_t* key, uint64_t size, uint8_t* symbols) {
	// We have 2**BITS_PER_SYMBOL + 1 different symbols, and each should fit in  a byte
	assert(BITS_PER_SYMBOL < 8);

	const uint64_t ones = 0x0101010101010101ULL;

	int64_t bytes_left = size;
	const uint8_t* key_ptr = key;
	uint8_t* next_sym_ptr = symbols;

	while (bytes_left > 0) {
		uint64_t key_qword = __builtin_bswap64(read_qword_zfill(key_ptr, bytes_left));

		// pdep works on the low bits, move key bytes there.
		key_qword >>= (64 - 8*BITS_PER_SYMBOL);

		*((uint64_t*)next_sym_ptr) = __builtin_bswap64(__builtin_ia32_pdep_di(key_qword, ones * (FANOUT - 1)) + ones);
		next_sym_ptr += 8;
		key_ptr += BITS_PER_SYMBOL;
		bytes_left -= BITS_PER_SYMBOL;
	}
}

typedef struct {
	uint8_t key_symbols[MAX_KEY_SYMBOLS];

	// prefix_hashes[i] is the hash of the key up to and including the i'th symbol
	uint64_t prefix_hashes[MAX_KEY_SYMBOLS];
	uint64_t prefetch_prefix_hash;
	uint64_t prefetch_pos;
	uint64_t num_key_symbols;
} key_prefetcher;

static inline void prefetcher_start(key_prefetcher* p, cuckoo_trie* trie, uint64_t key_size,
									uint8_t* key_bytes) {
	int i;
	p->num_key_symbols = (key_size * 8 + BITS_PER_SYMBOL - 1) / BITS_PER_SYMBOL + 1;
	key_to_symbols(key_bytes, key_size, p->key_symbols);
	p->key_symbols[p->num_key_symbols - 1] = SYMBOL_END;
	p->prefetch_prefix_hash = HASH_START_VALUE;
	for (i = 0; i < 4 && i < p->num_key_symbols; i++) {
		assert(p->key_symbols[i] == get_string_symbol(key_size, key_bytes, i));
		p->prefetch_prefix_hash = accumulate_hash(trie, p->prefetch_prefix_hash, p->key_symbols[i]);
		p->prefix_hashes[i] = p->prefetch_prefix_hash;
		prefetch_bucket_pair(trie, hash_to_bucket(p->prefetch_prefix_hash), hash_to_tag(p->prefetch_prefix_hash));
	}
	p->prefetch_pos = i;
}

static inline void prefetcher_step(key_prefetcher* p, cuckoo_trie* trie) {
	if (p->prefetch_pos < p->num_key_symbols) {
		p->prefetch_prefix_hash = accumulate_hash(trie, p->prefetch_prefix_hash, p->key_symbols[p->prefetch_pos]);
		p->prefix_hashes[p->prefetch_pos] = p->prefetch_prefix_hash;
		prefetch_bucket_pair(trie, hash_to_bucket(p->prefetch_prefix_hash), hash_to_tag(p->prefetch_prefix_hash));
		p->prefetch_pos++;
	}
}

// Given a finger positioned on the root, descend as much as possible along
// the symbols of <key>.
// Returns the first failed symbol (or -1 if the whole descent was successful)
int descend(ct_finger* finger, uint64_t key_size, uint8_t* key_bytes, int track_path) {
	uint64_t symbol;
	key_prefetcher prefetcher;

	prefetcher_start(&prefetcher, finger->trie, key_size, key_bytes);
	while (1) {
		prefetcher_step(&prefetcher, finger->trie);
		symbol = prefetcher.key_symbols[finger->prefix_len];
		debug_log("Trying to descend symbol 0x%x\n", symbol);
		int success = try_descend(finger, symbol, track_path, prefetcher.prefix_hashes[finger->prefix_len]);
		if (!success)
			return symbol;
		if (symbol == SYMBOL_END)
			return -1;  // We successfully descended the END symbol, meaning that the descent is done
	}
}

int ct_insert_internal(cuckoo_trie* trie, ct_kv* kv, int is_upsert) {
	ct_finger finger;
	ct_entry_storage* root;
	uint64_t symbol = -1;  // Just to please GCC. Will be initialized later.
	int result;
	int ret;

	// Add 1 for the special END symbol
	int num_key_symbols = (kv_key_size(kv) * 8 + BITS_PER_SYMBOL - 1) / BITS_PER_SYMBOL + 1;

	root = init_finger(&finger, trie);

	if (root == NULL) {
		// The trie is empty
		ret = create_root(&finger, kv);
		if (ret == SI_EXISTS) {
			// Another thread created a root in the meantime, use it
			root = init_finger(&finger, trie);
		} else {
			// We created the root
			assert(ret == SI_OK);
			return SI_OK;
		}
	}

	symbol = descend(&finger, kv_key_size(kv), kv_key_bytes(kv), 1);

	// We're now at the longest prefix of <key> in the trie, and cannot descend anymore.

	result = create_leaf(&finger, kv, symbol);

	if (is_upsert && result == SI_EXISTS) {
		assert(entry_type(&(finger.containing_entry.value)) == TYPE_LEAF);
		ret = upgrade_lock(&(finger.lock_mgr), &(finger.containing_entry));
		if (ret == SI_RETRY)
			return SI_RETRY;

		ct_entry new_entry = finger.containing_entry.value;
		entry_set_kv(&new_entry, kv);
		update_entry(trie, &(finger.containing_entry), &new_entry);
		release_all_locks(&(finger.lock_mgr));
	}

	return result;
}

int ct_insert(cuckoo_trie* trie, ct_kv* kv) {
	int ret;

	if (kv_key_size(kv) > MAX_KEY_BYTES)
		return S_KEYTOOLONG;

	do {
		ret = ct_insert_internal(trie, kv, 0);
		if (ret == SI_RETRY)
			debug_log("Insert retry\n");
	} while (ret == SI_RETRY);

	if (ret == SI_FAIL)
		return S_OVERFLOW;

	if (ret == SI_EXISTS)
		return S_ALREADYIN;

	assert(ret == SI_OK);
	return S_OK;
}

int ct_upsert(cuckoo_trie* trie, ct_kv* kv, int* created_new) {
	int ret;

	if (kv_key_size(kv) > MAX_KEY_BYTES)
		return S_KEYTOOLONG;

	do {
		ret = ct_insert_internal(trie, kv, 1);
		if (ret == SI_RETRY)
			debug_log("Insert retry\n");
	} while (ret == SI_RETRY);

	if (ret == SI_FAIL)
		return S_OVERFLOW;

	assert(ret == SI_OK || ret == SI_EXISTS);

	if (ret == SI_EXISTS)
		*created_new = 0;
	else
		*created_new = 1;

	return S_OK;
}

ct_kv* ct_lookup(cuckoo_trie* trie, uint64_t key_size, uint8_t* key_bytes) {
	int symbol;
	ct_finger finger;
	ct_entry_storage* root;

	root = init_finger(&finger, trie);

	if (root == NULL)
		return NULL;  // The trie is empty

	symbol = descend(&finger, key_size, key_bytes, 0);

	// If the whole key, including the END symbol, is a uniq-prefix, then this prefix
	// must point to the key itself
	if (symbol == -1) {
		assert(entry_type(&(finger.containing_entry.value)) == TYPE_LEAF);
		return entry_kv(&(finger.containing_entry.value));
	}

	if (entry_type(&(finger.containing_entry.value)) != TYPE_LEAF)
		return NULL; // No uniq-prefix matches <key>

	// Compare with the key stored in the leaf
	ct_kv* leaf_kv = entry_kv(&(finger.containing_entry.value));
	if (kv_key_compare_to(leaf_kv, key_size, key_bytes) == 0)
		return leaf_kv;

	return NULL;
}

int ct_update_internal(cuckoo_trie* trie, ct_kv* kv) {
	int ret;
	int symbol;
	ct_finger finger;
	ct_entry_storage* root;

	root = init_finger(&finger, trie);

	if (root == NULL)
		return SI_FAIL;  // The trie is empty

	symbol = descend(&finger, kv_key_size(kv), kv_key_bytes(kv), 0);

	if (entry_type(&(finger.containing_entry.value)) != TYPE_LEAF)
		return SI_FAIL; // No uniq-prefix matches <key>

	// Compare with the key stored in the leaf
	ct_kv* leaf_kv = entry_kv(&(finger.containing_entry.value));
	if (kv_key_compare(leaf_kv, kv) != 0)
		return SI_FAIL;

	assert(entry_type(&(finger.containing_entry.value)) == TYPE_LEAF);
	ret = upgrade_lock(&(finger.lock_mgr), &(finger.containing_entry));
	if (ret == SI_RETRY)
		return SI_RETRY;

	ct_entry new_entry = finger.containing_entry.value;
	entry_set_kv(&new_entry, kv);
	update_entry(trie, &(finger.containing_entry), &new_entry);
	release_all_locks(&(finger.lock_mgr));

	return SI_OK;
}

int ct_update(cuckoo_trie* trie, ct_kv* kv) {
	int ret;

	while (1) {
		ret = ct_update_internal(trie, kv);
		if (ret != SI_RETRY)
			break;
	}

	if (ret == SI_FAIL)
		return S_NOTFOUND;

	assert(ret == SI_OK);
	return S_OK;
}

// Place the iterator on the first key larger or equal to <key>
int ct_iter_goto_internal(ct_iter* iter, uint64_t key_size, uint8_t* key_bytes) {
	uint64_t depth;
	uint64_t symbol = -1;  // Just to please GCC. Will be initialized later.
	ct_finger finger;
	ct_entry* longest_prefix;
	ct_entry_storage* root;
	ct_pred_locator predecessor;
	key_prefetcher prefetcher;
	ct_path_entry* last_bitmap_path_pos = NULL;  // The lowest bitmap on the path to <key>

	// Add 1 for the special END symbol
	int num_key_symbols = (key_size * 8 + BITS_PER_SYMBOL - 1) / BITS_PER_SYMBOL + 1;

	root = init_finger(&finger, iter->trie);
	iter->is_exhausted = 0;

	if (root == NULL) {
		// The trie is empty
		iter->is_exhausted = 1;
		return SI_OK;
	}

	if (key_size == 0) {
		// The key is empty, so it is smaller or equal to any key in the trie
		read_min_leaf(iter->trie, &(iter->leaves[0]));
		return SI_OK;
	}

	prefetcher_start(&prefetcher, iter->trie, key_size, key_bytes);
	for (depth = 0;depth < num_key_symbols;depth++) {
		prefetcher_step(&prefetcher, iter->trie);
		if (entry_type(&(finger.containing_entry.value)) == TYPE_BITMAP)
			last_bitmap_path_pos = finger.last_path_entry;
		symbol = prefetcher.key_symbols[depth];
		debug_log("ct_iter_goto_interal: Trying to descend symbol 0x%x\n", symbol);

		// find_bitmap_child_predecessor requires path tracking to be enabled
		int success = try_descend(&finger, symbol, 1, prefetcher.prefix_hashes[depth]);
		if (!success)
			break;
	}

	longest_prefix = &(finger.containing_entry.value);   // The lowest node on the path to <key>

	if (entry_type(longest_prefix) == TYPE_BITMAP) {
		// We reached a bitmap without the required child
		prefetch_bitmap_child_predecessor(&finger, symbol, &predecessor);
	} else {
		// We reached a leaf, or a jump node with leaves under it.

		// <key> is either smaller than all keys under <longest_prefix>, or larger than
		// all these keys. If <key> itself is in the trie, we consider it as if it is
		// smaller than the longest prefix.
		int is_before_longest_prefix;

		if (entry_type(longest_prefix) == TYPE_LEAF) {
			ct_kv* leaf_kv = entry_kv(longest_prefix);
			is_before_longest_prefix = (kv_key_compare_to(leaf_kv, key_size, key_bytes) >= 0);
		} else {
			// We got stuck in the middle of a jump node, compare the key symbol
			// that was different from the jump.
			uint64_t next_symbol_in_jump = get_jump_symbol(longest_prefix, finger.depth_in_jump);
			assert(symbol != next_symbol_in_jump);
			is_before_longest_prefix = (symbol < next_symbol_in_jump);
		}

		if (last_bitmap_path_pos != NULL) {
			// TODO: We have the lowest-bitmap-above-this logic both here and inside
			// find_left_descend. Remove it from here.
			uint64_t last_bitmap_child = (last_bitmap_path_pos + 1)->entry.value.last_symbol;
			if (is_before_longest_prefix) {
				prefetch_path_child_predecessor(&finger, last_bitmap_path_pos,
												last_bitmap_child, &predecessor);
			} else {
				prefetch_path_child_predecessor(&finger, last_bitmap_path_pos,
												last_bitmap_child + 1, &predecessor);
			}
		} else {
			if (is_before_longest_prefix) {
				// The root should be reported
				// TODO extract method for thread-safe min-leaf reading
				read_min_leaf(iter->trie, &(iter->leaves[0]));
				if (entry_dirty(&(iter->leaves[0].value)))
					return SI_RETRY;

				// Verify that the root-that-is-leaf didn't change in the meantime
				if (!validate_entry(&(iter->leaves[0])))
					return SI_RETRY;
			} else {
				// The trie contains just the root, and <key> is larger than the root,
				// so no keys should be reported
				iter->is_exhausted = 1;
			}
			return SI_OK;
		}
	}

	// <predecessor> now describes the leaf(s) just before <key>
	// Place the iterator on that leaf
	if (!get_predecessor_atomic(iter->trie, &predecessor, &(iter->leaves[0])))
		return SI_RETRY;

	return SI_OK;
}

inline ct_entry_local_copy* iter_max_leaf(ct_iter* iter) {
	return &(iter->leaves[NUM_LINKED_LISTS - 1]);
}

int ct_iter_next_internal(ct_iter* iter) {
	ct_entry_local_copy new_leaf;

	locator_to_entry(iter->trie, &(iter->leaves[0].value.next_leaf), &new_leaf);
	if (entry_type(&(new_leaf.value)) != TYPE_LEAF)
		return SI_RETRY;

	copy_as_qwords(&(iter->leaves[0]), &new_leaf, sizeof(new_leaf));
	prefetch_bucket_pair(iter->trie, new_leaf.value.next_leaf.primary_bucket, new_leaf.value.next_leaf.tag);

	return SI_OK;
}

void ct_iter_goto(ct_iter* iter, uint64_t key_size, uint8_t* key_bytes) {
	int result;

	while(1) {
		result = ct_iter_goto_internal(iter, key_size, key_bytes);
#ifndef MULTITHREADING
		assert(result == SI_OK);
#else
		if (result == SI_RETRY)
			continue;
#endif

		if (iter->leaves[0].value.next_leaf.primary_bucket == ((uint32_t)-1))
			iter->is_exhausted = 1;

		if (iter->is_exhausted)
			return;

		// A fine point: The iterator now contains a leaf A with A.key < <key>,
		// A.next = C and C.key >= <key>. Assume now that a leaf B is added to the
		// trie between A and C before the first call to ct_iter_next. ct_iter_next
		// will detect that when it re-reads A and will resync the iterator. The
		// iterator will then fetch B, but cannot compare <key> and B.key to know
		// whether to report it.
		// Instead of storing a copy of <key> in the iterator, we advance it
		// here, while we have a pointer to <key>, and report the fetched key
		// on the next call to ct_iter_next.

		result = ct_iter_next_internal(iter);
#ifndef MULTITHREADING
		assert(result == SI_OK);
#else
		if (result == SI_RETRY)
			continue;
#endif
		break;
	}

	iter->report_current = 1;
}

// Retrieve the next key from the iterator and advance it
// Returns NULL if the maximal key was already returned
ct_kv* ct_iter_next(ct_iter* iter) {
	int result;

	if (iter->is_exhausted)
		return NULL;

	if (iter->report_current) {
		iter->report_current = 0;
		return entry_kv(&(iter_max_leaf(iter)->value));
	}

	if (iter->leaves[0].value.next_leaf.primary_bucket == ((uint32_t)-1)) {
		iter->is_exhausted = 1;
		return NULL;
	}

	while (1) {
		result = ct_iter_next_internal(iter);

		if (result == SI_RETRY) {
			// The linked list was changed. Recompute iter->leaves to point to consecutive
			// leaves.
#ifdef MULTITHREADING
			// The next key to report isn't the minimal key.

			// Goto the last reported key, and go to the first key after it.
			// We always advance an iterator once in ct_iter_goto, so
			// iter_max_leaf(iter) is a leaf in the trie, and not one of
			// the pseudo-leaves in trie->min_leaf
			ct_kv* last_reported_key = entry_kv(&(iter_max_leaf(iter)->value));
			ct_iter_goto(iter, kv_key_size(last_reported_key), kv_key_bytes(last_reported_key));

			// ct_iter_goto will set report_current, as the last reported
			// key is still in the trie. However, it was already reported (ct_iter_goto
			// doesn't know that). Unset report_current.
			assert(iter->report_current);
			iter->report_current = 0;

			continue;
#else
			// Without multithreading, we don't expect concurrent modifications.
			assert(0);
#endif
		}

		assert(result == SI_OK);
		break;
	}

	// Return the kv of the newly fetched leaf
	return entry_kv(&(iter_max_leaf(iter)->value));
}

ct_iter* ct_iter_alloc(cuckoo_trie* trie) {
	ct_iter* result = malloc(sizeof(ct_iter));

	result->trie = trie;
	return result;
}

void init_buckets(cuckoo_trie* trie) {
	uint64_t bucket_num;

	for (bucket_num = 0; bucket_num < trie->num_buckets; bucket_num++) {
		int i;
		for (i = 0;i < CUCKOO_BUCKET_SIZE;i++) {
			ct_entry_storage* entry = &(trie->buckets[bucket_num].cells[i]);
			((ct_entry*) entry)->parent_color_and_flags = (INVALID_COLOR << PARENT_COLOR_SHIFT) | TYPE_UNUSED;
			((ct_entry*) entry)->color_and_tag = INVALID_COLOR << TAG_BITS;
		}
		trie->buckets[bucket_num].write_lock_and_seq = 0;
	}
}

// Generate a table of random constants in the range [0, trie->num_buckets],
// to be used by {mix,unmix}_bucket
void init_bucket_mix_table(cuckoo_trie* trie) {
	uint64_t i;

	rand_seed(1);
	for (i = 0; i < (1 << TAG_BITS); i++)
		trie->bucket_mix_table[i] = rand_uint64() % trie->num_buckets;
}

cuckoo_trie* ct_alloc(uint64_t num_cells) {
	uint64_t num_buckets = (num_cells + CUCKOO_BUCKET_SIZE - 1) / CUCKOO_BUCKET_SIZE;
	uint64_t buckets_to_alloc;

	// Make num_buckets a multiple of FANOUT*2 s.t. xor-ing a symbol (which is in the range
	// 0 .. FANOUT, inclusive) won't make a bucket number invalid.
	num_buckets = (num_buckets + (FANOUT*2) - 1) / (FANOUT*2) * (FANOUT*2);

	buckets_to_alloc = num_buckets + 1;  // Add space for the min_leaf bucket

	uint64_t buckets_pages = (buckets_to_alloc * sizeof(ct_bucket)) / HUGEPAGE_SIZE + 1;
	ct_bucket* buckets = mmap_hugepage(buckets_pages * HUGEPAGE_SIZE);
	if (!buckets)
		return NULL;

	cuckoo_trie* result = malloc(sizeof(cuckoo_trie));
	if (!result) {
		munmap(buckets, buckets_pages * HUGEPAGE_SIZE);
		return NULL;
	}

	result->buckets = buckets;

	// The last bucket in the allocation is for the min_leaf bucket
	result->min_leaf_bucket = &(buckets[num_buckets]);
	result->num_buckets = num_buckets;
	result->num_pairs = num_buckets * (1ULL << TAG_BITS);

	result->num_shuffle_blocks = result->num_pairs >> BITS_PER_SYMBOL;

	// Set the type of the linklist heads to TYPE_LEAF, or predecessor search
	// might try to access their max_leaf fields.
	((ct_entry*) trie_min_leaf(result))->parent_color_and_flags = TYPE_LEAF;
	((ct_entry*) trie_min_leaf(result))->next_leaf.primary_bucket = (uint32_t)-1;

	result->is_empty = 1;
	init_bucket_mix_table(result);
	init_buckets(result);
	return result;
}

void ct_free(cuckoo_trie* trie) {
	uint64_t buckets_pages = (trie->num_buckets * sizeof(ct_bucket)) / HUGEPAGE_SIZE + 1;
	munmap(trie->buckets, buckets_pages * HUGEPAGE_SIZE);
	free(trie);
}
