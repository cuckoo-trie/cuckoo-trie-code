#include <assert.h>
#include <stddef.h>
#include "main.h"
#include "util.h"
#include "compiler.h"

// In x86_64, reading or writing an aligned 32-bit value is atomic by default.
// However, we still have to use __atomic_(store/load) or the compiler might:
// 1. Change the order of the read/write with respect to other reads/writes.
// 2. Read the value from memory multiple times, assuming it didn't change in the meantime.
void write_int_atomic(uint32_t* addr, uint32_t value) {
#ifndef MULTITHREADING
	*addr = value;
#else
	mt_debug_wait_for_access();
	__atomic_store_n(addr, value, __ATOMIC_RELEASE);
	mt_debug_access_done();
#endif
}

uint32_t read_int_atomic(uint32_t* addr) {
#ifndef MULTITHREADING
	return *addr;
#else
	uint32_t result;
	mt_debug_wait_for_access();
	result = __atomic_load_n(addr, __ATOMIC_ACQUIRE);
	mt_debug_access_done();
	return result;
#endif
}

uint32_t write_entry(ct_entry_storage* target, const ct_entry* src) {
	assert(sizeof(ct_entry_storage) <= 16);   // We only write 2 QWORDS
	assert(sizeof(ct_entry_storage) >= 8);    // Otherwise we'll write past the end of the entry
	uint64_t src_part1 = *((uint64_t*)src);
	uint64_t src_part2 = (*((__uint128_t*)src)) >> (8*(sizeof(ct_entry_storage)-8));
	uint64_t* target_part1 = (uint64_t*)target;
	uint64_t* target_part2 = (uint64_t*)(((uintptr_t)target) + sizeof(ct_entry_storage)-8);
#ifndef MULTITHREADING
	*target_part1 = src_part1;
	*target_part2 = src_part2;
	return 0;
#else
	uint32_t seq;
	uint32_t* counter = counter_ptr(target);

	// We can update the counter using an atomic store instead of a more expensive atomic increment,
	// as the bucket is locked. There's no risk of another thread writing to the counter
	// simultaneously, undoing our update.
	seq = *counter;
	assert(!(seq & SEQ_INCREMENT));
#ifdef MULTITHREADING
	// The bucket must be write-locked
	assert(seq & 1);
#endif

	mt_debug_wait_for_access();
	__atomic_store_n(counter, seq + SEQ_INCREMENT, __ATOMIC_RELEASE);
	mt_debug_access_done();

	mt_debug_wait_for_access();
	__atomic_store_n(target_part1, src_part1, __ATOMIC_RELEASE);
	mt_debug_access_done();

	mt_debug_wait_for_access();
	__atomic_store_n(target_part2, src_part2, __ATOMIC_RELEASE);
	mt_debug_access_done();

	mt_debug_wait_for_access();
	__atomic_store_n(counter, seq + 2*SEQ_INCREMENT, __ATOMIC_RELEASE);
	mt_debug_access_done();

	return seq + 2*SEQ_INCREMENT;
#endif
}

void entry_set_parent_color_atomic(ct_entry_storage* entry, uint8_t parent_color) {
#ifndef MULTITHREADING
	entry_set_parent_color((ct_entry*)entry, parent_color);
#else
	ct_entry new_entry;
	read_entry_non_atomic(entry, &new_entry);
	entry_set_parent_color(&new_entry, parent_color);
	write_entry(entry, &new_entry);
#endif
}

int try_take_lock(ct_bucket* bucket) {
#ifndef MULTITHREADING
	UNUSED_PARAMETER(bucket);
	return 1;
#else
	assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);
	mt_debug_wait_for_access();
	uint8_t prev_val = __atomic_exchange_n(&(bucket->write_lock), 1, __ATOMIC_ACQ_REL);
	mt_debug_access_done();
	return (prev_val == 0);
#endif
}

ct_bucket_write_lock* find_write_lock(ct_lock_mgr* lock_mgr, ct_bucket* bucket) {
	ct_bucket_write_lock* lock;

	// Search backwards, as the lock we look for is usually the last one created
	for (lock = lock_mgr->next_write_lock - 1; lock >= &(lock_mgr->bucket_write_locks[0]); lock--) {
		if (lock->bucket == bucket)
			return lock;
	}
	return NULL;
}

uint64_t bucket_write_locked(ct_lock_mgr* lock_mgr, ct_bucket* bucket_num) {
#ifndef MULTITHREADING
	UNUSED_PARAMETER(lock_mgr);
	UNUSED_PARAMETER(bucket_num);
	return 1;
#else
	ct_bucket_write_lock* lock = find_write_lock(lock_mgr, bucket_num);
	return (lock != NULL);
#endif
}

void remove_lock(ct_lock_mgr* lock_mgr, ct_bucket_write_lock* lock) {
	// <lock> should belong to lock_mgr
	assert(lock >= lock_mgr->bucket_write_locks);
	assert(lock < lock_mgr->next_write_lock);

	ct_bucket* bucket = lock->bucket;
	ct_bucket_write_lock* last_lock = lock_mgr->next_write_lock - 1;

	if (lock != last_lock)
		*lock = *last_lock;
	lock_mgr->next_write_lock--;

	mt_debug_wait_for_access();
	__atomic_store_n(&(bucket->write_lock), 0, __ATOMIC_RELEASE);
	mt_debug_access_done();
}

void read_lock_bucket(ct_bucket* bucket, ct_bucket_read_lock* read_lock) {
#ifndef MULTITHREADING
	UNUSED_PARAMETER(bucket);
	UNUSED_PARAMETER(read_lock);
#else
	uint32_t write_lock_and_seq = __atomic_load_n(&(bucket->write_lock_and_seq), __ATOMIC_ACQUIRE);
	read_lock->bucket = bucket;

	// Validation of the read lock should succeed if the write-lock byte was changed,
	// as long as the sequence number is the same. Therefore, we mask out the write-lock
	// byte.
	read_lock->seq = write_lock_and_seq & (~0xFF);
#endif
}

// Succeeds if the bucket didn't change since it was locked, fails otherwise.
int read_unlock_bucket(ct_bucket_read_lock* read_lock) {
#ifndef MULTITHREADING
	UNUSED_PARAMETER(read_lock);
	return SI_OK;
#else
	uint32_t write_lock_and_seq = __atomic_load_n(&(read_lock->bucket->write_lock_and_seq), __ATOMIC_ACQUIRE);
	if ((write_lock_and_seq & (~0xFF)) == read_lock->seq)
		return SI_OK;
	return SI_FAIL;
#endif
}

// Register a bucket as locked by this thread. Assumes that the atomic operation
// of taking the lock was already done.
ct_bucket_write_lock* add_lock(ct_lock_mgr* lock_mgr, ct_bucket* bucket) {
	assert(lock_mgr->next_write_lock < &(lock_mgr->bucket_write_locks[MAX_LOCKS]));
	ct_bucket_write_lock* new_lock = lock_mgr->next_write_lock;
	lock_mgr->next_write_lock++;

	new_lock->bucket = bucket;
	new_lock->total_refcount = 1;
	memset(new_lock->entry_refcounts, 0, sizeof(new_lock->entry_refcounts));

	return new_lock;
}

// Same as write_lock_bucket when we're sure that this thread doesn't already hold
// a lock on the bucket (though it might be locked by another thread).
ct_bucket_write_lock* write_lock_unlocked_bucket(ct_lock_mgr* lock_mgr, ct_bucket* bucket) {
	assert(!find_write_lock(lock_mgr, bucket));

	int ok = try_take_lock(bucket);
	if (!ok)
		return NULL;

	return add_lock(lock_mgr, bucket);
}

ct_bucket_write_lock* write_lock_bucket(ct_lock_mgr* lock_mgr, ct_bucket* bucket) {
#ifndef MULTITHREADING
	UNUSED_PARAMETER(lock_mgr);
	UNUSED_PARAMETER(bucket);
	return (ct_bucket_write_lock*)1;
#else
	// The common case is that we try to lock a bucket that is not locked by any thread.
	// Only rarely we try locking a bucket that is already locked (by this thread or by
	// another). Therefore, we first try takign the bucket lock. Only if we fail, we check
	// whether it is held by this thread or another thread.

	int ok = try_take_lock(bucket);
	if (!ok) {
		// The bucket is already locked. Check if it is locked by this thread
		ct_bucket_write_lock* existing_lock = find_write_lock(lock_mgr, bucket);
		if (existing_lock) {
			// We already hold a write-lock in that bucket (on the whole bucket
			// or on a specific entry), just increment the refcount.
			assert(bucket->write_lock_and_seq & 1);
			existing_lock->total_refcount++;
			return existing_lock;
		} else {
			// The bucket is locked by another thread
			return NULL;
		}
	}

	// We took the bucket lock successfully
	return add_lock(lock_mgr, bucket);

#endif
}

int upgrade_bucket_lock(ct_lock_mgr* lock_mgr, ct_bucket_read_lock* read_lock) {
#ifndef MULTITHREADING
	UNUSED_PARAMETER(lock_mgr);
	UNUSED_PARAMETER(read_lock);
	return SI_OK;
#else
	ct_bucket_write_lock* existing_lock = find_write_lock(lock_mgr, read_lock->bucket);
	ct_bucket* bucket = read_lock->bucket;
	uint32_t write_lock_and_seq;
	uint32_t seq;
	int ok;
	if (existing_lock) {
		// The bucket is already write-locked by this thread. Verify that the sequence
		// didn't change

		write_lock_and_seq = __atomic_load_n(&(bucket->write_lock_and_seq), __ATOMIC_ACQUIRE);
		seq = write_lock_and_seq & (~0xFF);
		if (seq != read_lock->seq)
			return SI_RETRY;   // The bucket changed since we read-locked it

		existing_lock->total_refcount++;
		return SI_OK;
	}

	ct_bucket_write_lock* lock = write_lock_unlocked_bucket(lock_mgr, read_lock->bucket);
	if (!lock)
		return SI_RETRY;

	write_lock_and_seq = __atomic_load_n(&(bucket->write_lock_and_seq), __ATOMIC_ACQUIRE);
	seq = write_lock_and_seq & (~0xFF);
	if (seq != read_lock->seq) {
		release_bucket_lock(lock_mgr, read_lock->bucket);
		return SI_RETRY;
	}

	return SI_OK;
#endif
}

void release_bucket_lock(ct_lock_mgr* lock_mgr, ct_bucket* bucket) {
#ifndef MULTITHREADING
	UNUSED_PARAMETER(lock_mgr);
	UNUSED_PARAMETER(bucket);
#else
	int i;

	ct_bucket_write_lock* lock = find_write_lock(lock_mgr, bucket);
	assert(lock);

	assert(lock->total_refcount != 0);
	lock->total_refcount--;
	if (lock->total_refcount != 0)
		return;

	remove_lock(lock_mgr, lock);
#endif
}

void write_lock_entry_in_locked_bucket(ct_lock_mgr* lock_mgr, ct_entry_storage* entry) {
#ifndef MULTITHREADING
	UNUSED_PARAMETER(lock_mgr);
	UNUSED_PARAMETER(entry);
#else
	ct_bucket* bucket = bucket_containing(entry);
	uint64_t entry_index = entry_index_in_bucket(entry);
	ct_bucket_write_lock* existing_lock = find_write_lock(lock_mgr, bucket);
	assert(existing_lock);

	existing_lock->total_refcount++;
	existing_lock->entry_refcounts[entry_index]++;
#endif
}

// If entry <src> is write-locked, release it and lock <dst> instead. Used to inform
// the lock_mgr of entry relocations
void move_entry_lock(ct_lock_mgr* lock_mgr, ct_entry_storage* dst, ct_entry_storage* src) {
#ifndef MULTITHREADING
	UNUSED_PARAMETER(lock_mgr);
	UNUSED_PARAMETER(dst);
	UNUSED_PARAMETER(src);
#else
	uint64_t src_entry_index = entry_index_in_bucket(src);
	uint64_t dst_entry_index = entry_index_in_bucket(dst);

	ct_bucket_write_lock* src_lock = find_write_lock(lock_mgr, bucket_containing(src));
	ct_bucket_write_lock* dst_lock = find_write_lock(lock_mgr, bucket_containing(dst));

	// source and destination buckets must be locked
	assert(src_lock);
	assert(dst_lock);

	if (src_lock->entry_refcounts[src_entry_index] == 0)
		return;   // <src> not locked

	src_lock->entry_refcounts[src_entry_index]--;
	src_lock->total_refcount--;
	dst_lock->entry_refcounts[dst_entry_index]++;
	dst_lock->total_refcount++;
#endif
}

uint32_t read_bucket_seq(ct_bucket* bucket) {
	uint8_t* lock_and_seq_ptr = (uint8_t*) &(bucket->write_lock_and_seq);
	uint16_t low_word = *((uint16_t*)(lock_and_seq_ptr+1));
	uint8_t high_byte = *(lock_and_seq_ptr+3);
	return (high_byte<<24)+(low_word<<8);
}

int upgrade_lock(ct_lock_mgr* lock_mgr, ct_entry_local_copy* entry) {
#ifndef MULTITHREADING
	UNUSED_PARAMETER(lock_mgr);
	UNUSED_PARAMETER(entry);
	return SI_OK;
#else
	int ok;
	ct_bucket* bucket = bucket_containing(entry->last_pos);
	uint64_t entry_index = entry_index_in_bucket(entry->last_pos);
	uint32_t entry_seq = (entry->last_seq) & (~0xFF);
	uint32_t bucket_seq;

	ok = try_take_lock(bucket);
	if (ok) {
		// We succeeded in locking the bucket, meaning that it was not locked by this
		// thread (or another one).
		ct_bucket_write_lock* new_lock = add_lock(lock_mgr, bucket);

		bucket_seq = read_bucket_seq(bucket);
		assert(bucket_seq == ((bucket->write_lock_and_seq) & (~0xFF)));
		if (bucket_seq != entry_seq) {
			release_bucket_lock(lock_mgr, bucket);
			return SI_RETRY;
		}

		// We decrement the bucket refcount (incremented in write_lock_bucket) and increment an
		// entry refcount, so the total refcount doesn't have to be changed
		new_lock->entry_refcounts[entry_index]++;
		return SI_OK;
	}

	// We failed to take the lock, so the bucket was already locked. Check if it was locked
	// by this thread.
	ct_bucket_write_lock* existing_lock = find_write_lock(lock_mgr, bucket);
	if (existing_lock) {
		bucket_seq = (bucket->write_lock_and_seq) & (~0xFF);

		if (bucket_seq != entry_seq)
			return SI_RETRY;   // The bucket changed since the entry was read

		existing_lock->entry_refcounts[entry_index]++;
		existing_lock->total_refcount++;
		return SI_OK;
	}

	return SI_RETRY;
#endif
}

void write_unlock(ct_lock_mgr* lock_mgr, ct_entry_storage* entry) {
#ifndef MULTITHREADING
	UNUSED_PARAMETER(lock_mgr);
	UNUSED_PARAMETER(entry);
#else
	ct_bucket* bucket = bucket_containing(entry);
	uint64_t entry_index = entry_index_in_bucket(entry);

	ct_bucket_write_lock* lock = find_write_lock(lock_mgr, bucket);
	assert(lock);

	assert(lock->entry_refcounts[entry_index] != 0);
	lock->entry_refcounts[entry_index]--;
	lock->total_refcount--;
	if (lock->total_refcount != 0)
		return;

	remove_lock(lock_mgr, lock);
#endif
}

void release_all_locks(ct_lock_mgr* lock_mgr) {
#ifndef MULTITHREADING
	UNUSED_PARAMETER(lock_mgr);
#else
	ct_bucket_write_lock* lock = &(lock_mgr->bucket_write_locks[0]);

	for (;lock < lock_mgr->next_write_lock;lock++) {
		ct_bucket* bucket = lock->bucket;

		mt_debug_wait_for_access();
		__atomic_store_n(&(bucket->write_lock), 0, __ATOMIC_RELEASE);
		mt_debug_access_done();
	}
	lock_mgr->next_write_lock = &(lock_mgr->bucket_write_locks[0]);
#endif
}
