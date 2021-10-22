#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>

#include "util.h"
#include "compiler.h"
#include "cuckoo_trie_internal.h"

// Various self-contained utility functions

static int debug_enabled = 0;

void ct_enable_debug_logs() {
	debug_enabled = 1;
}

#ifndef NDEBUG
void debug_log(const char* format, ...) {
	va_list args;
	va_start(args, format);
	if (debug_enabled) {
		printf("%lu ", pthread_self());
		vprintf(format, args);
	}
	va_end(args);
}
#else
void debug_log(const char* format, ...) {
	UNUSED_PARAMETER(format);
}
#endif

// start_bit = 0 means MSB of first byte
int extract_bits(uint8_t* bitstring, uint64_t start_bit, int num_bits) {
	assert(num_bits <= 24);  // The bits must be contained in a DWORD that starts on a byte boundary

	// Find a DWORD that contains all requested bits, but doesn't contain any byte
	// after them (otherwise we'll cause a cache miss if the bytes are at the end
	// of a cache line). We assume that the bitstring is at least 32 bits long.
	uint64_t last_bit = start_bit + num_bits - 1;
	int64_t dword_start_byte = last_bit / 8 - 3;
	if (dword_start_byte < 0)
		dword_start_byte = 0;
	uint32_t* containing_dword_ptr = (uint32_t*)(&bitstring[dword_start_byte]);

	// Read the DWORD and extract the bits
	uint32_t containing_dword = *containing_dword_ptr;
	containing_dword = __builtin_bswap32(containing_dword); // The word is read from memory in little-endian. Make the read big-endian.
	uint32_t offset = 32 - start_bit + (dword_start_byte * 8) - num_bits;
	return __builtin_ia32_bextr_u32(containing_dword, (num_bits << 8) + offset);
}

void put_bits(uint8_t* bitstring, uint64_t start_bit, uint64_t num_bits, uint32_t bits) {
	assert(num_bits <= 24);
	uint64_t last_bit = start_bit + num_bits - 1;
	int64_t dword_start_byte = last_bit / 8 - 3;
	if (dword_start_byte < 0)
		dword_start_byte = 0;
	uint32_t* containing_dword_ptr = (uint32_t*)(&bitstring[dword_start_byte]);
	uint32_t containing_dword = *containing_dword_ptr;
	containing_dword = __builtin_bswap32(containing_dword); // The word is read from memory in little-endian. Make the read big-endian.

	uint32_t offset = 32 - start_bit + (dword_start_byte * 8) - num_bits;
	uint32_t mask = ((1 << num_bits) - 1) << offset;
	containing_dword = containing_dword & (~mask);
	containing_dword = containing_dword | (bits << offset);

	containing_dword = __builtin_bswap32(containing_dword); // Swap again, as the write is little-endian too.
	*containing_dword_ptr = containing_dword;

	assert(extract_bits(bitstring, start_bit, num_bits) == bits);
}

void copy_bits(uint8_t* dest, uint8_t* src, uint64_t src_offset, uint64_t num_bits) {
	uint64_t pos = 0;
	uint8_t* dst_pos = dest;

	while (pos <= num_bits) {
		*dst_pos = extract_bits(src, src_offset + pos, 8);
		pos += 8;
		dst_pos++;
	}

	if (pos < num_bits) {
		uint64_t bits_left = num_bits - pos;
		*dst_pos = extract_bits(src, src_offset + pos, bits_left) << (8 - bits_left);
	}
}

int get_bit(uint8_t* bitstring, uint64_t bit) {
	uint64_t byte = bit / 8;
	return ((bitstring[byte] << (bit % 8)) & 0x80) != 0;
}

void set_bit(uint8_t* bitstring, uint64_t bit, int value) {
	assert((value == 0) || (value == 1));
	uint8_t mask = 0x80 >> (bit % 8);
	uint64_t byte = bit / 8;
	bitstring[byte] &= ~mask;
	bitstring[byte] |= mask * value;
}

int last_bit_before(uint8_t* bitstring, int end) {
	// We only read 64 bits, and if <end> is 64 the right shift that produces the mask will
	// be undefined (shifting a 64-bit value by 64 places is undefined)
	assert(end < 64);

	uint64_t bitstring_value = __builtin_bswap64(*((uint64_t*)bitstring));
	uint64_t mask = ((uint64_t)(-1ULL)) >> end;   // marks the uninteresting bits
	bitstring_value = bitstring_value & (~mask);

	if (bitstring_value == 0)
		return -1;

	return 63 - __builtin_ctzll(bitstring_value);
}

void* mmap_hugepage(size_t size) {
	void* result;
	result = mmap(0, size, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | (HUGEPAGE_LOG_SIZE << MAP_HUGE_SHIFT),
				  -1, 0);
	if (result == NULL) {
		printf("Very strange - we got the memory at address 0 from mmap\n");
		return NULL;
	}
	if (result == MAP_FAILED) {
		printf("Failed to allocate %lu bytes in 2048kB huge-pages. Do you have enough free huge-pages?\n", size);
		return NULL;
	}
	return result;
}


void dynamic_buffer_init(dynamic_buffer_t* buf) {
	buf->size = 1024;
	buf->ptr = malloc(buf->size);
	buf->pos = 0;
}

uint64_t dynamic_buffer_extend(dynamic_buffer_t* buf, uint64_t data_size) {
	uint64_t old_pos = buf->pos;
	if (buf->pos + data_size > buf->size) {
		buf->size = buf->size * 2 + data_size;
		buf->ptr = realloc(buf->ptr, buf->size);
	}
	buf->pos += data_size;
	return old_pos;
}
