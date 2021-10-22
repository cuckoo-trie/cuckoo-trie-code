#include <assert.h>

#define HUGEPAGE_LOG_SIZE 21
#define HUGEPAGE_SIZE (1 << HUGEPAGE_LOG_SIZE)

typedef struct {
	uint8_t* ptr;
	uint64_t size;
	uint64_t pos;
} dynamic_buffer_t;

static inline void copy_as_qwords(void* to, void* from, uint64_t size) {
	assert(size % sizeof(uint64_t) == 0);

	uint64_t i;
	uint64_t* to_qwords = (uint64_t*) to;

	// Mark from_qwords as volatile to force GCC to read it as QWORDs. Otherwise,
	// GCC might combine adjacent reads into 128-bit moves.
	volatile uint64_t* from_qwords = (uint64_t*) from;

	for (i = 0;i < size / sizeof(uint64_t);i++)
		to_qwords[i] = from_qwords[i];

}

void debug_log(const char* format, ...);
int extract_bits(uint8_t* bitstring, uint64_t start_bit, int num_bits);
void put_bits(uint8_t* bitstring, uint64_t start_bit, uint64_t num_bits, uint32_t bits);
void copy_bits(uint8_t* dest, uint8_t* src, uint64_t src_offset, uint64_t num_bits);
int get_bit(uint8_t* bitstring, uint64_t bit);
void set_bit(uint8_t* bitstring, uint64_t bit, int value);
int last_bit_before(uint8_t* bitstring, int end);
void* mmap_hugepage(size_t size);
void dynamic_buffer_init(dynamic_buffer_t* buf);
uint64_t dynamic_buffer_extend(dynamic_buffer_t* buf, uint64_t data_size);
