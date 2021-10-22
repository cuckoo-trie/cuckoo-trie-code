#include <stdint.h>

#define MAX_ZIPF_RANGES 10000

// Sample a number in [0,max) with all numbers having equal probability.
#define DIST_UNIFORM 0

// Sample a number in [0,max) with unequal probabilities: the k'th most
// common number has probability proportional to 1 / (k**skew).
#define DIST_ZIPF 1

// Same as DIST_ZIPF, but with 0 being the most common number, 1 the
// second most common, and so on.
#define DIST_ZIPF_RANK 2

typedef struct {
	// The weight of all ranges up to and including this one
	double weight_cumsum;

	uint64_t start;
	uint64_t size;
} zipf_range;

typedef struct {
	zipf_range zipf_ranges[MAX_ZIPF_RANGES];
	uint64_t num_zipf_ranges;
	double total_weight;
	double skew;
	uint64_t max;
	int type;
} rand_distribution;

uint32_t rand_dword();
uint32_t rand_dword_r(uint64_t* state);
uint64_t rand_uint64();
float rand_float();
void rand_uniform_init(rand_distribution* dist, uint64_t max);
void rand_zipf_init(rand_distribution* dist, uint64_t max, double skew);
void rand_zipf_rank_init(rand_distribution* dist, uint64_t max, double skew);
uint64_t rand_dist(rand_distribution* dist);
void random_bytes(uint8_t* buf, int count);
void rand_seed(uint64_t s);
long int seed_from_time();
void seed_and_print();
