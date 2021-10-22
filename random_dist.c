#include <math.h>
#include <assert.h>
#include <stdio.h>
#include "random.h"

#define ZIPF_ERROR_RATIO 1.01

double rand_double() {
	return ((double)rand_uint64()) / UINT64_MAX;
}

void rand_uniform_init(rand_distribution* dist, uint64_t max) {
	dist->max = max;
	dist->type = DIST_UNIFORM;
}

rand_distribution zipf_dist_cache = {.max = -1};

void rand_zipf_init(rand_distribution* dist, uint64_t max, double skew) {
	uint64_t i;
	double total_weight = 0.0;
	uint64_t range_start = 0;
	uint64_t range_end;
	uint64_t range_num = 0;

	if (max == zipf_dist_cache.max && skew == zipf_dist_cache.skew) {
		*dist = zipf_dist_cache;
		return;
	}

	// A multiplier M s.t. the ratio between the weights of the k'th element
	// and the (k*M)'th element is at most ZIPF_ERROR_RATIO
	double range_size_multiplier = pow(ZIPF_ERROR_RATIO, 1.0 / skew);

	while (range_start < max) {
		zipf_range* range = &(dist->zipf_ranges[range_num]);
		range->start = range_start;
		range_end = (uint64_t) floor((range->start + 1) * range_size_multiplier);
		range->size = range_end - range->start;
		if (range->start + range->size > max)
			range->size = max - range->start;
		for (i = 0;i < range->size;i++)
			total_weight += 1.0 / pow(i + range->start + 1, skew);

		range->weight_cumsum = total_weight;

		// Compute start point of the next range
		range_start = range->start + range->size;
		range_num++;
	}

	dist->num_zipf_ranges = range_num;
	dist->total_weight = total_weight;
	dist->max = max;
	dist->type = DIST_ZIPF;
	dist->skew = skew;

	zipf_dist_cache = *dist;
}

void rand_zipf_rank_init(rand_distribution* dist, uint64_t max, double skew) {
	rand_zipf_init(dist, max, skew);
	dist->type = DIST_ZIPF_RANK;
}

uint64_t mix(uint64_t x) {
	x ^= x >> 33;
	x *= 0xC2B2AE3D27D4EB4FULL;  // Random prime
	x ^= x >> 29;
	x *= 0x165667B19E3779F9ULL;  // Random prime
	x ^= x >> 32;
	return x;
}

uint64_t rand_dist(rand_distribution* dist) {
	uint64_t low, high;
	uint64_t range_num;

	if (dist->type == DIST_UNIFORM)
		return rand_uint64() % dist->max;

	// Generate Zipf-distributed random
	double x = rand_double() * dist->total_weight;

	// Find which range contains x
	low = 0;
	high = dist->num_zipf_ranges;
	while (1) {
		if (high - low <= 1) {
			range_num = low;
			break;
		}
		uint64_t mid = (low + high) / 2 - 1;
		if (x < dist->zipf_ranges[mid].weight_cumsum) {
			high = mid + 1;
		} else {
			low = mid + 1;
		}
	}

	// This range contains x. Choose a random value in the range.
	zipf_range* range = &(dist->zipf_ranges[range_num]);
	uint64_t zipf_rand = (rand_uint64() % range->size) + range->start;

	if (dist->type == DIST_ZIPF) {
		// Permute the output. Otherwise, all common values will be near one another
		assert(dist->max > 1000);  // When <max> is small, collisions change the distribution considerably.
		return mix(zipf_rand) % dist->max;
	} else {
		assert(dist->type == DIST_ZIPF_RANK);
		return zipf_rand;
	}
}