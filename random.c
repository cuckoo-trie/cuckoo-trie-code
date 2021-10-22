#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>

uint64_t rand_state = 1;

void rand_seed(uint64_t s) {
	rand_state = s;
}

uint32_t rand_dword() {
	rand_state = 6364136223846793005 * rand_state + 1;
	return rand_state >> 32;
}

uint32_t rand_dword_r(uint64_t* state) {
	*state = 6364136223846793005 * (*state) + 1;
	return *state >> 32;
}

uint64_t rand_uint64() {
	return (((uint64_t)rand_dword()) << 32) + rand_dword();
}

float rand_float() {
	return ((float)rand_dword()) / UINT32_MAX;
}

void random_bytes(uint8_t* buf, int count) {
	int i;
	for (i = 0;i < count;i++)
		buf[i] = rand_dword() % 256;
}

long int seed_from_time() {
	struct timeval now;
    long int seed;
	gettimeofday(&now, NULL);
	seed = now.tv_sec * 1000000 + now.tv_usec;
	rand_seed(seed);
	return seed;
}

void seed_and_print() {
	printf("Using seed %ld\n", seed_from_time());
}
