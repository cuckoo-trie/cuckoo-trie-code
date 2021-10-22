#include <stdint.h>
#include <string.h>

// Defines the ct_key struct and associated functions
// These definitions are split to a separate file
// to allow for easy replacement of the key representation.

typedef struct {
	int key_size;
	int value_size;
	uint8_t bytes[];
} ct_kv;

static uint64_t kv_required_size(uint64_t key_len, uint64_t value_len) {
    return sizeof(ct_kv) + key_len + value_len;
}

static uint64_t kv_size(ct_kv* kv) {
    return sizeof(ct_kv) + kv->key_size + kv->value_size;
}

static void kv_init(ct_kv* kv, uint64_t key_len, uint64_t value_len) {
    kv->key_size = key_len;
    kv->value_size = value_len;
}

static uint64_t kv_key_size(ct_kv* kv) {
    return kv->key_size;
}

static uint8_t* kv_key_bytes(ct_kv* kv) {
    return kv->bytes;
}

static uint64_t kv_value_size(ct_kv* kv) {
    return kv->value_size;
}

static uint8_t* kv_value_bytes(ct_kv* kv) {
    return kv->bytes + kv->key_size;
}

static int kv_key_compare_to(ct_kv* kv, uint64_t size, uint8_t* bytes) {
    uint64_t min_size;
    int result;

    if (kv->key_size < size)
        min_size = kv->key_size;
    else
        min_size = size;

    result = memcmp(kv->bytes, bytes, min_size);
    if (result != 0)
        return result;

    // If one key is prefix of the other, the shorter key is smaller
    return kv->key_size - size;
}

static int kv_key_compare(ct_kv* k1, ct_kv* k2) {
    return kv_key_compare_to(k1, kv_key_size(k2), kv_key_bytes(k2));
}
