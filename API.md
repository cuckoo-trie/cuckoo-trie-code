# Cuckoo Trie API

To use the following functions, include cuckoo_trie.h in your project, and link with libcuckoo_trie.so

## Key-value (`ct_kv`) objects

```c
typedef struct {
	int key_size;
	int value_size;
	uint8_t bytes[];
} ct_kv;
```

A `ct_kv` represents a key-value pair to be inserted into the trie. `key_size` and `value_size` are the sizes of the key and the value, respectively, in bytes. `bytes` is the concatenation of the key and the value. There is no padding of the key or the value and no separator between them.

## Allocation and freeing

### `cuckoo_trie* ct_alloc(uint64_t num_cells)`

Allocate a Cuckoo Trie with at least `num_cells` hashtable cells and return a pointer to it. The actual number of cells might be somewhat higher.

Automatic resizing isn't implemented - once the trie is allocated its size remains fixed. If it becomes full, no further operations are possible. As a rule of thumb, N keys need around 1.5N-2N cells.

### `void ct_free(cuckoo_trie* trie)`

Free a Cuckoo Trie previously allocated by `ct_alloc`.

## Point operations

The Cuckoo Trie allows to insert and search key-value pairs. The current implementation doesn't suppport deletion.

### `int ct_insert(cuckoo_trie* trie, ct_kv* kv)`

Insert the key-value par `kv` into the trie `trie`. Abort if the key already exists.

When a key-value pair is inserted into the trie, its contents aren't copied. Rather, the trie stores a pointer to `kv`. Therefore, `kv` should not be freed or modified after the insertion.

Return value:
- `S_OK`: The insertion was successful.
- `S_ALREADYIN`: The trie already contains the given key.
- `S_OVERFLOW`: The trie is full. The results of further operations (except `ct_free`) are undefined.
- `S_KEYTOOLONG`: The key has more than `MAX_KEY_BYTES` bytes.

### `int ct_update(cuckoo_trie* trie, ct_kv* kv)`

Update the value of the given key, assumed to already be present in the trie.

Return value:
- `S_OK`: The update was successful.
- `S_NOTFOUND`: The key is not in the trie.

### `int ct_upsert(cuckoo_trie* trie, ct_kv* kv, int* created_new)`

Insert the key-value par `kv` into the trie `trie`. If the key is already present, update its value. `created_new` is set to 0 if the key was laready present and to 1 otherwise.

Return value:
- `S_OK`: The insertion was successful.
- `S_OVERFLOW`: The trie is full. The results of further operations (except `ct_free`) are undefined.
- `S_KEYTOOLONG`: The key has more than `MAX_KEY_BYTES` bytes.

### `ct_kv* ct_lookup(cuckoo_trie* trie, uint64_t key_size, uint8_t* key_bytes)`

Search the given key in the trie `trie`. Returns a pointer to the key-value pair, or `NULL` if the key was not found.

## Iteration

Iteration allows to retrieve all key-value pairs with keys in a certain interval, sorted in lexicographic order.

To perform iteration, allocate an iterator, set it to the start of the interval, and advance it until the end of the interval is reached. Multiple threads can iterate the trie simultaneously, but each must use a separate iterator.

### `ct_iter* ct_iter_alloc(cuckoo_trie* trie)`

Create an iterator that iterates over keys in `trie` in lexicographical order. `ct_iter_goto` must be called before retrieving keys from the iterator.

### `void ct_iter_goto(ct_iter* iter, uint64_t key_size, uint8_t* key_bytes)`

Set the iterator `iter` to the smallest key in the trie that is equal or larger than the given key. An iterator can be set multiple times after it was allocated, even after `ct_iter_next` was called.

### `ct_kv* ct_iter_next(ct_iter* iter)`

Return the next key from the iterator, or `NULL` if the maximal key was already returned.