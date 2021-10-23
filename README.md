# The Cuckoo Trie

The Cuckoo Trie is an efficient in-memory ordered index. It achieves high performance by utilising memory-level parallelism - the ability of modern processors to perfrom multiple memory accesses in parallel. This repository contains the implementation of the Cuckoo Trie index used in our paper.

If you use the Cuckoo Trie, please cite our paper: **Cuckoo Trie: Exploiting Memory-Level Parallelism for Efficient DRAM Indexing.** Adar Zeitak, Adam Morrison. *Proceedings of the 28th ACM Symposium on Operating Systems Principles (SOSP '21)*.

The code for the other indexes the Cuckoo Trie was benchmarked against can be found [here](https://github.com/cuckoo-trie/other-benchmarked-indexes).

The Cuckoo Trie is implemented as a library, `libcuckoo_trie`. The API for the library is described in API.md. In addition, this repository contains tools to benchmark and test the library.

This implementation was created to run the experiments in the paper. Features that were not required to run the experiments may be missing or buggy. It is not robust enough to be used as an index in your program.

## Building

The Cuckoo Trie only supports Linux systems with x86_64 processors.

To build everything, run `make` in the root of the cloned repository. By default, a thread-safe version is built. To build a faster, non-thread-safe version, comment out `#define MULTITHREADING` from `config.h`.

The build produces several files:
- `libcuckoo_trie.so`: A dynamic library implementing the Cuckoo Trie (interface described in `API.md`).
- `benchmark`: Allows to run various benchmarks with the Cuckoo Trie.
- `test`: Performs basic tests on the Cuckoo Trie. Useful if you change the code.

The library and the testing tool have `_debug` versions. These are compiled with a lower optimization level and assertions enabled to allow for easier debugging, but are significantly slower.

## Running

The Cuckoo Trie requires 2MB huge pages to store the hash table.

On single-processor systems, you can allocate 1000 huge pages (2GB) with

```sh
sudo sh -c "echo 1000 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
```

On multiple-processor systems, use the following to distribute the huge pages equally between the NUMA nodes:

```sh
sudo numactl --interleave=all sh -c "echo 1000 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hug
epages_mempolicy"
```

View the number of huge pages on each node with

```sh
cat /sys/devices/system/node/node[node_num]/hugepages/hugepages-2048kB/nr_hugepages
```

## Benchmarking tool (`benchmark`)

### Achieving high performance

The performance of the Cuckoo Trie is sensitive to many factors. Achieving high and consistent throughput (similar to the results in the paper), requires:
- **A memory allocator that uses huge pages**: The benchmarking tool uses `malloc` to allocate memory for the keys to be inserted to the Cuckoo Trie. The default `malloc` from glibc doesn't place the keys in huge pages, resulting in lower throughputs. `benchmark` should be run with another memory allocator that uses huge pages. See below on how to do that with `jemalloc`.
- **A recent processor and compiler**: The Cuckoo Trie was optimized for recent Intel processors (Broadwell/Skylake microarchitectures), and GCC 7.5.0.
- **Turning off Turbo-Boost**: Intel processors have a feature called Turbo-Boost, that raises the clock frequency when only few cores are active. This is misleading when comparing single-core and multi-core results.
- **Using NUMA interleaving**: If the system has multiple NUMA nodes, memory allocations should be interleaved between the nodes. This can be done by running the benchmark with `numactl --interleave=all`. Note that all nodes should have the same number of huge pages allocated for this to work.

The following is an example commandline that uses `numactl` and the `jemalloc` allocator to run the benchmarking tool:
```sh
numactl --interleave=all env LD_PRELOAD=path/to/libjemalloc.so MALLOC_CONF=thp:always ./benchmark insert rand-8
```

**Note**: `jemalloc` relies on the Transparent Huge Pages (THP) mechanism in Linux to allocate huge pages, and THP silently falls back to regular pages if no huge pages are available. Check that the counter `thp_fault_fallback` in `/proc/vmstat` is not incremented when running the benchmark to rule out this possibility.

### Usage

```sh
./benchmark [flags] BENCHMARK DATASET
```

Where `BENCHMARK` is one of the available benchmark types and `DATASET` is the path of the file containing the dataset to be used. The special name `rand-<k>` specifies a dataset of 10M random `k`-byte keys.

Most benchmarks have a single-threaded and a multi-threaded version (named `mt-*`). The single-threaded version ignores the `--threads` flag. The available benchmark types are:
- `insert`, `mt-insert`: Insert all keys into the trie.
- `pos-lookup`, `mt-pos-lookup`: Perform positive lookups for random keys. Positive lookups are ones that succeed (that is, ask for keys that are present in the trie).
- `mem-usage`: Find the smallest hash table size for the Cuckoo Trie that is enough to store the given dataset.
- `ycsb-a`, `ycsb-b`, ... `ycsb-f`, `mt-ycsb-a`, ..., `mt-ycsb-f`: Run the appropriate mix of insert and lookup operations from the [YCSB](https://github.com/brianfrankcooper/YCSB/wiki/Core-Workloads) benchmark suite. By default, this runs the benchmark with a Zipfian query distribution, specify `--ycsb-uniform-dist` to use a uniform distribution instead.

The following flags can be used with each benchmark:
- `--threads <N>` (`mt-*` only): use `N` threads. Each thread is bound to a different core. The default is to use 4 threads.
- `--dataset-size <N>` (`pos-lookup` and `mem-usage` only): Use only the first `N` keys of the dataset.
- `--trie-cells <N>`: Set the hash table size to `N` cells. The default is 2.5 times the number of keys in the dataset.
- `--ycsb-uniform-dist` (`ycsb-*` and `mt-ycsb-*` only): Run YCSB benchmarks with a uniform query distribution. The default is Zipfian distribution.

### Dataset file format

The dataset files used with `benchmark` are binary files with the following format:
- `Number of keys`: a 64-bit little-endian number.
- `Total size of all keys`: a 64-bit little-endian number. This number does not include the size that precedes each key.
- `Keys`: Each key is encoded as a 32-bit little-endian length `L`, followed by `L` key bytes. The keys are not NULL-terminated.

## Test tool (`test`)

Usage:

```sh
./test [flags] TEST
./test_debug [flags] TEST
```

Runs the test `TEST` on `libcuckoo_trie`. If no errors are printed - the test succeeded.

`test` tests `libcuckoo_trie.so` and `test_debug` tests `libcuckoo_trie_debug.so`. It is recommended to run `test_debug`, as it can detect bugs that only cause assertion failures (assertions are turned off in `libcuckoo_trie.so`).

When running multithreaded tests, `test_debug` makes the order in which the threads access the trie deterministic, to make concurrency bugs more repeatable.

The available tests are:
- `insert`: Insert random keys into a small trie until it is full. Check that the resulting trie is consistent.
- `iter`: Insert random keys into the trie. Then, place an iterator on a random key and iterate until reaching the maximal key. Verify that the keys returned from the iterator are correct.
- `mt-insert-lookup`: Run one thread that inserts keys and another thread that performs lookups for these keys. The lookup thread tries to search for keys whose insertion is currently in progress to trigger concurrency bugs.
- `mt-insert-scan`: Run one thread that inserts keys and another thread that repeatedly iterates through all keys in the trie. Verify that the keys returned from the iterator are correct.
- `mt-insert-succ`: Run one thread that inserts keys and another thread that repeatedly requests the successor of random keys. Verify the values returned.
- `mt-insert`: Insert a small random dataset using 8 threads (each inserting one eighth of the keys). Check that the resulting trie is consistent.

The following flags can be specified:
- `-s <N>`: Use `N` as the seed of the random number generator. Zero (the default) uses a random seed. When using a random seed, the seed is printed to allow repeating a failed test.
- `-v`: Makes some of the tests more verbose.
- `-vv` (`./test_debug` only): Like `-v`, but also turns on internal debugging prints in `libcuckoo_trie_debug.so`. Produces a *lot* of output.