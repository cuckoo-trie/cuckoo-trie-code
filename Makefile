LIB_SOURCES=main.c util.c verify_trie.c random.c atomics.c mt_debug.c
LIB_DEPS=${LIB_SOURCES} atomics.h config.h cuckoo_trie.h main.h util.h \
					key_object.h cuckoo_trie_internal.h random.h mt_debug.h
TEST_SOURCES=test.c random.c dataset.c util.c
TEST_DEPS=${TEST_SOURCES} cuckoo_trie.h random.h key_object.h dataset.h util.h
BENCHMARK_SOURCES=benchmark.c random.c dataset.c util.c random_dist.c
BENCHMARK_DEPS=${BENCHMARK_SOURCES} random.h cuckoo_trie.h dataset.h cuckoo_trie_internal.h util.h
BINARIES=libcuckoo_trie.so libcuckoo_trie_debug.so test test_debug benchmark

# Without -fvisibility=hidden gcc assumes that all functions are exported and usually
# won't inline them
OPTIMIZE_FLAGS=-O3 -fvisibility=hidden -flto -fno-strict-aliasing

# Add -march=haswell to enable the bextr_u32 builtin
FLAGS=-march=haswell -Wreturn-type -Wuninitialized -Wunused-parameter

CC ?= gcc

all: ${BINARIES}

clean:
	rm ${BINARIES}

libcuckoo_trie.so: Makefile ${LIB_DEPS}
	${CC} ${FLAGS} ${OPTIMIZE_FLAGS} -fPIC -shared -march=haswell -DNDEBUG -o $@ ${LIB_SOURCES}

libcuckoo_trie_debug.so: Makefile ${LIB_DEPS}
	${CC} ${FLAGS} -O1 -fPIC -shared -march=haswell -g -o $@ ${LIB_SOURCES}

test: Makefile ${TEST_DEPS}
	${CC} ${FLAGS} ${OPTIMIZE_FLAGS} -Wl,-rpath=. -o $@ ${TEST_SOURCES} libcuckoo_trie.so -lpthread

test_debug: Makefile ${TEST_DEPS}
	${CC} ${FLAGS} -Wl,-rpath=. -g -DTEST_DEBUG -o $@ ${TEST_SOURCES} libcuckoo_trie_debug.so -lpthread

benchmark: Makefile ${BENCHMARK_DEPS}
	${CC} ${FLAGS} ${OPTIMIZE_FLAGS} -Wl,-rpath=. -o $@ ${BENCHMARK_SOURCES} libcuckoo_trie.so -lpthread -lm