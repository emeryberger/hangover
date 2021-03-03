PATH_TO_MALLOC=/home/emery/git/DieHard/src
MALLOC_LIBRARY=diehard

fuzzymemory: fuzzymemory.cpp
	afl-clang-fast++ -std=c++14 -O3 -L$(PATH_TO_MALLOC) -l$(MALLOC_LIBRARY) fuzzymemory.cpp -o fuzzymemory

fuzz: fuzzymemory
	afl-fuzz -m 131072 -t 100 -x dictionary/malloc.dict -i afl_in -o afl_out ./fuzzymemory

clean:
	rm -f fuzzymemory
