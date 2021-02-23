PATH_TO_MALLOC=/home/emery/git/DieHard/src
MALLOC_LIBRARY=diehard

fuzzymemory:
	afl-clang-fast++ -O3 -L$(PATH_TO_MALLOC) -l$(MALLOC_LIBRARY) fuzzymemory.cpp -o fuzzymemory

fuzz: fuzzymemory
	afl-fuzz -m 2048 -t 100 -x dictionary/malloc.dict -i afl_in -o afl_out ./fuzzymemory

clean:
	rm -f fuzzymemory
