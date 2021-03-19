#PATH_TO_MALLOC=
#MALLOC_LIBRARY=

#PATH_TO_MALLOC=-L$(HOME)/git/Hoard/src
#MALLOC_LIBRARY=-lhoard

#PATH_TO_MALLOC=-L$(HOME)/git/Hoard/mimalloc/build
#MALLOC_LIBRARY=-lmimalloc

#PATH_TO_MALLOC=-L$(HOME)/git/DieHard/src
#MALLOC_LIBRARY=-ldiehard

#PATH_TO_MALLOC=-L$(HOME)/git/Guarder
#MALLOC_LIBRARY=-lguarder

PATH_TO_MALLOC=-L$(HOME)/git/mesh/build/lib
MALLOC_LIBRARY=-lmesh

CXX = afl-c++

hangover: hangover.cpp
	$(CXX) -std=c++14 -O3 -g $(PATH_TO_MALLOC) $(MALLOC_LIBRARY) $^ -o $@

fuzz: hangover
	afl-fuzz -m 180000 -t 100 -x dictionary/malloc.dict -i afl_in -o afl_out ./hangover

clean:
	rm -f hangover
