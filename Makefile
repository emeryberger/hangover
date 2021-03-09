#PATH_TO_MALLOC=
#MALLOC_LIBRARY=

#PATH_TO_MALLOC=-L/home/emery/git/Hoard/src
#MALLOC_LIBRARY=-lhoard

#PATH_TO_MALLOC=-L/home/emery/git/Hoard/mimalloc/build
#MALLOC_LIBRARY=-lmimalloc

#PATH_TO_MALLOC=-L/home/emery/git/DieHard/src
#MALLOC_LIBRARY=-ldiehard

PATH_TO_MALLOC=-L/home/emery/git/Guarder
MALLOC_LIBRARY=-lguarder

CXX = afl-c++

hangover: hangover.cpp
	$(CXX) -std=c++14 -O0 -g $(PATH_TO_MALLOC) $(MALLOC_LIBRARY) hangover.cpp -o hangover

fuzz: hangover
	afl-fuzz -m 18000000 -t 100 -x dictionary/malloc.dict -i afl_in -o afl_out ./hangover

clean:
	rm -f hangover
