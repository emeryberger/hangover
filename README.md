# HangOver

Basic fuzzing for `malloc()` (hangovers lead to fuzzy memories...). Linux only for now. Relies on AFL.

## building

    make PATH_TO_MALLOC=/path/to/malloclib MALLOC_LIBRARY=yourmalloc

## running the fuzzer

    export LD_LIBRARY_PATH=/path/to/malloclib
    make fuzz

