# HangOver

Basic fuzzing for `malloc()` (hangovers lead to fuzzy memories...). Linux only for now. Relies on AFL. We recommend using [AFL++](https://github.com/AFLplusplus/AFLplusplus).

## building

    make PATH_TO_MALLOC=/path/to/malloclib MALLOC_LIBRARY=yourmalloc

## running the fuzzer

    export LD_LIBRARY_PATH=/path/to/malloclib
    make fuzz

## how it works

HangOver uses a randomly-generated stream produced by AFL; the first four bytes are interpreted as the seed of a pseudo-random number generator so that crashes are deterministically reproducible. The rest of the stream should consist of the following three characters:

* **M** means `malloc` a randomly-sized object (based on the PRNG initialized above), which it fills with known characters
* **F** means `free` a victim chosen randomly from among all currently allocated objects
* **R** means `realloc` a victim chosen randomly from the currently allocated objects to a randomly-chosen new size
