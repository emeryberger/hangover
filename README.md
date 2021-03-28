# HangOver

Basic fuzzing for `malloc()` (hangovers lead to fuzzy memories...). Linux only for now. Relies on AFL. We recommend using [AFL++](https://github.com/AFLplusplus/AFLplusplus).

## building

    make PATH_TO_MALLOC=/path/to/malloclib MALLOC_LIBRARY=yourmalloc

## running the fuzzer

    export LD_LIBRARY_PATH=/path/to/malloclib
    make fuzz

## how it works

HangOver operates on a randomly-generated stream produced by AFL.

Here's an example legal input: `1234MMMFFFMFAMMMFFFFFF`.

HangOver interprets the first four bytes as the seed of a pseudo-random number generator, making crashing inputs deterministically reproducible (HangOver currently is single-threaded only). The rest of the stream consists of a sequence containing the following characters:

* **M** = `malloc` a randomly-sized object (based on the PRNG initialized above), fill with known characters, and mark as allocated
* **F** = `free` a victim chosen randomly from among all currently allocated objects, mark as deallocated
* **R** = `realloc` a victim chosen randomly from the currently allocated objects to a randomly-chosen new size
* **A** = `memalign` a randomly-sized object aligned to a randomly chosen power of two

HangOver checks every allocated object for correct alignment. It also ensures that allocated objects are unique and non-overlapping. By design, HangOver should never crash when running a correctly-implemented and standards-compliant allocator.

So far, we have been using HangOver during allocator development and testing.

Anecdotally, we have demonstrated HangOver's effectiveness by identifying and resolving problems in a `malloc` implementation described in [this tutorial by Dan Luu](https://danluu.com/malloc-tutorial/) (code in the `test` directory).
