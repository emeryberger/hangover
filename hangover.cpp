#include <cassert>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <unistd.h>

#include <unordered_map>
#include <vector>

#include <malloc.h>

#ifndef HANGOVER_MALLOC
#define HANGOVER_MALLOC(x) ::malloc(x)
#define HANGOVER_FREE(x) ::free(x)
#define HANGOVER_REALLOC(x, s) ::realloc(x, s)
#endif

/**
   HangOver: a memory fuzzer for malloc implementations.
 */


// maximum size of allocated objects
constexpr size_t MAX_SIZE = 2048; // 256;

// all allocated objects
std::vector<void *> allocs;

// the words occupied by all allocated objects
std::unordered_map<unsigned long, bool> allocated_bytes;

// the sizes of all allocated objects (0 if freed)
std::unordered_map<void *, size_t> sizes;

#if 0
#define EXERCISE_UNDEFINED_BEHAVIOR 1
#else
#define EXERCISE_UNDEFINED_BEHAVIOR 0
#endif


#if 0
#define DEBUG_PRINT 1
#else
#define DEBUG_PRINT 0
#endif

void simulateMalloc() {
  // Random size up to MAX_SIZE bytes.
  size_t sz = rand() % MAX_SIZE;
  if (sz == 0) {
    sz = 8;
  }
  void * ptr = HANGOVER_MALLOC(sz);
  // We do not expect memory exhaustion during fuzzing, though it is of course legal!
  assert(ptr);
  sizes[ptr] = sz;
  // Check alignment.
  if (sz >= alignof(max_align_t)) {
    assert((uintptr_t) ptr % alignof(max_align_t) == 0);
  }
  // Make sure we aren't overlapping with any previous malloc'd
  // regions.
  for (auto ind = 0; ind < sz; ind++) {
    assert(!allocated_bytes[ind + (uintptr_t) ptr]);
    allocated_bytes[ind + (uintptr_t) ptr] = true;
  }
#if DEBUG_PRINT
  printf("MALLOC %ld = %p\n", sz, ptr);
#endif
  allocs.push_back(ptr);
  // Fill with a known value.
  for (auto ind = 0; ind < sz; ind++) {
    ((char *) ptr)[ind] = ('M' + ind + (uintptr_t) ptr) % 256;
  }
}

void simulateFree() {
  if (allocs.size() == 0) {
    exit(-1);
  }
  // Find a random victim to delete.
  auto victimIndex = rand() % allocs.size();
  auto ptr = allocs[victimIndex]; // .front();
#if DEBUG_PRINT
  printf("FREE %p\n", ptr);
#endif
  // Ensure size reported matches size requested.
  auto sz = sizes[ptr];
  printf("sz = %lu, malloc_usable_size = %lu\n", sz, malloc_usable_size(ptr));
  assert(malloc_usable_size(ptr) >= sz);
  // Check for the known value.
  for (auto ind = 0; ind < sz; ind++) {
    auto v = ('M' + ind + (uintptr_t) ptr) % 256;
    //    	  printf("free checking to see if ind %d = %d (it's actually %d)\n", ind, v, ((char *) ptr)[ind]);
    assert(((char *) ptr)[ind] == v);
    // Fill with garbage
    ((char *) ptr)[ind] = rand() % 256;
  }
  // Mark the bytes as no longer allocated.
  for (auto ind = 0; ind < sz ; ind++) {
    // printf("is %d allocated? should be.\n", ind);
    assert(allocated_bytes[ind + (uintptr_t) ptr ]);
    allocated_bytes[ind + (uintptr_t) ptr ] = false;
  }
  sizes[ptr] = 0;
  // allocs.pop_back();
  allocs.erase(allocs.begin() + victimIndex); // pop_front();
  HANGOVER_FREE(ptr);
#if EXERCISE_UNDEFINED_BEHAVIOR
  for (auto ind = 0; ind < sz; ind++) {
    // Fill with garbage
    ((char *) ptr)[ind] = rand() % 256;
  }
#endif
}

void simulateRealloc()
{
  if (allocs.size() == 0) {
    exit(-1);
  }
  // Find a random victim to realloc.
  auto victimIndex = rand() % allocs.size();
  auto ptr = allocs[victimIndex];
  // Ensure size reported matches size requested.
  auto sz = sizes[ptr];
  assert(sz != 0); // can't be freed already
  assert(malloc_usable_size(ptr) >= sz); // sizes must be in sync
  // Allocate the new chunk.
  auto newSize = rand() % MAX_SIZE;
  if (newSize == 0) {
    // It's a free. Mark as deallocated.
    for (auto ind = 0; ind < sz; ind++) {
      allocated_bytes[ind + (uintptr_t) ptr ] = false;
    }
    allocs.erase(allocs.begin() + victimIndex);
    sizes[ptr] = 0;
    return;
  }
  assert(ptr != nullptr);
  assert(newSize != 0);
  auto newPtr = HANGOVER_REALLOC(ptr, newSize);
  // Check AND reset the known value.
  auto minSize = ((sz < newSize) ? sz : newSize);
  for (auto ind = 0; ind < minSize; ind++) {
    //printf("accessing ind %d\n", ind);
    assert(((char *) newPtr)[ind] == ('M' + ind + (uintptr_t) ptr) % 256);
    ((char *) newPtr)[ind] = ('M' + ind + (uintptr_t) newPtr) % 256;
  }
  for (auto ind = minSize; ind < newSize; ind++) {
    auto v = ('M' + ind + (uintptr_t) newPtr) % 256;
    //	  printf("writing %d into ind %d\n", v, ind);
    ((char *) newPtr)[ind] = v;
  }
  for (auto ind = 0; ind < sz; ind++) {
    allocated_bytes[ind + (uintptr_t) ptr ] = false;
#if EXERCISE_UNDEFINED_BEHAVIOR
    // Overwrite with garbage (note: it's already been freed, so this is undefined).
    if (ptr != newPtr) {
      ((char *) ptr)[ind] = rand() % 256;
    }
#endif
  }
  for (auto ind = 0; ind < newSize ; ind++) {
    allocated_bytes[ind + (uintptr_t) newPtr ] = true;
  }
#if DEBUG_PRINT
  printf("REALLOC %lu -> %lu (%p -> %p)\n", sz, newSize, ptr, newPtr);
#endif
  sizes[newPtr] = newSize;
  // allocs.pop_back();
  if (ptr != newPtr) {
    sizes[ptr] = 0;
    allocs.erase(allocs.begin() + victimIndex);
    allocs.push_back(newPtr);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * Data, size_t size) {
 
  // Parse out the first four bytes as the seed for random size
  // requests.
  int i = 0;
  void * ptr;
  if (size < 4) {
    return -1;
  }
  for (auto ind = 0; ind < 4; ind++) {
    char ch = ((char *) Data)[ind];
    switch (ch) {
    case 'M':
    case 'F':
    case 'R':
      return -1;
    default:
      break;
    }
  }
  uint32_t seed = *((uint32_t *) Data);
  i += 4;
  printf("seed = %u\n", seed);
  srand(seed);

  // Parse the string, invoking malloc and free as appropriate, with
  // lots of checks for correctness.
  size_t sz = 0;
  while (i < size) {
    switch (Data[i]) {
    case 'M': // malloc
      i++;
      simulateMalloc();
      break;
    case 'F': // free
      i++;
      simulateFree();
      break;
    case 'R': // realloc
      i++;
      simulateRealloc();
      break;
    default:
      // Parse failed.
      i++;
      return -1;
      break;
    }
  }
  return 0;
}
  
int main()
{
  constexpr int MAX_INPUT_LENGTH = 65536;
  char data[MAX_INPUT_LENGTH];
  memset(data, 0, MAX_INPUT_LENGTH);
  auto result = fread(data, MAX_INPUT_LENGTH, 1, stdin);
  if (result == 0) {
    LLVMFuzzerTestOneInput((const uint8_t *) data, strlen(data));
  }
  return 0;
}

