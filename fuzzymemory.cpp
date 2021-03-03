#include <cassert>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <unistd.h>

#include <unordered_map>
#include <vector>

#include <malloc.h>

/**
   fuzzymemory: a fuzzer for malloc implementations.
 */

// A default-false boolean
class falsy {
public:
  falsy()
    : _val (false)
  {}
  operator bool&() {
    return _val;
  }
  falsy& operator=(bool v) {
    _val = v;
    return *this;
  }
private:
  bool _val;
};

// maximum size of allocated objects
constexpr size_t MAX_SIZE = 256;

// all allocated objects
std::vector<void *> allocs;

// the words occupied by all allocated objects
std::unordered_map<unsigned long, falsy> allocated_bytes;

// the sizes of all allocated objects (0 if freed)
std::unordered_map<void *, size_t> sizes;


void simulateMalloc() {
  // Random size up to MAX_SIZE bytes.
  size_t sz = rand() % MAX_SIZE;
  void * ptr = ::malloc(sz);
  sizes[ptr] = sz;
  // Check alignment.
  assert((uintptr_t) ptr % alignof(max_align_t) == 0);
  // Make sure we aren't overlapping with any previous malloc'd
  // regions.
  for (auto ind = 0; ind < sz; ind++) {
    assert(!allocated_bytes[ind + (uintptr_t) ptr]);
    allocated_bytes[ind + (uintptr_t) ptr] = true;
  }
  printf("MALLOC %ld = %p\n", sz, ptr);
  allocs.push_back(ptr);
  // Fill with a known value.
  for (auto ind = 0; ind < sz; ind++) {
    ((char *) ptr)[ind] = ('M' + ind + (uintptr_t) ptr) % 256;
  }
}

void simulateFree() {
  if (allocs.size() > 0) {
    // ptr = allocs.back();
    // Find a random victim to delete.
    auto victimIndex = rand() % allocs.size();
    auto ptr = allocs[victimIndex]; // .front();
    // Drop "double frees"
    printf("FREE %p\n", ptr);
    // Ensure size reported matches size requested.
    auto sz = sizes[ptr];
    assert(malloc_usable_size(ptr) >= sz);
    // Check for the known value.
    for (auto ind = 0; ind < sz; ind++) {
      auto v = ('M' + ind + (uintptr_t) ptr) % 256;
      //	  printf("free checking to see if ind %d = %d (it's actually %d)\n", ind, v, ((char *) ptr)[ind]);
      assert(((char *) ptr)[ind] == v);
      // Fill with garbage
      ((char *) ptr)[ind] = rand() % 256;
    }
    // Mark the words as no longer allocated.
    for (auto ind = 0; ind < sz ; ind++) {
      // printf("is %d allocated? should be.\n", ind);
      assert(allocated_bytes[ind + (uintptr_t) ptr ]);
      allocated_bytes[ind + (uintptr_t) ptr ] = false;
    }
    ::free(ptr);
    sizes[ptr] = 0;
    // allocs.pop_back();
    allocs.erase(allocs.begin() + victimIndex); // pop_front();
  }
}

void simulateRealloc()
{
      
  if (allocs.size() > 0) {
    // Find a random victim to realloc.
    auto victimIndex = rand() % allocs.size();
    auto ptr = allocs[victimIndex];
    // Ensure size reported matches size requested.
    auto sz = sizes[ptr];
    assert(malloc_usable_size(ptr) >= sz);
    // Allocate the new chunk.
    auto newSize = rand() % MAX_SIZE;
    auto newPtr = ::realloc(ptr, newSize);
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
#if 0
    if (newPtr != ptr) {
      // Fill the old area with garbage
      for (auto ind = 0; ind < sz; ind++) {
	((char *) ptr)[ind] = rand() % 256;
      }
      for (auto ind = 0; ind < sz ; ind++) {
	assert(allocated_bytes[ind + (uintptr_t) ptr ]);
	allocated_bytes[ind + (uintptr_t) ptr ] = false;
      }
    }
#endif
    for (auto ind = 0; ind < sz; ind++) {
      allocated_bytes[ind + (uintptr_t) ptr ] = false;
    }
    for (auto ind = 0; ind < newSize ; ind++) {
      allocated_bytes[ind + (uintptr_t) newPtr ] = true;
    }
    printf("REALLOC %lu -> %lu (%p -> %p)\n", sz, newSize, ptr, newPtr);
    sizes[newPtr] = newSize;
    // allocs.pop_back();
    if (ptr != newPtr) {
      sizes[ptr] = 0;
      allocs.erase(allocs.begin() + victimIndex); // pop_front();
    }
    allocs.push_back(newPtr);	
  }
  
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * Data, size_t size) {
 
  // Parse out the first four bytes as the seed for random size
  // requests.
  int i = 0;
  void * ptr;
  if (size < 4) {
    return 0;
  }
  for (auto ind = 0; ind < 4; ind++) {
    char ch = ((char *) Data)[ind];
    switch (ch) {
    case 'M':
    case 'F':
    case 'R':
      return 0;
    default:
      break;
    }
  }
  uint32_t seed = *((uint32_t *) Data);
  i += 4;
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
      // Parse failed, skip to the next character.
      i++;
      break;
    }
  }
  return 0;
}
  
int main()
{
  char data[4096];
  memset(data, 0, 4096);
  auto result = fread(data, 4096, 1, stdin);
  if (result == 0) {
    LLVMFuzzerTestOneInput((const uint8_t *) data, strlen(data));
  }
  return 0;
}

