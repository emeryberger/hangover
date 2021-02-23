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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * Data, size_t size) {
  // all allocated objects
  std::vector<void *> allocs;
  
  // the words occupied by all allocated objects
  std::unordered_map<unsigned long, falsy> allocated_words;

  // all freed objects
  std::unordered_map<void *, bool> freed;

  // the sizes of all allocated objects (0 if freed)
  std::unordered_map<void *, size_t> sizes;

  // Parse out the first four bytes as the seed for random size
  // requests.
  int i = 0;
  void * ptr;
  if (size < 4) {
    return 0;
  }
  uint32_t seed = *((uint32_t *) Data);
  i += 4;
  srand(seed);

  // Parse the string, invoking malloc and free as appropriate, with
  // lots of checks for correctness.
  size_t sz = 0;
  while (i < size) {
    switch (Data[i]) {
    case '(': // malloc
      printf("(\n");
      i++;
      // Random size up to 128 bytes.
      sz = rand() % 128; 
      ptr = ::malloc(sz);
      sizes[ptr] = sz;
      // Check alignment.
      assert((uintptr_t) ptr % 8 == 0);
      // Make sure we aren't overlapping with any previous malloc'd
      // regions.
      for (auto ind = 0; ind < sz / sizeof(unsigned long); ind++) {
	assert(!allocated_words[ind + (uintptr_t) ptr / sizeof(unsigned long)]);
	allocated_words[ind + (uintptr_t) ptr / sizeof(unsigned long)] = true;
      }
      printf("MALLOC %ld = %p\n", sz, ptr);
      allocs.push_back(ptr);
      freed[ptr] = false;
      // Fill with a known value.
      for (auto ind = 0; ind < sz; ind++) {
	((char *) ptr)[ind] = ('M' + ind + (uintptr_t) ptr) % 256;
      }
      break;
    case ')': // free
      i++;
      if (allocs.size() > 0) {
	// ptr = allocs.back();
	// Find a random victim to delete.
	auto victimIndex = rand() % allocs.size();
	ptr = allocs[victimIndex]; // .front();
	// Drop "double frees"
	if (!freed[ptr]) {
	  printf("FREE %p\n", ptr);
	  // Ensure size reported matches size requested.
	  auto sz = sizes[ptr];
	  assert(malloc_usable_size(ptr) >= sz);
	  // Check for the known value.
	  for (auto ind = 0; ind < sz; ind++) {
	    assert(((char *) ptr)[ind] == ('M' + ind + (uintptr_t) ptr) % 256);
	    // Fill with garbage
	    ((char *) ptr)[ind] = rand() % 256;
	  }
	  // Mark the words as no longer allocated.
	  for (auto ind = 0; ind < sz / sizeof(unsigned long); ind++) {
	    assert(allocated_words[ind + (uintptr_t) ptr / sizeof(unsigned long)]);
	    allocated_words[ind + (uintptr_t) ptr / sizeof(unsigned long)] = false;
	  }
	  ::free(ptr);
	  sizes[ptr] = 0;
	  freed[ptr] = true;
	  // allocs.pop_back();
	  allocs.erase(allocs.begin() + victimIndex); // pop_front();
	}
      }
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

