#include <iostream>
#include <string>
#include <random>

int
main()
{
  // Seed with a real random value, if available
  std::random_device r;
  
  std::default_random_engine e1(r());
  std::uniform_int_distribution<int> uniform_dist(0, RAND_MAX);
  int rando = uniform_dist(e1);
  char * rc = (char *) &rando;
  for (int i = 0; i < 4; i++) {
    std::cout << rc[i];
  }
  std::uniform_int_distribution<int> action_dist(0, 2);
  char arr[] = { 'M', 'F', 'R' };
  for (int i = 0; i < 65536; i++) {
    std::cout << arr[action_dist(e1)];
  }
  return 0;
}
