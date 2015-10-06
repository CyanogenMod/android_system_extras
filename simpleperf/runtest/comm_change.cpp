#include <sys/prctl.h>

constexpr int LOOP_COUNT = 100000000;

void Function1() {
  for (volatile int i = 0; i < LOOP_COUNT; ++i) {
  }
}

int main() {
  prctl(PR_SET_NAME, reinterpret_cast<unsigned long>("RUN_COMM1"), 0, 0, 0);
  Function1();
  prctl(PR_SET_NAME, reinterpret_cast<unsigned long>("RUN_COMM2"), 0, 0, 0);
  Function1();
  return 0;
}
