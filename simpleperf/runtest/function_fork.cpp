#include <unistd.h>

constexpr int LOOP_COUNT = 100000000;

void ParentFunction() {
  for (volatile int i = 0; i < LOOP_COUNT; ++i) {
  }
}

void ChildFunction() {
  for (volatile int i = 0; i < LOOP_COUNT; ++i) {
  }
}

int main() {
  pid_t pid = fork();
  if (pid == 0) {
    ChildFunction();
    return 0;
  } else {
    ParentFunction();
  }
  return 0;
}
