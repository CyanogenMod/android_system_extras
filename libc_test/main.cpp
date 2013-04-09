/*
** Copyright 2013 The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

// Put any local test functions into the extern below.
extern "C" {
}

#define MAX_MEMCPY_TEST_SIZE      2048
#define MAX_MEMCPY_BUFFER_SIZE    (3 * MAX_MEMCPY_TEST_SIZE)

#define MAX_MEMSET_TEST_SIZE      2048
#define MAX_MEMSET_BUFFER_SIZE    (3 * MAX_MEMSET_TEST_SIZE)

#define MAX_STRCMP_TEST_SIZE      1024
#define MAX_STRCMP_BUFFER_SIZE    (3 * MAX_STRCMP_TEST_SIZE)

// Return a pointer into the current string with the specified alignment.
void *getAlignedPtr(void *orig_ptr, int alignment, int or_mask) {
  uint64_t ptr = reinterpret_cast<uint64_t>(orig_ptr);
  if (alignment > 0) {
      // When setting the alignment, set it to exactly the alignment chosen.
      // The pointer returned will be guaranteed not to be aligned to anything
      // more than that.
      ptr += alignment - (ptr & (alignment - 1));
      ptr |= alignment | or_mask;
  }

  return reinterpret_cast<void*>(ptr);
}

bool doStrcmpExpectEqual(char *string1, char *string2, int align[4],
                         int (*test_strcmp)(const char *s1, const char *s2)) {
  char *align_str1 = (char*)getAlignedPtr(string1, align[0], align[1]);
  char *align_str2 = (char*)getAlignedPtr(string2, align[2], align[3]);

  bool pass = true;
  for (int i = 0; i < MAX_STRCMP_TEST_SIZE; i++) {
    for (int j = 0; j < i; j++) {
      align_str1[j] = (char)(32 + (j % 96));
      align_str2[j] = align_str1[j];
    }
    align_str1[i] = '\0';
    align_str2[i] = '\0';
    // Set the characters after the string terminates to different values
    // to verify that the strcmp is not over checking.
    for (int j = i+1; j < i+64; j++) {
      align_str1[j] = (char)(32 + j);
      align_str2[j] = (char)(40 + j);
    }

    if (test_strcmp(align_str1, align_str2) != 0) {
      printf("    Failed at size %d, src1 %p, src2 %p\n",
             i, align_str1, align_str2);
      pass = false;
    }
  }
  return pass;
}

bool doStrcmpExpectDiff(char *string1, char *string2, int diff_align[2],
                        int align[4], char diff_char,
                        int (*test_strcmp)(const char *s1, const char *s2)) {
  char *align_str1 = (char*)getAlignedPtr(string1, align[0], align[1]);
  char *align_str2 = (char*)getAlignedPtr(string2, align[2], align[3]);
  bool pass = true;

  for (int i = 0; i < MAX_STRCMP_TEST_SIZE; i++) {
    // Use valid ascii characters, no unprintables characters.
    align_str1[i] = (char)(32 + (i % 96));
    if (align_str1[i] == diff_char) {
      // Assumes that one less than the diff character is still a valid
      // character.
      align_str1[i] = diff_char-1;
    }
    align_str2[i] = align_str1[i];
  }
  align_str1[MAX_STRCMP_TEST_SIZE] = '\0';
  align_str2[MAX_STRCMP_TEST_SIZE] = '\0';

  // Quick check to make sure that the strcmp knows that everything is
  // equal. If it's so broken that it already thinks the strings are
  // different, then there is no point running any of the other tests.
  if (test_strcmp(align_str1, align_str2) != 0) {
    printf("    strcmp is too broken to do difference testing.\n");
    return false;
  }

  // Get a pointer into the string at the specified alignment.
  char *bad = (char*) getAlignedPtr(align_str1+MAX_STRCMP_TEST_SIZE/2,
                                    diff_align[0], diff_align[1]);

  char saved_char = bad[0];
  bad[0] = diff_char;
  if (test_strcmp(align_str1, align_str2) == 0) {
    printf("   Did not miscompare at size %d, src1 %p, src2 %p, diff %p\n",
           MAX_STRCMP_TEST_SIZE, align_str1, align_str2, bad);
    pass = false;
  }
  bad[0] = saved_char;

  // Re-verify that something hasn't gone horribly wrong.
  if (test_strcmp(align_str1, align_str2) != 0) {
    printf("   strcmp is too broken to do difference testing.\n");
    return false;
  }

  bad = (char*)getAlignedPtr(align_str2+MAX_STRCMP_TEST_SIZE/2, diff_align[0],
                             diff_align[1]);
  bad[0] = diff_char;
  if (test_strcmp(align_str1, align_str2) == 0) {
    printf("    Did not miscompare at size %d, src1 %p, src2 %p, diff %p\n",
           MAX_STRCMP_TEST_SIZE, align_str1, align_str2, bad);
    pass = false;
  }

  return pass;
}

bool doStrcmpCheckRead(int (*test_strcmp)(const char *s1, const char *s2)) {
  // In order to verify that the strcmp is not reading past the end of the
  // string, create some strings that end near unreadable memory.
  long pagesize = sysconf(_SC_PAGE_SIZE);
  char *memory = (char*)memalign(pagesize, 2 * pagesize);
  if (memory == NULL) {
    perror("Unable to allocate memory.\n");
    return false;
  }

  // Make the second page unreadable and unwritable.
  if (mprotect(&memory[pagesize], pagesize, PROT_NONE) != 0) {
    perror("Unable to set protection of page.\n");
    return false;
  }

  char *string;
  bool pass = true;
  int max_size = pagesize < MAX_STRCMP_TEST_SIZE ? pagesize-1 : MAX_STRCMP_TEST_SIZE;
  // Allocate an extra byte beyond the string terminator to allow us to
  // extend the string to be larger than our protected string.
  char *other_string = (char *)malloc(max_size+2);
  if (other_string == NULL) {
    perror("Unable to allocate memory.\n");
    return false;
  }
  for (int i = 0; i <= max_size; i++) {
    string = &memory[pagesize-i-1];
    for (int j = 0; j < i; j++) {
      other_string[j] = (char)(32 + (j % 96));
      string[j] = other_string[j];
    }
    other_string[i] = '\0';
    string[i] = '\0';

    if (test_strcmp(other_string, string) != 0) {
      printf("    Failed at size %d, src1 %p, src2 %p\n", i, other_string, string);
      pass = false;
    }
    if (test_strcmp(string, other_string) != 0) {
      printf("    Failed at size %d, src1 %p, src2 %p\n", i, string, other_string);
      pass = false;
    }

    // Now make other_string longer than our protected string.
    other_string[i] = '1';
    other_string[i+1] = '\0';

    if (test_strcmp(other_string, string) == 0) {
      printf("    Failed at size %d, src1 %p, src2 %p\n", i, other_string, string);
      pass = false;
    }
    if (test_strcmp(string, other_string) == 0) {
      printf("    Failed at size %d, src1 %p, src2 %p\n", i, string, other_string);
      pass = false;
    }
  }
  return pass;
}

bool runStrcmpTest(int (*test_strcmp)(const char *s1, const char *s2)) {
  // Allocate two large buffers to hold the two strings.
  char *string1 = reinterpret_cast<char*>(malloc(MAX_STRCMP_BUFFER_SIZE+1));
  char *string2 = reinterpret_cast<char*>(malloc(MAX_STRCMP_BUFFER_SIZE+1));
  if (string1 == NULL || string2 == NULL) {
    perror("Unable to allocate memory.\n");
    return false;
  }
  char saved_char;

  // Initialize the strings to be exactly the same.
  for (int i = 0; i < MAX_STRCMP_BUFFER_SIZE; i++) {
    string1[i] = (char)(32 + (i % 96));
    string2[i] = string1[i];
  }
  string1[MAX_STRCMP_BUFFER_SIZE] = '\0';
  string2[MAX_STRCMP_BUFFER_SIZE] = '\0';

  bool pass = true;

  // Loop through strings that are the same, unknown alignment looking for
  // very obvious problems.
  printf("  Verifying variable sized strings.\n");
  for (int i = 0; i <= MAX_STRCMP_TEST_SIZE; i++) {
    saved_char = string1[i];
    string1[i] = '\0';
    string2[i] = '\0';
    if (test_strcmp(string1, string2) != 0) {
      printf("   Found incorrect mismatch at size %d\n", i);
      pass = false;
    }
    string1[i] = saved_char;
    string2[i] = saved_char;
  }

  // Strings the same, all same size:
  // - Both pointers double word aligned.
  // - One pointer double word aligned, one pointer word aligned.
  // - Both pointers word aligned.
  // - One pointer double word aligned, one pointer 1 off a word alignment.
  // - One pointer double word aligned, one pointer 2 off a word alignment.
  // - One pointer double word aligned, one pointer 3 off a word alignment.
  // - One pointer word aligned, one pointer 1 off a word alignment.
  // - One pointer word aligned, one pointer 2 off a word alignment.
  // - One pointer word aligned, one pointer 3 off a word alignment.
  int string_aligns[][4] = {
    { 1, 0, 1, 0 },
    { 2, 0, 2, 0 },
    { 4, 0, 4, 0 },
    { 8, 0, 8, 0 },

    { 8, 0, 4, 0 },
    { 4, 0, 8, 0 },

    { 8, 0, 8, 1 },
    { 8, 0, 8, 2 },
    { 8, 0, 8, 3 },
    { 8, 1, 8, 0 },
    { 8, 2, 8, 0 },
    { 8, 3, 8, 0 },

    { 4, 0, 4, 1 },
    { 4, 0, 4, 2 },
    { 4, 0, 4, 3 },
    { 4, 1, 4, 0 },
    { 4, 2, 4, 0 },
    { 4, 3, 4, 0 },
  };

  printf("  Verifying equal sized strings at different alignments.\n");
  for (size_t i = 0; i < sizeof(string_aligns)/sizeof(int[4]); i++) {
    pass = pass && doStrcmpExpectEqual(string1, string2, string_aligns[i],
                                       test_strcmp);
  }

  // Different strings, all same size:
  // - Single difference at double word boundary.
  // - Single difference at word boudary.
  // - Single difference at 1 off a word alignment.
  // - Single difference at 2 off a word alignment.
  // - Single difference at 3 off a word alignment.

  // Different sized strings, strings the same until the end:
  // - Shorter string ends on a double word boundary.
  // - Shorter string ends on word boundary.
  // - Shorter string ends at 1 off a word boundary.
  // - Shorter string ends at 2 off a word boundary.
  // - Shorter string ends at 3 off a word boundary.
  int diff_aligns[][2] = {
    { 4, 0 },
    { 4, 1 },
    { 4, 2 },
    { 4, 3 },
    { 8, 0 },
    { 8, 1 },
    { 8, 2 },
    { 8, 3 },
  };
  printf("  Verifying different strings at different alignments.\n");
  for (unsigned int i = 0; i < sizeof(diff_aligns)/sizeof(int[2]); i++) {
    // First loop put the string terminator at the chosen alignment.
    for (unsigned int j = 0; j < sizeof(string_aligns)/sizeof(int[4]); j++) {
      pass = pass && doStrcmpExpectDiff(string1, string2, diff_aligns[i],
                                        string_aligns[j], '\0', test_strcmp);
    }
    // Second loop put a different character at the chosen alignment.
    // This character is guaranteed not to be in the original string.
    for (unsigned int j = 0; j < sizeof(string_aligns)/sizeof(int[4]); j++) {
      pass = pass && doStrcmpExpectDiff(string1, string2, diff_aligns[i],
                                        string_aligns[j], '\0', test_strcmp);
    }
  }

  printf("  Verifying strcmp does not read too many bytes.\n");
  pass = pass && doStrcmpCheckRead(test_strcmp);

  if (pass) {
    printf("All tests pass.\n");
  }

  return pass;
}

bool runMemcpyTest(void* (*test_memcpy)(void *dst, const void *src, size_t n)) {
  // Allocate two large buffers to hold the dst and src.
  uint8_t *dst = reinterpret_cast<uint8_t*>(malloc(MAX_MEMCPY_BUFFER_SIZE));
  uint8_t *src = reinterpret_cast<uint8_t*>(malloc(MAX_MEMCPY_BUFFER_SIZE));
  if (dst == NULL || src == NULL) {
    perror("Unable to allocate memory.\n");
    return false;
  }

  // Set the source to a known pattern once. We are assuming that the
  // memcpy isn't so broken that it's writing into the source buffer.
  for (int i = 0; i < MAX_MEMCPY_BUFFER_SIZE; i++) {
    src[i] = i % 256;
    if (src[i] == 0) {
      // Don't allow any zeroes so we can do a quick check that the source
      // is never zero.
      src[i] = 0xaa;
    }
  }

  bool pass = true;

  // Loop through and do copies of various sizes and unknown alignment
  // looking for very obvious problems.
  printf("  Verifying variable sized copies.\n");
  for (int len = 0; len <= MAX_MEMCPY_TEST_SIZE; len++) {
    memset(dst, 0, len);
    // Set fencepost values to check if the copy went past the end.
    dst[len] = 0xde;
    dst[len+1] = 0xad;

    test_memcpy(dst, src, len);

    for (int i = 0; i < len; i++) {
      if (dst[i] != src[i] || !src[i]) {
        if (!src[i]) {
          printf("    src[%d] is 0, memcpy wrote into the source.\n", i);
        }
        printf("    Failed at size %d[%d,%d!=%d], src=%p[0,0], dst=%p[0,0] no alignment set\n",
               len, i, src[i], dst[i], src, dst);
        pass = false;
        break;
      }
    }
    if (dst[len] != 0xde || dst[len+1] != 0xad) {
      printf("    memcpy wrote past the end of the array.\n");
      printf("    Failed at size %d, src=%p[0,0], dst=%p[0,0] [%d,%d]\n",
             len, src, dst, dst[len], dst[len+1]);
      pass = false;
    }
  }

  int aligns[][4] = {
    // Src and Dst at same alignment.
    { 1, 0, 1, 0 },
    { 2, 0, 2, 0 },
    { 4, 0, 4, 0 },
    { 8, 0, 8, 0 },
    { 16, 0, 16, 0 },
    { 32, 0, 32, 0 },
    { 64, 0, 64, 0 },
    { 128, 0, 128, 0 },

    // Different alignments between src and dst.
    { 8, 0, 4, 0 },
    { 4, 0, 8, 0 },
    { 16, 0, 4, 0 },
    { 4, 0, 16, 0 },

    // General unaligned cases.
    { 4, 0, 4, 1 },
    { 4, 0, 4, 2 },
    { 4, 0, 4, 3 },
    { 4, 1, 4, 0 },
    { 4, 2, 4, 0 },
    { 4, 3, 4, 0 },

    // All non-word aligned cases.
    { 4, 1, 4, 0 },
    { 4, 1, 4, 1 },
    { 4, 1, 4, 2 },
    { 4, 1, 4, 3 },

    { 4, 2, 4, 0 },
    { 4, 2, 4, 1 },
    { 4, 2, 4, 2 },
    { 4, 2, 4, 3 },

    { 4, 3, 4, 0 },
    { 4, 3, 4, 1 },
    { 4, 3, 4, 2 },
    { 4, 3, 4, 3 },

    { 2, 0, 4, 0 },
    { 4, 0, 2, 0 },
    { 2, 0, 2, 0 },

    // Invoke the unaligned case where the code needs to align dst to 0x10.
    { 128, 1, 128, 4 },
    { 128, 1, 128, 8 },
    { 128, 1, 128, 12 },
    { 128, 1, 128, 16 },
  };

  printf("  Verifying variable sized copies at different alignments.\n");
  uint8_t *src_align, *dst_align;
  for (size_t i = 0; i < sizeof(aligns)/sizeof(int[4]); i++) {
    for (int len = 0; len <= MAX_MEMCPY_TEST_SIZE; len++) {
      src_align = (uint8_t*)getAlignedPtr(src, aligns[i][0], aligns[i][1]);
      dst_align = (uint8_t*)getAlignedPtr(dst, aligns[i][2], aligns[i][3]);
      memset(dst_align, 0, len);
      // Set fencepost values to check if the copy went past the end.
      dst_align[len] = 0xde;
      dst_align[len+1] = 0xad;

      test_memcpy(dst_align, src_align, len);

      for (int j = 0; j < len; j++) {
        if (dst_align[j] != src_align[j] || !src_align[j]) {
          if (!src_align[j]) {
            printf("    src_align[%d] is 0, memcpy wrote into the source.\n", j);
          }
          printf("    Failed at size %d, src_align=%p[%d,%d], dst_align=%p[%d,%d]\n",
                 len, src_align, aligns[i][0], aligns[i][1],
                 dst_align, aligns[i][2], aligns[i][3]);
          pass = false;
          break;
        }
      }
      if (dst_align[len] != 0xde || dst_align[len+1] != 0xad) {
        printf("    memcpy wrote past the end of the array.\n");
        printf("    Failed at size %d, src_align=%p[%d,%d], dst_align=%p[%d,%d] [%d,%d]\n",
               len, src_align, aligns[i][0], aligns[i][1],
               dst_align, aligns[i][2], aligns[i][3],
               dst_align[len], dst_align[len+1]);
        pass = false;
      }
    }
  }

  if (pass) {
    printf("All tests pass.\n");
  }

  return pass;
}

bool runMemsetTest(void* (*test_memset)(void *s, int c, size_t n)) {
  // Allocate one large buffer to hold the dst.
  uint8_t *buf = reinterpret_cast<uint8_t*>(malloc(MAX_MEMSET_BUFFER_SIZE));
  if (buf == NULL) {
    perror("Unable to allocate memory.\n");
    return false;
  }

  bool pass = true;
  int value;

  // Loop through and do copies of various sizes and unknown alignment
  // looking for very obvious problems.
  printf("  Verifying variable sized copies.\n");
  for (int len = 0; len <= MAX_MEMSET_TEST_SIZE; len++) {
    // Set the buffer to all zero without memset since it might be the
    // function we are testing.
    for (int i = 0; i < len; i++) {
      buf[i] = 0;
    }
    // Set fencepost values to check if the set went past the end.
    buf[len] = 0xde;
    buf[len+1] = 0xad;

    value = (len % 255) + 1;
    test_memset(buf, value, len);

    for (int i = 0; i < len; i++) {
      if (buf[i] != value) {
        printf("    Failed at size %d[%d,%d!=%d], buf=%p[0,0]\n",
               len, i, buf[i], value, buf);
        pass = false;
        return pass;
        break;
      }
    }
    if (buf[len] != 0xde || buf[len+1] != 0xad) {
      printf("    memset wrote past the end of the array.\n");
      printf("    Failed at size %d, buf=%p[0,0] [%d,%d]\n",
             len, buf, buf[len], buf[len+1]);
      pass = false;
      return pass;
    }
  }

  int aligns[][2] = {
    // Different alignments.
    { 1, 0 },
    { 2, 0 },
    { 4, 0 },
    { 8, 0 },
    { 16, 0 },
    { 32, 0 },
    { 64, 0 },

    // Different alignments between src and dst.
    { 8, 1 },
    { 8, 2 },
    { 8, 3 },
    { 8, 4 },
    { 8, 5 },
    { 8, 6 },
    { 8, 7 },
  };

  printf("  Verifying variable sized memsets at different alignments.\n");
  uint8_t *buf_align;
  for (size_t i = 0; i < sizeof(aligns)/sizeof(int[2]); i++) {
    for (int len = 0; len <= MAX_MEMSET_TEST_SIZE; len++) {
      buf_align = (uint8_t*)getAlignedPtr(buf, aligns[i][0], aligns[i][1]);

      // Set the buffer to all zero without memset since it might be the
      // function we are testing.
      for (int j = 0; j < len; j++) {
        buf_align[j] = 0;
      }
      // Set fencepost values to check if the set went past the end.
      buf_align[len] = 0xde;
      buf_align[len+1] = 0xad;

      value = (len % 255) + 1;
      test_memset(buf_align, value, len);

      for (int j = 0; j < len; j++) {
        if (buf_align[j] != value) {

          printf("    Failed at size %d[%d,%d!=%d], buf_align=%p[%d,%d]\n",
                 len, j, buf_align[j], value, buf_align, aligns[i][0],
                 aligns[i][1]);
          pass = false;
          return pass;
          break;
        }
      }
      if (buf_align[len] != 0xde || buf_align[len+1] != 0xad) {
        printf("    memset wrote past the end of the array.\n");
        printf("    Failed at size %d, buf_align=%p[%d,%d]\n",
               len, buf_align, aligns[i][0], aligns[i][1]);
        pass = false;
        return pass;
      }
    }
  }

  if (pass) {
    printf("All tests pass.\n");
  }

  return pass;
}

int main(int argc, char **argv) {
  bool tests_passing = true;

  printf("Testing strcmp...\n");
  tests_passing = tests_passing && runStrcmpTest(strcmp);

  printf("Testing memcpy...\n");
  tests_passing = tests_passing && runMemcpyTest(memcpy);

  printf("Testing memset...\n");
  tests_passing = tests_passing && runMemsetTest(memset);

  return (tests_passing ? 0 : 1);
}
