/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <pagemap/pagemap.h>

#include <string>

#include <gtest/gtest.h>

TEST(pagemap, maps) {
  pm_kernel_t* kernel;
  ASSERT_EQ(0, pm_kernel_create(&kernel));

  pm_process_t* process;
  ASSERT_EQ(0, pm_process_create(kernel, getpid(), &process));

  pm_map_t** maps;
  size_t num_maps;
  ASSERT_EQ(0, pm_process_maps(process, &maps, &num_maps));

  bool found_heap = false;
  bool found_stack = false;
  for (size_t i = 0; i < num_maps; i++) {
    std::string name(maps[i]->name);
    if (name == "[heap]" || name == "[anon:libc_malloc]") found_heap = true;
    if (name == "[stack]") found_stack = true;
  }

  ASSERT_TRUE(found_heap);
  ASSERT_TRUE(found_stack);

  free(maps);
  pm_process_destroy(process);
  pm_kernel_destroy(kernel);
}
