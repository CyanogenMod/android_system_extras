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

#include <gtest/gtest.h>

#include "command.h"

class MockCommand : public Command {
 public:
  MockCommand() : Command("mock", "mock_short_help", "mock_long_help") {
  }

  bool Run(const std::vector<std::string>&) override {
    return true;
  }
};

TEST(command, CreateCommandInstance) {
  ASSERT_TRUE(CreateCommandInstance("mock1") == nullptr);
  RegisterCommand("mock1", [] { return std::unique_ptr<Command>(new MockCommand); });
  ASSERT_TRUE(CreateCommandInstance("mock1") != nullptr);
  UnRegisterCommand("mock1");
  ASSERT_TRUE(CreateCommandInstance("mock1") == nullptr);
}

TEST(command, GetAllCommands) {
  size_t command_count = GetAllCommandNames().size();
  RegisterCommand("mock1", [] { return std::unique_ptr<Command>(new MockCommand); });
  ASSERT_EQ(command_count + 1, GetAllCommandNames().size());
  UnRegisterCommand("mock1");
  ASSERT_EQ(command_count, GetAllCommandNames().size());
}
