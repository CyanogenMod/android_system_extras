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

#include "command.h"

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include <android-base/logging.h>

bool Command::NextArgumentOrError(const std::vector<std::string>& args, size_t* pi) {
  if (*pi + 1 == args.size()) {
    LOG(ERROR) << "No argument following " << args[*pi] << " option. Try `simpleperf help " << name_
               << "`";
    return false;
  }
  ++*pi;
  return true;
}

void Command::ReportUnknownOption(const std::vector<std::string>& args, size_t i) {
  LOG(ERROR) << "Unknown option for " << name_ << " command: '" << args[i]
             << "'. Try `simpleperf help " << name_ << "`";
}

typedef std::function<std::unique_ptr<Command>(void)> callback_t;

static std::map<std::string, callback_t>& CommandMap() {
  // commands is used in the constructor of Command. Defining it as a static
  // variable in a function makes sure it is initialized before use.
  static std::map<std::string, callback_t> command_map;
  return command_map;
}

void RegisterCommand(const std::string& cmd_name,
                     std::function<std::unique_ptr<Command>(void)> callback) {
  CommandMap().insert(std::make_pair(cmd_name, callback));
}

void UnRegisterCommand(const std::string& cmd_name) {
  CommandMap().erase(cmd_name);
}

std::unique_ptr<Command> CreateCommandInstance(const std::string& cmd_name) {
  auto it = CommandMap().find(cmd_name);
  return (it == CommandMap().end()) ? nullptr : (it->second)();
}

const std::vector<std::string> GetAllCommandNames() {
  std::vector<std::string> names;
  for (auto pair : CommandMap()) {
    names.push_back(pair.first);
  }
  return names;
}

extern void RegisterDumpRecordCommand();
extern void RegisterHelpCommand();
extern void RegisterListCommand();
extern void RegisterRecordCommand();
extern void RegisterReportCommand();
extern void RegisterStatCommand();

class CommandRegister {
 public:
  CommandRegister() {
    RegisterDumpRecordCommand();
    RegisterHelpCommand();
    RegisterReportCommand();
#if defined(__linux__)
    RegisterListCommand();
    RegisterRecordCommand();
    RegisterStatCommand();
#endif
  }
};

CommandRegister command_register;
