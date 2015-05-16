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

#include <stdio.h>
#include <map>
#include <string>
#include <vector>

#include <base/logging.h>

#include "command.h"
#include "event_type.h"
#include "perf_event.h"

static void PrintEventTypesOfType(uint32_t type, const std::string& type_name,
                                  const std::vector<EventType>& event_types) {
  printf("List of %s:\n", type_name.c_str());
  for (auto& event_type : event_types) {
    if (event_type.type == type && event_type.IsSupportedByKernel()) {
      printf("  %s\n", event_type.name.c_str());
    }
  }
  printf("\n");
}

class ListCommand : public Command {
 public:
  ListCommand()
      : Command("list", "list available event types",
                "Usage: simpleperf list [hw|sw|cache|tracepoint]\n"
                "    List all available perf events on this machine.\n") {
  }

  bool Run(const std::vector<std::string>& args) override;
};

bool ListCommand::Run(const std::vector<std::string>& args) {
  static std::map<std::string, std::pair<int, std::string>> type_map = {
      {"hw", {PERF_TYPE_HARDWARE, "hardware events"}},
      {"sw", {PERF_TYPE_SOFTWARE, "software events"}},
      {"cache", {PERF_TYPE_HW_CACHE, "hw-cache events"}},
      {"tracepoint", {PERF_TYPE_TRACEPOINT, "tracepoint events"}},
  };

  std::vector<std::string> names;
  if (args.size() == 1) {
    for (auto& item : type_map) {
      names.push_back(item.first);
    }
  } else {
    for (size_t i = 1; i < args.size(); ++i) {
      if (type_map.find(args[i]) != type_map.end()) {
        names.push_back(args[i]);
      } else {
        LOG(ERROR) << "unknown event type category: " << args[i] << ", try using \"help list\"";
        return false;
      }
    }
  }

  auto& event_types = EventTypeFactory::GetAllEventTypes();

  for (auto& name : names) {
    auto it = type_map.find(name);
    PrintEventTypesOfType(it->second.first, it->second.second, event_types);
  }
  return true;
}

ListCommand list_command;
