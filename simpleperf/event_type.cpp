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

#include "event_type.h"

#include <unistd.h>
#include <algorithm>
#include <string>
#include <vector>

#include <base/file.h>
#include <base/logging.h>

#include "event_attr.h"
#include "event_fd.h"
#include "utils.h"

#define EVENT_TYPE_TABLE_ENTRY(name, type, config) \
  { name, type, config }                           \
  ,

static const std::vector<EventType> static_event_type_array = {
#include "event_type_table.h"
};

static bool IsEventTypeSupportedByKernel(const EventType& event_type) {
  auto event_fd =
      EventFd::OpenEventFile(CreateDefaultPerfEventAttr(event_type), getpid(), -1, false);
  return event_fd != nullptr;
}

bool EventType::IsSupportedByKernel() const {
  return IsEventTypeSupportedByKernel(*this);
}

static const std::vector<EventType> GetTracepointEventTypes() {
  std::vector<EventType> result;
  const std::string tracepoint_dirname = "/sys/kernel/debug/tracing/events";
  std::vector<std::string> system_dirs;
  GetEntriesInDir(tracepoint_dirname, nullptr, &system_dirs);
  for (auto& system_name : system_dirs) {
    std::string system_path = tracepoint_dirname + "/" + system_name;
    std::vector<std::string> event_dirs;
    GetEntriesInDir(system_path, nullptr, &event_dirs);
    for (auto& event_name : event_dirs) {
      std::string id_path = system_path + "/" + event_name + "/id";
      std::string id_content;
      if (!android::base::ReadFileToString(id_path, &id_content)) {
        continue;
      }
      char* endptr;
      uint64_t id = strtoull(id_content.c_str(), &endptr, 10);
      if (endptr == id_content.c_str()) {
        LOG(DEBUG) << "unexpected id '" << id_content << "' in " << id_path;
        continue;
      }
      result.push_back(EventType(system_name + ":" + event_name, PERF_TYPE_TRACEPOINT, id));
    }
  }
  std::sort(result.begin(), result.end(),
            [](const EventType& type1, const EventType& type2) { return type1.name < type2.name; });
  return result;
}

const std::vector<EventType>& EventTypeFactory::GetAllEventTypes() {
  static std::vector<EventType> event_type_array;
  if (event_type_array.empty()) {
    event_type_array.insert(event_type_array.end(), static_event_type_array.begin(),
                            static_event_type_array.end());
    const std::vector<EventType> tracepoint_array = GetTracepointEventTypes();
    event_type_array.insert(event_type_array.end(), tracepoint_array.begin(),
                            tracepoint_array.end());
  }
  return event_type_array;
}

const EventType* EventTypeFactory::FindEventTypeByName(const std::string& name,
                                                       bool report_unsupported_type) {
  const EventType* result = nullptr;
  for (auto& event_type : GetAllEventTypes()) {
    if (event_type.name == name) {
      result = &event_type;
      break;
    }
  }
  if (result == nullptr) {
    LOG(ERROR) << "Unknown event_type '" << name
               << "', try `simpleperf list` to list all possible event type names";
    return nullptr;
  }
  if (!result->IsSupportedByKernel()) {
    (report_unsupported_type ? PLOG(ERROR) : PLOG(DEBUG)) << "Event type '" << result->name
                                                          << "' is not supported by the kernel";
    return nullptr;
  }
  return result;
}

const EventType* EventTypeFactory::FindEventTypeByConfig(uint32_t type, uint64_t config) {
  for (auto& event_type : GetAllEventTypes()) {
    if (event_type.type == type && event_type.config == config) {
      return &event_type;
    }
  }
  return nullptr;
}
