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

#include <android-base/file.h>
#include <android-base/logging.h>

#include "event_attr.h"
#include "utils.h"

#define EVENT_TYPE_TABLE_ENTRY(name, type, config) {name, type, config},

static const std::vector<EventType> static_event_type_array = {
#include "event_type_table.h"
};

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

const std::vector<EventType>& GetAllEventTypes() {
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

const EventType* FindEventTypeByConfig(uint32_t type, uint64_t config) {
  for (auto& event_type : GetAllEventTypes()) {
    if (event_type.type == type && event_type.config == config) {
      return &event_type;
    }
  }
  return nullptr;
}

const EventType* FindEventTypeByName(const std::string& name) {
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
  return result;
}

std::unique_ptr<EventTypeAndModifier> ParseEventType(const std::string& event_type_str) {
  static std::string modifier_characters = "ukhGHp";
  std::unique_ptr<EventTypeAndModifier> event_type_modifier(new EventTypeAndModifier);
  event_type_modifier->name = event_type_str;
  std::string event_type_name = event_type_str;
  std::string modifier;
  size_t comm_pos = event_type_str.rfind(':');
  if (comm_pos != std::string::npos) {
    bool match_modifier = true;
    for (size_t i = comm_pos + 1; i < event_type_str.size(); ++i) {
      char c = event_type_str[i];
      if (c != ' ' && modifier_characters.find(c) == std::string::npos) {
        match_modifier = false;
        break;
      }
    }
    if (match_modifier) {
      event_type_name = event_type_str.substr(0, comm_pos);
      modifier = event_type_str.substr(comm_pos + 1);
    }
  }
  const EventType* event_type = FindEventTypeByName(event_type_name);
  if (event_type == nullptr) {
    // Try if the modifier belongs to the event type name, like some tracepoint events.
    if (!modifier.empty()) {
      event_type_name = event_type_str;
      modifier.clear();
      event_type = FindEventTypeByName(event_type_name);
    }
    if (event_type == nullptr) {
      return nullptr;
    }
  }
  event_type_modifier->event_type = *event_type;
  if (modifier.find_first_of("ukh") != std::string::npos) {
    event_type_modifier->exclude_user = true;
    event_type_modifier->exclude_kernel = true;
    event_type_modifier->exclude_hv = true;
  }
  if (modifier.find_first_of("GH") != std::string::npos) {
    event_type_modifier->exclude_guest = true;
    event_type_modifier->exclude_host = true;
  }

  for (auto& c : modifier) {
    switch (c) {
      case 'u':
        event_type_modifier->exclude_user = false;
        break;
      case 'k':
        event_type_modifier->exclude_kernel = false;
        break;
      case 'h':
        event_type_modifier->exclude_hv = false;
        break;
      case 'G':
        event_type_modifier->exclude_guest = false;
        break;
      case 'H':
        event_type_modifier->exclude_host = false;
        break;
      case 'p':
        event_type_modifier->precise_ip++;
        break;
      case ' ':
        break;
      default:
        LOG(ERROR) << "Unknown event type modifier '" << c << "'";
    }
  }
  event_type_modifier->modifier = modifier;
  return event_type_modifier;
}
