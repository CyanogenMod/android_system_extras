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
#include <string>
#include <vector>
#include "event_attr.h"
#include "event_fd.h"

#define EVENT_TYPE_TABLE_ENTRY(name, type, config) \
  { name, type, config }                           \
  ,

static std::vector<const EventType> event_type_array = {
#include "event_type_table.h"
};

static bool IsEventTypeSupportedByKernel(const EventType& event_type) {
  auto event_fd = EventFd::OpenEventFileForProcess(
      EventAttr::CreateDefaultAttrToMonitorEvent(event_type), getpid());
  return event_fd != nullptr;
}

bool EventType::IsSupportedByKernel() const {
  return IsEventTypeSupportedByKernel(*this);
}

const std::vector<const EventType>& EventTypeFactory::GetAllEventTypes() {
  return event_type_array;
}

const EventType* EventTypeFactory::FindEventTypeByName(const std::string& name) {
  for (auto& event_type : event_type_array) {
    if (event_type.name == name) {
      return &event_type;
    }
  }
  return nullptr;
}

const EventType* EventTypeFactory::FindEventTypeByConfig(uint32_t type, uint64_t config) {
  for (auto& event_type : event_type_array) {
    if (event_type.type == type && event_type.config == config) {
      return &event_type;
    }
  }
  return nullptr;
}
