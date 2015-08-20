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

#ifndef SIMPLE_PERF_EVENT_H_
#define SIMPLE_PERF_EVENT_H_

#include <stdint.h>
#include <memory>
#include <string>
#include <vector>

// EventType represents one type of event, like cpu_cycle_event, cache_misses_event.
// The user knows one event type by its name, and the kernel knows one event type by its
// (type, config) pair. EventType connects the two representations, and tells the user if
// the event type is supported by the kernel.

struct EventType {
  EventType(const std::string& name, uint32_t type, uint64_t config)
      : name(name), type(type), config(config) {
  }

  EventType() : type(0), config(0) {
  }

  std::string name;
  uint32_t type;
  uint64_t config;
};

const std::vector<EventType>& GetAllEventTypes();
const EventType* FindEventTypeByConfig(uint32_t type, uint64_t config);
const EventType* FindEventTypeByName(const std::string& name);

struct EventTypeAndModifier {
  std::string name;
  EventType event_type;
  std::string modifier;
  bool exclude_user;
  bool exclude_kernel;
  bool exclude_hv;
  bool exclude_host;
  bool exclude_guest;
  int precise_ip : 2;

  EventTypeAndModifier()
      : exclude_user(false),
        exclude_kernel(false),
        exclude_hv(false),
        exclude_host(false),
        exclude_guest(false),
        precise_ip(0) {
  }
};

std::unique_ptr<EventTypeAndModifier> ParseEventType(const std::string& event_type_str);

#endif  // SIMPLE_PERF_EVENT_H_
