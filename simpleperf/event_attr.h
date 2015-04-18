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

#ifndef SIMPLE_PERF_EVENT_ATTR_H_
#define SIMPLE_PERF_EVENT_ATTR_H_

#include <stdint.h>
#include <string>

#include "perf_event.h"

struct EventType;

// EventAttr manages perf_event_attr, which provides detailed configuration information when
// opening a perf_event_file. The configuration information tells the kernel how to count and
// record events.
class EventAttr {
 public:
  static EventAttr CreateDefaultAttrToMonitorEvent(const EventType& event_type);

  EventAttr(const perf_event_attr& attr) : attr_(attr) {
  }

  perf_event_attr Attr() const {
    return attr_;
  }

  uint64_t SampleType() const {
    return attr_.sample_type;
  }

  void EnableOnExec() {
    attr_.enable_on_exec = 1;
  }

  void SetSampleFreq(uint64_t freq) {
    attr_.freq = 1;
    attr_.sample_freq = freq;
  }

  void SetSamplePeriod(uint64_t period) {
    attr_.freq = 0;
    attr_.sample_period = period;
  }

  void SetSampleAll() {
    attr_.sample_id_all = 1;
  }

  void Dump(size_t indent = 0) const;

 private:
  perf_event_attr attr_;
};

#endif  // SIMPLE_PERF_EVENT_ATTR_H_
