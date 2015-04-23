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

#include "event_attr.h"

#include <inttypes.h>
#include <stdio.h>
#include <string>
#include <unordered_map>

#include <base/logging.h>

#include "event_type.h"
#include "utils.h"

static std::string SampleTypeToString(uint64_t sample_type) {
  std::unordered_map<int, std::string> map = {
      {PERF_SAMPLE_IP, "ip"},
      {PERF_SAMPLE_TID, "tid"},
      {PERF_SAMPLE_TIME, "time"},
      {PERF_SAMPLE_ADDR, "addr"},
      {PERF_SAMPLE_READ, "read"},
      {PERF_SAMPLE_CALLCHAIN, "callchain"},
      {PERF_SAMPLE_ID, "id"},
      {PERF_SAMPLE_CPU, "cpu"},
      {PERF_SAMPLE_PERIOD, "period"},
      {PERF_SAMPLE_STREAM_ID, "stream_id"},
      {PERF_SAMPLE_RAW, "raw"},
  };

  std::string result;
  for (auto p : map) {
    if (sample_type & p.first) {
      sample_type &= ~p.first;
      if (!result.empty()) {
        result += ", ";
      }
      result += p.second;
    }
  }
  if (sample_type != 0) {
    LOG(DEBUG) << "unknown sample_type bits: " << std::hex << sample_type;
  }

  return result;
}

EventAttr EventAttr::CreateDefaultAttrToMonitorEvent(const EventType& event_type) {
  perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(perf_event_attr);
  attr.type = event_type.type;
  attr.config = event_type.config;
  attr.mmap = 1;
  attr.comm = 1;
  // Changing read_format affects the layout of the data read from perf_event_file, namely
  // PerfCounter in event_fd.h.
  attr.read_format =
      PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING | PERF_FORMAT_ID;
  attr.sample_type |= PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_PERIOD;
  attr.disabled = 1;
  return EventAttr(attr);
}

void EventAttr::Dump(size_t indent) const {
  std::string event_name = "unknown";
  const EventType* event_type = EventTypeFactory::FindEventTypeByConfig(attr_.type, attr_.config);
  if (event_type != nullptr) {
    event_name = event_type->name;
  }

  PrintIndented(indent, "event_attr_: for event %s\n", event_name.c_str());

  PrintIndented(indent + 2, "type %u, size %u, config %llu\n", attr_.type, attr_.size, attr_.config);

  if (attr_.freq != 0) {
    PrintIndented(indent + 2, "sample_freq %llu\n", attr_.sample_freq);
  } else {
    PrintIndented(indent + 2, "sample_period %llu\n", attr_.sample_period);
  }

  PrintIndented(indent + 2, "sample_type (0x%llx) %s\n", attr_.sample_type,
                SampleTypeToString(attr_.sample_type).c_str());

  PrintIndented(indent + 2, "read_format (0x%llx)\n", attr_.read_format);

  PrintIndented(indent + 2, "disabled %llu, inherit %llu, pinned %llu, exclusive %llu\n",
                attr_.disabled, attr_.inherit, attr_.pinned, attr_.exclusive);

  PrintIndented(indent + 2, "exclude_user %llu, exclude_kernel %llu, exclude_hv %llu\n",
                attr_.exclude_user, attr_.exclude_kernel, attr_.exclude_hv);

  PrintIndented(indent + 2, "exclude_idle %llu, mmap %llu, comm %llu, freq %llu\n",
                attr_.exclude_idle, attr_.mmap, attr_.comm, attr_.freq);

  PrintIndented(indent + 2, "inherit_stat %llu, enable_on_exec %llu, task %llu\n",
                attr_.inherit_stat, attr_.enable_on_exec, attr_.task);

  PrintIndented(indent + 2, "watermark %llu, precise_ip %llu, mmap_data %llu\n", attr_.watermark,
                attr_.precise_ip, attr_.mmap_data);

  PrintIndented(indent + 2, "sample_id_all %llu, exclude_host %llu, exclude_guest %llu\n",
                attr_.sample_id_all, attr_.exclude_host, attr_.exclude_guest);
}
