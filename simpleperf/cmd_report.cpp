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

#include <inttypes.h>
#include <functional>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include <base/logging.h>
#include <base/stringprintf.h>
#include <base/strings.h>

#include "command.h"
#include "environment.h"
#include "event_attr.h"
#include "event_type.h"
#include "record.h"
#include "record_file.h"
#include "sample_tree.h"

typedef int (*compare_sample_entry_t)(const SampleEntry& sample1, const SampleEntry& sample2);
typedef std::string (*print_sample_entry_header_t)();
typedef std::string (*print_sample_entry_t)(const SampleEntry& sample);

struct ReportItem {
  size_t width;
  compare_sample_entry_t compare_function;
  print_sample_entry_header_t print_header_function;
  print_sample_entry_t print_function;
};

static int ComparePid(const SampleEntry& sample1, const SampleEntry& sample2) {
  return sample1.process->pid - sample2.process->pid;
}

static std::string PrintHeaderPid() {
  return "Pid";
}

static std::string PrintPid(const SampleEntry& sample) {
  return android::base::StringPrintf("%d", sample.process->pid);
}

static ReportItem report_pid = {
    .compare_function = ComparePid,
    .print_header_function = PrintHeaderPid,
    .print_function = PrintPid,
};

static int CompareComm(const SampleEntry& sample1, const SampleEntry& sample2) {
  return strcmp(sample1.process->comm.c_str(), sample2.process->comm.c_str());
}

static std::string PrintHeaderComm() {
  return "Command";
}

static std::string PrintComm(const SampleEntry& sample) {
  return sample.process->comm;
}

static ReportItem report_comm = {
    .compare_function = CompareComm,
    .print_header_function = PrintHeaderComm,
    .print_function = PrintComm,
};

static int CompareDso(const SampleEntry& sample1, const SampleEntry& sample2) {
  return strcmp(sample1.map->dso->path.c_str(), sample2.map->dso->path.c_str());
}

static std::string PrintHeaderDso() {
  return "Shared Object";
}

static std::string PrintDso(const SampleEntry& sample) {
  std::string filename = sample.map->dso->path;
  if (filename == DEFAULT_EXECNAME_FOR_THREAD_MMAP) {
    filename = "[unknown]";
  }
  return filename;
}

static ReportItem report_dso = {
    .compare_function = CompareDso,
    .print_header_function = PrintHeaderDso,
    .print_function = PrintDso,
};

static int CompareSymbol(const SampleEntry& sample1, const SampleEntry& sample2) {
  return strcmp(sample1.symbol->name.c_str(), sample2.symbol->name.c_str());
}

static std::string PrintHeaderSymbol() {
  return "Symbol";
}

static std::string PrintSymbol(const SampleEntry& sample) {
  return sample.symbol->name;
}

static ReportItem report_symbol = {
    .compare_function = CompareSymbol,
    .print_header_function = PrintHeaderSymbol,
    .print_function = PrintSymbol,
};

static std::string PrintHeaderSampleCount() {
  return "Sample";
}

static std::string PrintSampleCount(const SampleEntry& sample) {
  return android::base::StringPrintf("%" PRId64, sample.sample_count);
}

static ReportItem report_sample_count = {
    .compare_function = nullptr,
    .print_header_function = PrintHeaderSampleCount,
    .print_function = PrintSampleCount,
};

static std::unordered_map<std::string, ReportItem*> report_item_map = {
    {"comm", &report_comm}, {"pid", &report_pid}, {"dso", &report_dso}, {"symbol", &report_symbol},
};

class ReportCommand : public Command {
 public:
  ReportCommand()
      : Command("report", "report sampling information in perf.data",
                "Usage: simpleperf report [options]\n"
                "    -i <file>     Specify path of record file, default is perf.data.\n"
                "    -n            Print the sample count for each item.\n"
                "    --no-demangle        Don't demangle symbol names.\n"
                "    --sort key1,key2,... Select the keys to sort and print the report.\n"
                "                         Possible keys include pid, comm, dso, symbol.\n"
                "                         Default keys are \"comm,pid,dso\"\n"
                "    --symfs <dir>  Look for files with symbols relative to this directory.\n"),
        record_filename_("perf.data") {
  }

  bool Run(const std::vector<std::string>& args);

 private:
  bool ParseOptions(const std::vector<std::string>& args);
  bool ReadEventAttrFromRecordFile();
  void ReadSampleTreeFromRecordFile();
  int CompareSampleEntry(const SampleEntry& sample1, const SampleEntry& sample2);
  void PrintReport();
  void PrintReportContext();
  void CollectReportWidth();
  void CollectReportEntryWidth(const SampleEntry& sample);
  void PrintReportHeader();
  void PrintReportEntry(const SampleEntry& sample);

  std::string record_filename_;
  std::unique_ptr<RecordFileReader> record_file_reader_;
  perf_event_attr event_attr_;
  std::vector<ReportItem*> report_items_;
  std::unique_ptr<SampleTree> sample_tree_;
};

bool ReportCommand::Run(const std::vector<std::string>& args) {
  // 1. Parse options.
  if (!ParseOptions(args)) {
    return false;
  }

  // 2. Read record file and build SampleTree.
  record_file_reader_ = RecordFileReader::CreateInstance(record_filename_);
  if (record_file_reader_ == nullptr) {
    return false;
  }
  if (!ReadEventAttrFromRecordFile()) {
    return false;
  }
  ReadSampleTreeFromRecordFile();

  // 3. Read symbol table from elf files.

  // 4. Show collected information.
  PrintReport();

  return true;
}

bool ReportCommand::ParseOptions(const std::vector<std::string>& args) {
  bool print_sample_count = false;
  for (size_t i = 0; i < args.size(); ++i) {
    if (args[i] == "-i") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      record_filename_ = args[i];

    } else if (args[i] == "-n") {
      print_sample_count = true;

    } else if (args[i] == "--no-demangle") {
      DsoFactory::SetDemangle(false);

    } else if (args[i] == "--sort") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      std::vector<std::string> sort_keys = android::base::Split(args[i], ",");
      for (auto& key : sort_keys) {
        auto it = report_item_map.find(key);
        if (it != report_item_map.end()) {
          report_items_.push_back(it->second);
        } else {
          LOG(ERROR) << "Unknown sort key: " << key;
          return false;
        }
      }
    } else if (args[i] == "--symfs") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      if (!DsoFactory::SetSymFsDir(args[i])) {
        return false;
      }
    } else {
      ReportUnknownOption(args, i);
      return false;
    }
  }

  if (report_items_.empty()) {
    report_items_.push_back(report_item_map["comm"]);
    report_items_.push_back(report_item_map["pid"]);
    report_items_.push_back(report_item_map["dso"]);
  }
  if (print_sample_count) {
    report_items_.insert(report_items_.begin(), &report_sample_count);
  }
  return true;
}

bool ReportCommand::ReadEventAttrFromRecordFile() {
  std::vector<const PerfFileFormat::FileAttr*> attrs = record_file_reader_->AttrSection();
  if (attrs.size() != 1) {
    LOG(ERROR) << "record file contains " << attrs.size() << " attrs";
    return false;
  }
  event_attr_ = attrs[0]->attr;
  return true;
}

void ReportCommand::ReadSampleTreeFromRecordFile() {
  compare_sample_func_t compare_sample_callback = std::bind(
      &ReportCommand::CompareSampleEntry, this, std::placeholders::_1, std::placeholders::_2);
  sample_tree_ = std::unique_ptr<SampleTree>(new SampleTree(compare_sample_callback));
  sample_tree_->AddProcess(0, "swapper");

  std::vector<std::unique_ptr<const Record>> records = record_file_reader_->DataSection();
  for (auto& record : records) {
    if (record->header.type == PERF_RECORD_MMAP) {
      const MmapRecord& r = *static_cast<const MmapRecord*>(record.get());
      if ((r.header.misc & PERF_RECORD_MISC_CPUMODE_MASK) == PERF_RECORD_MISC_KERNEL) {
        sample_tree_->AddKernelMap(r.data.addr, r.data.len, r.data.pgoff,
                                   r.sample_id.time_data.time, r.filename);
      } else {
        sample_tree_->AddUserMap(r.data.pid, r.data.addr, r.data.len, r.data.pgoff,
                                 r.sample_id.time_data.time, r.filename);
      }
    } else if (record->header.type == PERF_RECORD_SAMPLE) {
      const SampleRecord& r = *static_cast<const SampleRecord*>(record.get());
      bool in_kernel = (r.header.misc & PERF_RECORD_MISC_CPUMODE_MASK) == PERF_RECORD_MISC_KERNEL;
      sample_tree_->AddSample(r.tid_data.pid, r.tid_data.tid, r.ip_data.ip, r.time_data.time,
                              r.period_data.period, in_kernel);
    } else if (record->header.type == PERF_RECORD_COMM) {
      const CommRecord& r = *static_cast<const CommRecord*>(record.get());
      sample_tree_->AddProcess(r.data.pid, r.comm);
    }
  }
}

int ReportCommand::CompareSampleEntry(const SampleEntry& sample1, const SampleEntry& sample2) {
  for (auto& item : report_items_) {
    if (item->compare_function != nullptr) {
      int result = item->compare_function(sample1, sample2);
      if (result != 0) {
        return result;
      }
    }
  }
  return 0;
}

void ReportCommand::PrintReport() {
  PrintReportContext();
  CollectReportWidth();
  PrintReportHeader();
  sample_tree_->VisitAllSamples(
      std::bind(&ReportCommand::PrintReportEntry, this, std::placeholders::_1));
  fflush(stdout);
}

void ReportCommand::PrintReportContext() {
  const EventType* event_type = FindEventTypeByConfig(event_attr_.type, event_attr_.config);
  std::string event_type_name;
  if (event_type != nullptr) {
    event_type_name = event_type->name;
  } else {
    event_type_name =
        android::base::StringPrintf("(type %u, config %llu)", event_attr_.type, event_attr_.config);
  }
  printf("Samples: %" PRIu64 " of event '%s'\n", sample_tree_->TotalSamples(),
         event_type_name.c_str());
  printf("Event count: %" PRIu64 "\n\n", sample_tree_->TotalPeriod());
}

void ReportCommand::CollectReportWidth() {
  for (auto& item : report_items_) {
    std::string s = item->print_header_function();
    item->width = s.size();
  }
  sample_tree_->VisitAllSamples(
      std::bind(&ReportCommand::CollectReportEntryWidth, this, std::placeholders::_1));
}

void ReportCommand::CollectReportEntryWidth(const SampleEntry& sample) {
  for (auto& item : report_items_) {
    std::string s = item->print_function(sample);
    item->width = std::max(item->width, s.size());
  }
}

void ReportCommand::PrintReportHeader() {
  printf("%8s", "Overhead");
  for (size_t i = 0; i < report_items_.size(); ++i) {
    auto& item = report_items_[i];
    printf("  ");
    std::string s = item->print_header_function();
    printf("%-*s", (i + 1 == report_items_.size()) ? 0 : static_cast<int>(item->width), s.c_str());
  }
  printf("\n");
}

void ReportCommand::PrintReportEntry(const SampleEntry& sample) {
  double percentage = 0.0;
  if (sample_tree_->TotalPeriod() != 0) {
    percentage = 100.0 * sample.period / sample_tree_->TotalPeriod();
  }
  printf("%7.2lf%%", percentage);
  for (size_t i = 0; i < report_items_.size(); ++i) {
    auto& item = report_items_[i];
    printf("  ");
    std::string s = item->print_function(sample);
    printf("%-*s", (i + 1 == report_items_.size()) ? 0 : static_cast<int>(item->width), s.c_str());
  }
  printf("\n");
}

__attribute__((constructor)) static void RegisterReportCommand() {
  RegisterCommand("report", [] { return std::unique_ptr<Command>(new ReportCommand()); });
}
