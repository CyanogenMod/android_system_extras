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

#include <libgen.h>
#include <poll.h>
#include <signal.h>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <base/logging.h>
#include <base/strings.h>

#include "command.h"
#include "environment.h"
#include "event_selection_set.h"
#include "event_type.h"
#include "read_elf.h"
#include "record.h"
#include "record_file.h"
#include "utils.h"
#include "workload.h"

static std::string default_measured_event_type = "cpu-cycles";

static std::unordered_map<std::string, uint64_t> branch_sampling_type_map = {
    {"u", PERF_SAMPLE_BRANCH_USER},
    {"k", PERF_SAMPLE_BRANCH_KERNEL},
    {"any", PERF_SAMPLE_BRANCH_ANY},
    {"any_call", PERF_SAMPLE_BRANCH_ANY_CALL},
    {"any_ret", PERF_SAMPLE_BRANCH_ANY_RETURN},
    {"ind_call", PERF_SAMPLE_BRANCH_IND_CALL},
};

static volatile bool signaled;
static void signal_handler(int) {
  signaled = true;
}

class RecordCommand : public Command {
 public:
  RecordCommand()
      : Command(
            "record", "record sampling info in perf.data",
            "Usage: simpleperf record [options] [command [command-args]]\n"
            "    Gather sampling information when running [command].\n"
            "    -a           System-wide collection.\n"
            "    -b           Enable take branch stack sampling. Same as '-j any'\n"
            "    -c count     Set event sample period.\n"
            "    -e event     Select the event to sample (Use `simpleperf list`)\n"
            "                 to find all possible event names.\n"
            "    -f freq      Set event sample frequency.\n"
            "    -F freq      Same as '-f freq'.\n"
            "    -g           Enables call-graph recording.\n"
            "    -j branch_filter1,branch_filter2,...\n"
            "                 Enable taken branch stack sampling. Each sample\n"
            "                 captures a series of consecutive taken branches.\n"
            "                 The following filters are defined:\n"
            "                   any: any type of branch\n"
            "                   any_call: any function call or system call\n"
            "                   any_ret: any function return or system call return\n"
            "                   ind_call: any indirect branch\n"
            "                   u: only when the branch target is at the user level\n"
            "                   k: only when the branch target is in the kernel\n"
            "                 This option requires at least one branch type among any,\n"
            "                 any_call, any_ret, ind_call.\n"
            "    -o record_file_name    Set record file name, default is perf.data.\n"
            "    -p pid1,pid2,...\n"
            "                 Record events on existing processes. Mutually exclusive with -a.\n"
            "    -t tid1,tid2,...\n"
            "                 Record events on existing threads. Mutually exclusive with -a.\n"),
        use_sample_freq_(true),
        sample_freq_(4000),
        system_wide_collection_(false),
        branch_sampling_(0),
        callchain_sampling_(false),
        measured_event_type_(nullptr),
        perf_mmap_pages_(256),
        record_filename_("perf.data") {
    signaled = false;
    signal_handler_register_.reset(
        new SignalHandlerRegister({SIGCHLD, SIGINT, SIGTERM}, signal_handler));
  }

  bool Run(const std::vector<std::string>& args);

  static bool ReadMmapDataCallback(const char* data, size_t size);

 private:
  bool ParseOptions(const std::vector<std::string>& args, std::vector<std::string>* non_option_args);
  bool SetMeasuredEventType(const std::string& event_type_name);
  bool SetEventSelection();
  bool WriteData(const char* data, size_t size);
  bool DumpKernelAndModuleMmaps();
  bool DumpThreadCommAndMmaps();
  bool DumpAdditionalFeatures();
  bool DumpBuildIdFeature();

  bool use_sample_freq_;    // Use sample_freq_ when true, otherwise using sample_period_.
  uint64_t sample_freq_;    // Sample 'sample_freq_' times per second.
  uint64_t sample_period_;  // Sample once when 'sample_period_' events occur.

  bool system_wide_collection_;
  std::vector<pid_t> monitored_threads_;
  uint64_t branch_sampling_;
  bool callchain_sampling_;
  const EventType* measured_event_type_;
  EventSelectionSet event_selection_set_;

  // mmap pages used by each perf event file, should be power of 2.
  const size_t perf_mmap_pages_;

  std::string record_filename_;
  std::unique_ptr<RecordFileWriter> record_file_writer_;

  std::unique_ptr<SignalHandlerRegister> signal_handler_register_;
};

bool RecordCommand::Run(const std::vector<std::string>& args) {
  // 1. Parse options, and use default measured event type if not given.
  std::vector<std::string> workload_args;
  if (!ParseOptions(args, &workload_args)) {
    return false;
  }
  if (measured_event_type_ == nullptr) {
    if (!SetMeasuredEventType(default_measured_event_type)) {
      return false;
    }
  }
  if (!SetEventSelection()) {
    return false;
  }

  // 2. Create workload.
  std::unique_ptr<Workload> workload;
  if (!workload_args.empty()) {
    workload = Workload::CreateWorkload(workload_args);
    if (workload == nullptr) {
      return false;
    }
  }
  if (!system_wide_collection_ && monitored_threads_.empty()) {
    if (workload != nullptr) {
      monitored_threads_.push_back(workload->GetPid());
      event_selection_set_.SetEnableOnExec(true);
    } else {
      LOG(ERROR) << "No threads to monitor. Try `simpleperf help record` for help\n";
      return false;
    }
  }

  // 3. Open perf_event_files, create memory mapped buffers for perf_event_files, add prepare poll
  //    for perf_event_files.
  if (system_wide_collection_) {
    if (!event_selection_set_.OpenEventFilesForAllCpus()) {
      return false;
    }
  } else {
    if (!event_selection_set_.OpenEventFilesForThreads(monitored_threads_)) {
      return false;
    }
  }
  if (!event_selection_set_.MmapEventFiles(perf_mmap_pages_)) {
    return false;
  }
  std::vector<pollfd> pollfds;
  event_selection_set_.PreparePollForEventFiles(&pollfds);

  // 4. Open record file writer, and dump kernel/modules/threads mmap information.
  record_file_writer_ = RecordFileWriter::CreateInstance(
      record_filename_, event_selection_set_.FindEventAttrByType(*measured_event_type_),
      event_selection_set_.FindEventFdsByType(*measured_event_type_));
  if (record_file_writer_ == nullptr) {
    return false;
  }
  if (!DumpKernelAndModuleMmaps()) {
    return false;
  }
  if (system_wide_collection_ && !DumpThreadCommAndMmaps()) {
    return false;
  }

  // 5. Write records in mmap buffers of perf_event_files to output file while workload is running.
  if (!event_selection_set_.GetEnableOnExec()) {
    if (!event_selection_set_.EnableEvents()) {
      return false;
    }
  }
  if (workload != nullptr && !workload->Start()) {
    return false;
  }
  auto callback =
      std::bind(&RecordCommand::WriteData, this, std::placeholders::_1, std::placeholders::_2);
  while (true) {
    if (!event_selection_set_.ReadMmapEventData(callback)) {
      return false;
    }
    if (signaled) {
      break;
    }
    poll(&pollfds[0], pollfds.size(), -1);
  }

  // 6. Dump additional features, and close record file.
  if (!DumpAdditionalFeatures()) {
    return false;
  }
  if (!record_file_writer_->Close()) {
    return false;
  }
  return true;
}

bool RecordCommand::ParseOptions(const std::vector<std::string>& args,
                                 std::vector<std::string>* non_option_args) {
  std::set<pid_t> tid_set;
  size_t i;
  for (i = 0; i < args.size() && args[i].size() > 0 && args[i][0] == '-'; ++i) {
    if (args[i] == "-a") {
      system_wide_collection_ = true;
    } else if (args[i] == "-b") {
      branch_sampling_ = branch_sampling_type_map["any"];
    } else if (args[i] == "-c") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      char* endptr;
      sample_period_ = strtoull(args[i].c_str(), &endptr, 0);
      if (*endptr != '\0' || sample_period_ == 0) {
        LOG(ERROR) << "Invalid sample period: '" << args[i] << "'";
        return false;
      }
      use_sample_freq_ = false;
    } else if (args[i] == "-e") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      if (!SetMeasuredEventType(args[i])) {
        return false;
      }
    } else if (args[i] == "-f" || args[i] == "-F") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      char* endptr;
      sample_freq_ = strtoull(args[i].c_str(), &endptr, 0);
      if (*endptr != '\0' || sample_freq_ == 0) {
        LOG(ERROR) << "Invalid sample frequency: '" << args[i] << "'";
        return false;
      }
      use_sample_freq_ = true;
    } else if (args[i] == "-g") {
      callchain_sampling_ = true;
    } else if (args[i] == "-j") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      std::vector<std::string> branch_sampling_types = android::base::Split(args[i], ",");
      for (auto& type : branch_sampling_types) {
        auto it = branch_sampling_type_map.find(type);
        if (it == branch_sampling_type_map.end()) {
          LOG(ERROR) << "unrecognized branch sampling filter: " << type;
          return false;
        }
        branch_sampling_ |= it->second;
      }
    } else if (args[i] == "-o") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      record_filename_ = args[i];
    } else if (args[i] == "-p") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      if (!GetValidThreadsFromProcessString(args[i], &tid_set)) {
        return false;
      }
    } else if (args[i] == "-t") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      if (!GetValidThreadsFromThreadString(args[i], &tid_set)) {
        return false;
      }
    } else {
      ReportUnknownOption(args, i);
      return false;
    }
  }

  monitored_threads_.insert(monitored_threads_.end(), tid_set.begin(), tid_set.end());
  if (system_wide_collection_ && !monitored_threads_.empty()) {
    LOG(ERROR)
        << "Record system wide and existing processes/threads can't be used at the same time.";
    return false;
  }

  if (non_option_args != nullptr) {
    non_option_args->clear();
    for (; i < args.size(); ++i) {
      non_option_args->push_back(args[i]);
    }
  }
  return true;
}

bool RecordCommand::SetMeasuredEventType(const std::string& event_type_name) {
  const EventType* event_type = EventTypeFactory::FindEventTypeByName(event_type_name);
  if (event_type == nullptr) {
    return false;
  }
  measured_event_type_ = event_type;
  return true;
}

bool RecordCommand::SetEventSelection() {
  event_selection_set_.AddEventType(*measured_event_type_);
  if (use_sample_freq_) {
    event_selection_set_.SetSampleFreq(sample_freq_);
  } else {
    event_selection_set_.SetSamplePeriod(sample_period_);
  }
  event_selection_set_.SampleIdAll();
  if (!event_selection_set_.SetBranchSampling(branch_sampling_)) {
    return false;
  }
  if (callchain_sampling_) {
    event_selection_set_.EnableCallChainSampling();
  }
  return true;
}

bool RecordCommand::WriteData(const char* data, size_t size) {
  return record_file_writer_->WriteData(data, size);
}

bool RecordCommand::DumpKernelAndModuleMmaps() {
  KernelMmap kernel_mmap;
  std::vector<ModuleMmap> module_mmaps;
  if (!GetKernelAndModuleMmaps(&kernel_mmap, &module_mmaps)) {
    return false;
  }
  const perf_event_attr& attr = event_selection_set_.FindEventAttrByType(*measured_event_type_);
  MmapRecord mmap_record = CreateMmapRecord(attr, true, UINT_MAX, 0, kernel_mmap.start_addr,
                                            kernel_mmap.len, kernel_mmap.pgoff, kernel_mmap.name);
  if (!record_file_writer_->WriteData(mmap_record.BinaryFormat())) {
    return false;
  }
  for (auto& module_mmap : module_mmaps) {
    std::string filename = module_mmap.filepath;
    if (filename.empty()) {
      filename = "[" + module_mmap.name + "]";
    }
    MmapRecord mmap_record = CreateMmapRecord(attr, true, UINT_MAX, 0, module_mmap.start_addr,
                                              module_mmap.len, 0, filename);
    if (!record_file_writer_->WriteData(mmap_record.BinaryFormat())) {
      return false;
    }
  }
  return true;
}

bool RecordCommand::DumpThreadCommAndMmaps() {
  std::vector<ThreadComm> thread_comms;
  if (!GetThreadComms(&thread_comms)) {
    return false;
  }
  const perf_event_attr& attr = event_selection_set_.FindEventAttrByType(*measured_event_type_);
  for (auto& thread : thread_comms) {
    CommRecord record = CreateCommRecord(attr, thread.tgid, thread.tid, thread.comm);
    if (!record_file_writer_->WriteData(record.BinaryFormat())) {
      return false;
    }
    if (thread.is_process) {
      std::vector<ThreadMmap> thread_mmaps;
      if (!GetThreadMmapsInProcess(thread.tgid, &thread_mmaps)) {
        // The thread may exit before we get its info.
        continue;
      }
      for (auto& thread_mmap : thread_mmaps) {
        if (thread_mmap.executable == 0) {
          continue;  // No need to dump non-executable mmap info.
        }
        MmapRecord record =
            CreateMmapRecord(attr, false, thread.tgid, thread.tid, thread_mmap.start_addr,
                             thread_mmap.len, thread_mmap.pgoff, thread_mmap.name);
        if (!record_file_writer_->WriteData(record.BinaryFormat())) {
          return false;
        }
      }
    }
  }
  return true;
}

bool RecordCommand::DumpAdditionalFeatures() {
  size_t feature_count = (branch_sampling_ != 0 ? 2 : 1);
  if (!record_file_writer_->WriteFeatureHeader(feature_count)) {
    return false;
  }
  if (!DumpBuildIdFeature()) {
    return false;
  }
  if (branch_sampling_ != 0 && !record_file_writer_->WriteBranchStackFeature()) {
    return false;
  }
  return true;
}

bool RecordCommand::DumpBuildIdFeature() {
  std::vector<std::string> hit_kernel_modules;
  std::vector<std::string> hit_user_files;
  if (!record_file_writer_->GetHitModules(&hit_kernel_modules, &hit_user_files)) {
    return false;
  }
  std::vector<BuildIdRecord> build_id_records;
  BuildId build_id;
  // Add build_ids for kernel/modules.
  for (auto& filename : hit_kernel_modules) {
    if (filename == DEFAULT_KERNEL_MMAP_NAME) {
      if (!GetKernelBuildId(&build_id)) {
        LOG(DEBUG) << "can't read build_id for kernel";
        continue;
      }
      build_id_records.push_back(
          CreateBuildIdRecord(true, UINT_MAX, build_id, DEFAULT_KERNEL_FILENAME_FOR_BUILD_ID));
    } else {
      std::string module_name = basename(&filename[0]);
      if (android::base::EndsWith(module_name, ".ko")) {
        module_name = module_name.substr(0, module_name.size() - 3);
      }
      if (!GetModuleBuildId(module_name, &build_id)) {
        LOG(DEBUG) << "can't read build_id for module " << module_name;
        continue;
      }
      build_id_records.push_back(CreateBuildIdRecord(true, UINT_MAX, build_id, filename));
    }
  }
  // Add build_ids for user elf files.
  for (auto& filename : hit_user_files) {
    if (filename == DEFAULT_EXECNAME_FOR_THREAD_MMAP) {
      continue;
    }
    if (!GetBuildIdFromElfFile(filename, &build_id)) {
      LOG(DEBUG) << "can't read build_id from file " << filename;
      continue;
    }
    build_id_records.push_back(CreateBuildIdRecord(false, UINT_MAX, build_id, filename));
  }
  if (!record_file_writer_->WriteBuildIdFeature(build_id_records)) {
    return false;
  }
  return true;
}

__attribute__((constructor)) static void RegisterRecordCommand() {
  RegisterCommand("record", [] { return std::unique_ptr<Command>(new RecordCommand()); });
}
