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
#include <sys/utsname.h>
#include <unistd.h>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <android-base/logging.h>
#include <android-base/strings.h>

#include "command.h"
#include "dwarf_unwind.h"
#include "environment.h"
#include "event_selection_set.h"
#include "event_type.h"
#include "read_apk.h"
#include "read_elf.h"
#include "record.h"
#include "record_file.h"
#include "scoped_signal_handler.h"
#include "thread_tree.h"
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

// Used in cpu-hotplug test.
bool system_wide_perf_event_open_failed = false;

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
            "    --call-graph fp | dwarf[,<dump_stack_size>]\n"
            "                 Enable call graph recording. Use frame pointer or dwarf as the\n"
            "                 method to parse call graph in stack. Default is dwarf,8192.\n"
            "    --cpu cpu_item1,cpu_item2,...\n"
            "                 Collect samples only on the selected cpus. cpu_item can be cpu\n"
            "                 number like 1, or cpu range like 0-3.\n"
            "    -e event1[:modifier1],event2[:modifier2],...\n"
            "                 Select the event list to sample. Use `simpleperf list` to find\n"
            "                 all possible event names. Modifiers can be added to define\n"
            "                 how the event should be monitored. Possible modifiers are:\n"
            "                   u - monitor user space events only\n"
            "                   k - monitor kernel space events only\n"
            "    -f freq      Set event sample frequency.\n"
            "    -F freq      Same as '-f freq'.\n"
            "    -g           Same as '--call-graph dwarf'.\n"
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
            "    -m mmap_pages\n"
            "                 Set the size of the buffer used to receiving sample data from\n"
            "                 the kernel. It should be a power of 2. The default value is 16.\n"
            "    --no-inherit\n"
            "                 Don't record created child threads/processes.\n"
            "    --no-unwind  If `--call-graph dwarf` option is used, then the user's stack will\n"
            "                 be unwound by default. Use this option to disable the unwinding of\n"
            "                 the user's stack.\n"
            "    -o record_file_name    Set record file name, default is perf.data.\n"
            "    -p pid1,pid2,...\n"
            "                 Record events on existing processes. Mutually exclusive with -a.\n"
            "    --post-unwind\n"
            "                 If `--call-graph dwarf` option is used, then the user's stack will\n"
            "                 be unwound while recording by default. But it may lose records as\n"
            "                 stacking unwinding can be time consuming. Use this option to unwind\n"
            "                 the user's stack after recording.\n"
            "    -t tid1,tid2,...\n"
            "                 Record events on existing threads. Mutually exclusive with -a.\n"),
        use_sample_freq_(true),
        sample_freq_(4000),
        system_wide_collection_(false),
        branch_sampling_(0),
        fp_callchain_sampling_(false),
        dwarf_callchain_sampling_(false),
        dump_stack_size_in_dwarf_sampling_(8192),
        unwind_dwarf_callchain_(true),
        post_unwind_(false),
        child_inherit_(true),
        perf_mmap_pages_(16),
        record_filename_("perf.data"),
        sample_record_count_(0) {
    signaled = false;
    scoped_signal_handler_.reset(
        new ScopedSignalHandler({SIGCHLD, SIGINT, SIGTERM}, signal_handler));
  }

  bool Run(const std::vector<std::string>& args);

  static bool ReadMmapDataCallback(const char* data, size_t size);

 private:
  bool ParseOptions(const std::vector<std::string>& args, std::vector<std::string>* non_option_args);
  bool AddMeasuredEventType(const std::string& event_type_name);
  bool SetEventSelection();
  bool CreateAndInitRecordFile();
  std::unique_ptr<RecordFileWriter> CreateRecordFile(const std::string& filename);
  bool DumpKernelAndModuleMmaps();
  bool DumpThreadCommAndMmaps(bool all_threads, const std::vector<pid_t>& selected_threads);
  bool CollectRecordsFromKernel(const char* data, size_t size);
  bool ProcessRecord(Record* record);
  void UpdateRecordForEmbeddedElfPath(Record* record);
  void UnwindRecord(Record* record);
  bool PostUnwind(const std::vector<std::string>& args);
  bool DumpAdditionalFeatures(const std::vector<std::string>& args);
  bool DumpBuildIdFeature();
  void CollectHitFileInfo(Record* record);
  std::pair<std::string, uint64_t> TestForEmbeddedElf(Dso *dso, uint64_t pgoff);

  bool use_sample_freq_;    // Use sample_freq_ when true, otherwise using sample_period_.
  uint64_t sample_freq_;    // Sample 'sample_freq_' times per second.
  uint64_t sample_period_;  // Sample once when 'sample_period_' events occur.

  bool system_wide_collection_;
  uint64_t branch_sampling_;
  bool fp_callchain_sampling_;
  bool dwarf_callchain_sampling_;
  uint32_t dump_stack_size_in_dwarf_sampling_;
  bool unwind_dwarf_callchain_;
  bool post_unwind_;
  bool child_inherit_;
  std::vector<pid_t> monitored_threads_;
  std::vector<int> cpus_;
  std::vector<EventTypeAndModifier> measured_event_types_;
  EventSelectionSet event_selection_set_;

  // mmap pages used by each perf event file, should be a power of 2.
  size_t perf_mmap_pages_;

  std::unique_ptr<RecordCache> record_cache_;
  ThreadTree thread_tree_;
  std::string record_filename_;
  std::unique_ptr<RecordFileWriter> record_file_writer_;

  std::set<std::string> hit_kernel_modules_;
  std::set<std::string> hit_user_files_;

  std::unique_ptr<ScopedSignalHandler> scoped_signal_handler_;
  uint64_t sample_record_count_;
};

bool RecordCommand::Run(const std::vector<std::string>& args) {
  if (!CheckPerfEventLimit()) {
    return false;
  }

  // 1. Parse options, and use default measured event type if not given.
  std::vector<std::string> workload_args;
  if (!ParseOptions(args, &workload_args)) {
    return false;
  }
  if (measured_event_types_.empty()) {
    if (!AddMeasuredEventType(default_measured_event_type)) {
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
    if (!event_selection_set_.OpenEventFilesForCpus(cpus_)) {
      system_wide_perf_event_open_failed = true;
      return false;
    }
  } else {
    if (!event_selection_set_.OpenEventFilesForThreadsOnCpus(monitored_threads_, cpus_)) {
      return false;
    }
  }
  if (!event_selection_set_.MmapEventFiles(perf_mmap_pages_)) {
    return false;
  }
  std::vector<pollfd> pollfds;
  event_selection_set_.PreparePollForEventFiles(&pollfds);

  // 4. Create perf.data.
  if (!CreateAndInitRecordFile()) {
    return false;
  }

  // 5. Write records in mmap buffers of perf_event_files to output file while workload is running.
  if (workload != nullptr && !workload->Start()) {
    return false;
  }
  record_cache_.reset(
      new RecordCache(*event_selection_set_.FindEventAttrByType(measured_event_types_[0])));
  auto callback = std::bind(&RecordCommand::CollectRecordsFromKernel, this, std::placeholders::_1,
                            std::placeholders::_2);
  while (true) {
    if (!event_selection_set_.ReadMmapEventData(callback)) {
      return false;
    }
    if (signaled) {
      break;
    }
    poll(&pollfds[0], pollfds.size(), -1);
  }
  std::vector<std::unique_ptr<Record>> records = record_cache_->PopAll();
  for (auto& r : records) {
    if (!ProcessRecord(r.get())) {
      return false;
    }
  }

  // 6. Dump additional features, and close record file.
  if (!DumpAdditionalFeatures(args)) {
    return false;
  }
  if (!record_file_writer_->Close()) {
    return false;
  }

  // 7. Unwind dwarf callchain.
  if (post_unwind_) {
    if (!PostUnwind(args)) {
      return false;
    }
  }
  LOG(VERBOSE) << "Record " << sample_record_count_ << " samples.";
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
    } else if (args[i] == "--call-graph") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      std::vector<std::string> strs = android::base::Split(args[i], ",");
      if (strs[0] == "fp") {
        fp_callchain_sampling_ = true;
        dwarf_callchain_sampling_ = false;
      } else if (strs[0] == "dwarf") {
        fp_callchain_sampling_ = false;
        dwarf_callchain_sampling_ = true;
        if (strs.size() > 1) {
          char* endptr;
          uint64_t size = strtoull(strs[1].c_str(), &endptr, 0);
          if (*endptr != '\0' || size > UINT_MAX) {
            LOG(ERROR) << "invalid dump stack size in --call-graph option: " << strs[1];
            return false;
          }
          if ((size & 7) != 0) {
            LOG(ERROR) << "dump stack size " << size << " is not 8-byte aligned.";
            return false;
          }
          dump_stack_size_in_dwarf_sampling_ = static_cast<uint32_t>(size);
        }
      } else {
        LOG(ERROR) << "unexpected argument for --call-graph option: " << args[i];
        return false;
      }
    } else if (args[i] == "--cpu") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      cpus_ = GetCpusFromString(args[i]);
    } else if (args[i] == "-e") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      std::vector<std::string> event_types = android::base::Split(args[i], ",");
      for (auto& event_type : event_types) {
        if (!AddMeasuredEventType(event_type)) {
          return false;
        }
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
      fp_callchain_sampling_ = false;
      dwarf_callchain_sampling_ = true;
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
    } else if (args[i] == "-m") {
      if (!NextArgumentOrError(args, &i)) {
        return false;
      }
      char* endptr;
      uint64_t pages = strtoull(args[i].c_str(), &endptr, 0);
      if (*endptr != '\0' || !IsPowerOfTwo(pages)) {
        LOG(ERROR) << "Invalid mmap_pages: '" << args[i] << "'";
        return false;
      }
      perf_mmap_pages_ = pages;
    } else if (args[i] == "--no-inherit") {
      child_inherit_ = false;
    } else if (args[i] == "--no-unwind") {
      unwind_dwarf_callchain_ = false;
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
    } else if (args[i] == "--post-unwind") {
      post_unwind_ = true;
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

  if (!dwarf_callchain_sampling_) {
    if (!unwind_dwarf_callchain_) {
      LOG(ERROR) << "--no-unwind is only used with `--call-graph dwarf` option.";
      return false;
    }
    unwind_dwarf_callchain_ = false;
  }
  if (post_unwind_) {
    if (!dwarf_callchain_sampling_) {
      LOG(ERROR) << "--post-unwind is only used with `--call-graph dwarf` option.";
      return false;
    }
    if (!unwind_dwarf_callchain_) {
      LOG(ERROR) << "--post-unwind can't be used with `--no-unwind` option.";
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

bool RecordCommand::AddMeasuredEventType(const std::string& event_type_name) {
  std::unique_ptr<EventTypeAndModifier> event_type_modifier = ParseEventType(event_type_name);
  if (event_type_modifier == nullptr) {
    return false;
  }
  measured_event_types_.push_back(*event_type_modifier);
  return true;
}

bool RecordCommand::SetEventSelection() {
  for (auto& event_type : measured_event_types_) {
    if (!event_selection_set_.AddEventType(event_type)) {
      return false;
    }
  }
  if (use_sample_freq_) {
    event_selection_set_.SetSampleFreq(sample_freq_);
  } else {
    event_selection_set_.SetSamplePeriod(sample_period_);
  }
  event_selection_set_.SampleIdAll();
  if (!event_selection_set_.SetBranchSampling(branch_sampling_)) {
    return false;
  }
  if (fp_callchain_sampling_) {
    event_selection_set_.EnableFpCallChainSampling();
  } else if (dwarf_callchain_sampling_) {
    if (!event_selection_set_.EnableDwarfCallChainSampling(dump_stack_size_in_dwarf_sampling_)) {
      return false;
    }
  }
  event_selection_set_.SetInherit(child_inherit_);
  return true;
}

bool RecordCommand::CreateAndInitRecordFile() {
  record_file_writer_ = CreateRecordFile(record_filename_);
  if (record_file_writer_ == nullptr) {
    return false;
  }
  if (!DumpKernelAndModuleMmaps()) {
    return false;
  }
  if (!DumpThreadCommAndMmaps(system_wide_collection_, monitored_threads_)) {
    return false;
  }
  return true;
}

std::unique_ptr<RecordFileWriter> RecordCommand::CreateRecordFile(const std::string& filename) {
  std::unique_ptr<RecordFileWriter> writer = RecordFileWriter::CreateInstance(filename);
  if (writer == nullptr) {
    return nullptr;
  }

  std::vector<AttrWithId> attr_ids;
  for (auto& event_type : measured_event_types_) {
    AttrWithId attr_id;
    attr_id.attr = event_selection_set_.FindEventAttrByType(event_type);
    CHECK(attr_id.attr != nullptr);
    const std::vector<std::unique_ptr<EventFd>>* fds =
        event_selection_set_.FindEventFdsByType(event_type);
    CHECK(fds != nullptr);
    for (auto& fd : *fds) {
      attr_id.ids.push_back(fd->Id());
    }
    attr_ids.push_back(attr_id);
  }
  if (!writer->WriteAttrSection(attr_ids)) {
    return nullptr;
  }
  return writer;
}

bool RecordCommand::DumpKernelAndModuleMmaps() {
  KernelMmap kernel_mmap;
  std::vector<KernelMmap> module_mmaps;
  GetKernelAndModuleMmaps(&kernel_mmap, &module_mmaps);

  const perf_event_attr* attr = event_selection_set_.FindEventAttrByType(measured_event_types_[0]);
  CHECK(attr != nullptr);
  MmapRecord mmap_record = CreateMmapRecord(*attr, true, UINT_MAX, 0, kernel_mmap.start_addr,
                                            kernel_mmap.len, 0, kernel_mmap.filepath);
  if (!ProcessRecord(&mmap_record)) {
    return false;
  }
  for (auto& module_mmap : module_mmaps) {
    MmapRecord mmap_record = CreateMmapRecord(*attr, true, UINT_MAX, 0, module_mmap.start_addr,
                                              module_mmap.len, 0, module_mmap.filepath);
    if (!ProcessRecord(&mmap_record)) {
      return false;
    }
  }
  return true;
}

bool RecordCommand::DumpThreadCommAndMmaps(bool all_threads,
                                           const std::vector<pid_t>& selected_threads) {
  std::vector<ThreadComm> thread_comms;
  if (!GetThreadComms(&thread_comms)) {
    return false;
  }
  // Decide which processes and threads to dump.
  std::set<pid_t> dump_processes;
  std::set<pid_t> dump_threads;
  for (auto& tid : selected_threads) {
    dump_threads.insert(tid);
  }
  for (auto& thread : thread_comms) {
    if (dump_threads.find(thread.tid) != dump_threads.end()) {
      dump_processes.insert(thread.pid);
    }
  }

  const perf_event_attr* attr = event_selection_set_.FindEventAttrByType(measured_event_types_[0]);
  CHECK(attr != nullptr);

  // Dump processes.
  for (auto& thread : thread_comms) {
    if (thread.pid != thread.tid) {
      continue;
    }
    if (!all_threads && dump_processes.find(thread.pid) == dump_processes.end()) {
      continue;
    }
    CommRecord record = CreateCommRecord(*attr, thread.pid, thread.tid, thread.comm);
    if (!ProcessRecord(&record)) {
      return false;
    }
    std::vector<ThreadMmap> thread_mmaps;
    if (!GetThreadMmapsInProcess(thread.pid, &thread_mmaps)) {
      // The thread may exit before we get its info.
      continue;
    }
    for (auto& thread_mmap : thread_mmaps) {
      if (thread_mmap.executable == 0) {
        continue;  // No need to dump non-executable mmap info.
      }
      MmapRecord record =
          CreateMmapRecord(*attr, false, thread.pid, thread.tid, thread_mmap.start_addr,
                           thread_mmap.len, thread_mmap.pgoff, thread_mmap.name);
      if (!ProcessRecord(&record)) {
        return false;
      }
    }
  }

  // Dump threads.
  for (auto& thread : thread_comms) {
    if (thread.pid == thread.tid) {
      continue;
    }
    if (!all_threads && dump_threads.find(thread.tid) == dump_threads.end()) {
      continue;
    }
    ForkRecord fork_record = CreateForkRecord(*attr, thread.pid, thread.tid, thread.pid, thread.pid);
    if (!ProcessRecord(&fork_record)) {
      return false;
    }
    CommRecord comm_record = CreateCommRecord(*attr, thread.pid, thread.tid, thread.comm);
    if (!ProcessRecord(&comm_record)) {
      return false;
    }
  }
  return true;
}

bool RecordCommand::CollectRecordsFromKernel(const char* data, size_t size) {
  record_cache_->Push(data, size);
  while (true) {
    std::unique_ptr<Record> r = record_cache_->Pop();
    if (r == nullptr) {
      break;
    }
    if (!ProcessRecord(r.get())) {
      return false;
    }
  }
  return true;
}

bool RecordCommand::ProcessRecord(Record* record) {
  UpdateRecordForEmbeddedElfPath(record);
  BuildThreadTree(*record, &thread_tree_);
  CollectHitFileInfo(record);
  if (unwind_dwarf_callchain_ && !post_unwind_) {
    UnwindRecord(record);
  }
  if (record->type() == PERF_RECORD_SAMPLE) {
    sample_record_count_++;
  }
  bool result = record_file_writer_->WriteData(record->BinaryFormat());
  return result;
}

template<class RecordType>
void UpdateMmapRecordForEmbeddedElfPath(RecordType* record) {
  RecordType& r = *record;
  bool in_kernel = ((r.header.misc & PERF_RECORD_MISC_CPUMODE_MASK) == PERF_RECORD_MISC_KERNEL);
  if (!in_kernel && r.data.pgoff != 0) {
    // For the case of a shared library "foobar.so" embedded
    // inside an APK, we rewrite the original MMAP from
    // ["path.apk" offset=X] to ["path.apk!/foobar.so" offset=W]
    // so as to make the library name explicit. This update is
    // done here (as part of the record operation) as opposed to
    // on the host during the report, since we want to report
    // the correct library name even if the the APK in question
    // is not present on the host. The new offset W is
    // calculated to be with respect to the start of foobar.so,
    // not to the start of path.apk.
    EmbeddedElf* ee = ApkInspector::FindElfInApkByOffset(r.filename, r.data.pgoff);
    if (ee != nullptr) {
      // Compute new offset relative to start of elf in APK.
      r.data.pgoff -= ee->entry_offset();
      r.filename = GetUrlInApk(r.filename, ee->entry_name());
      r.AdjustSizeBasedOnData();
    }
  }
}

void RecordCommand::UpdateRecordForEmbeddedElfPath(Record* record) {
  if (record->type() == PERF_RECORD_MMAP) {
    UpdateMmapRecordForEmbeddedElfPath(static_cast<MmapRecord*>(record));
  } else if (record->type() == PERF_RECORD_MMAP2) {
    UpdateMmapRecordForEmbeddedElfPath(static_cast<Mmap2Record*>(record));
  }
}

void RecordCommand::UnwindRecord(Record* record) {
  if (record->type() == PERF_RECORD_SAMPLE) {
    SampleRecord& r = *static_cast<SampleRecord*>(record);
    if ((r.sample_type & PERF_SAMPLE_CALLCHAIN) && (r.sample_type & PERF_SAMPLE_REGS_USER) &&
        (r.regs_user_data.reg_mask != 0) && (r.sample_type & PERF_SAMPLE_STACK_USER) &&
        (!r.stack_user_data.data.empty())) {
      ThreadEntry* thread = thread_tree_.FindThreadOrNew(r.tid_data.pid, r.tid_data.tid);
      RegSet regs = CreateRegSet(r.regs_user_data.reg_mask, r.regs_user_data.regs);
      std::vector<char>& stack = r.stack_user_data.data;
      std::vector<uint64_t> unwind_ips = UnwindCallChain(GetBuildArch(), *thread, regs, stack);
      r.callchain_data.ips.push_back(PERF_CONTEXT_USER);
      r.callchain_data.ips.insert(r.callchain_data.ips.end(), unwind_ips.begin(), unwind_ips.end());
      r.regs_user_data.abi = 0;
      r.regs_user_data.reg_mask = 0;
      r.regs_user_data.regs.clear();
      r.stack_user_data.data.clear();
      r.stack_user_data.dyn_size = 0;
      r.AdjustSizeBasedOnData();
    }
  }
}

bool RecordCommand::PostUnwind(const std::vector<std::string>& args) {
  thread_tree_.Clear();
  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(record_filename_);
  if (reader == nullptr) {
    return false;
  }
  std::string tmp_filename = record_filename_ + ".tmp";
  record_file_writer_ = CreateRecordFile(tmp_filename);
  if (record_file_writer_ == nullptr) {
    return false;
  }
  bool result = reader->ReadDataSection(
      [this](std::unique_ptr<Record> record) {
        BuildThreadTree(*record, &thread_tree_);
        UnwindRecord(record.get());
        return record_file_writer_->WriteData(record->BinaryFormat());
      },
      false);
  if (!result) {
    return false;
  }
  if (!DumpAdditionalFeatures(args)) {
    return false;
  }
  if (!record_file_writer_->Close()) {
    return false;
  }

  if (unlink(record_filename_.c_str()) != 0) {
    PLOG(ERROR) << "failed to remove " << record_filename_;
    return false;
  }
  if (rename(tmp_filename.c_str(), record_filename_.c_str()) != 0) {
    PLOG(ERROR) << "failed to rename " << tmp_filename << " to " << record_filename_;
    return false;
  }
  return true;
}

bool RecordCommand::DumpAdditionalFeatures(const std::vector<std::string>& args) {
  size_t feature_count = (branch_sampling_ != 0 ? 5 : 4);
  if (!record_file_writer_->WriteFeatureHeader(feature_count)) {
    return false;
  }
  if (!DumpBuildIdFeature()) {
    return false;
  }
  utsname uname_buf;
  if (TEMP_FAILURE_RETRY(uname(&uname_buf)) != 0) {
    PLOG(ERROR) << "uname() failed";
    return false;
  }
  if (!record_file_writer_->WriteFeatureString(PerfFileFormat::FEAT_OSRELEASE, uname_buf.release)) {
    return false;
  }
  if (!record_file_writer_->WriteFeatureString(PerfFileFormat::FEAT_ARCH, uname_buf.machine)) {
    return false;
  }

  std::string exec_path = "simpleperf";
  GetExecPath(&exec_path);
  std::vector<std::string> cmdline;
  cmdline.push_back(exec_path);
  cmdline.push_back("record");
  cmdline.insert(cmdline.end(), args.begin(), args.end());
  if (!record_file_writer_->WriteCmdlineFeature(cmdline)) {
    return false;
  }
  if (branch_sampling_ != 0 && !record_file_writer_->WriteBranchStackFeature()) {
    return false;
  }
  return true;
}

bool RecordCommand::DumpBuildIdFeature() {
  std::vector<BuildIdRecord> build_id_records;
  BuildId build_id;
  // Add build_ids for kernel/modules.
  for (const auto& filename : hit_kernel_modules_) {
    if (filename == DEFAULT_KERNEL_FILENAME_FOR_BUILD_ID) {
      if (!GetKernelBuildId(&build_id)) {
        LOG(DEBUG) << "can't read build_id for kernel";
        continue;
      }
      build_id_records.push_back(
          CreateBuildIdRecord(true, UINT_MAX, build_id, DEFAULT_KERNEL_FILENAME_FOR_BUILD_ID));
    } else {
      std::string path = filename;
      std::string module_name = basename(&path[0]);
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
  for (const auto& filename : hit_user_files_) {
    if (filename == DEFAULT_EXECNAME_FOR_THREAD_MMAP) {
      continue;
    }
    auto tuple = SplitUrlInApk(filename);
    if (std::get<0>(tuple)) {
      if (!GetBuildIdFromApkFile(std::get<1>(tuple), std::get<2>(tuple), &build_id)) {
        LOG(DEBUG) << "can't read build_id from file " << filename;
        continue;
      }
    } else {
      if (!GetBuildIdFromElfFile(filename, &build_id)) {
        LOG(DEBUG) << "can't read build_id from file " << filename;
        continue;
      }
    }
    build_id_records.push_back(CreateBuildIdRecord(false, UINT_MAX, build_id, filename));
  }
  if (!record_file_writer_->WriteBuildIdFeature(build_id_records)) {
    return false;
  }
  return true;
}

void RecordCommand::CollectHitFileInfo(Record* record) {
  if (record->type() == PERF_RECORD_SAMPLE) {
    auto r = *static_cast<SampleRecord*>(record);
    bool in_kernel = ((r.header.misc & PERF_RECORD_MISC_CPUMODE_MASK) == PERF_RECORD_MISC_KERNEL);
    const ThreadEntry* thread = thread_tree_.FindThreadOrNew(r.tid_data.pid, r.tid_data.tid);
    const MapEntry* map = thread_tree_.FindMap(thread, r.ip_data.ip, in_kernel);
    if (in_kernel) {
      hit_kernel_modules_.insert(map->dso->Path());
    } else {
      hit_user_files_.insert(map->dso->Path());
    }
  }
}

void RegisterRecordCommand() {
  RegisterCommand("record", [] { return std::unique_ptr<Command>(new RecordCommand()); });
}
