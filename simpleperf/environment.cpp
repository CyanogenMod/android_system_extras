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

#include "environment.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <limits>
#include <set>
#include <unordered_map>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android-base/stringprintf.h>

#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

#include "read_elf.h"
#include "utils.h"

class LineReader {
 public:
  LineReader(FILE* fp) : fp_(fp), buf_(nullptr), bufsize_(0) {
  }

  ~LineReader() {
    free(buf_);
    fclose(fp_);
  }

  char* ReadLine() {
    if (getline(&buf_, &bufsize_, fp_) != -1) {
      return buf_;
    }
    return nullptr;
  }

  size_t MaxLineSize() {
    return bufsize_;
  }

 private:
  FILE* fp_;
  char* buf_;
  size_t bufsize_;
};

std::vector<int> GetOnlineCpus() {
  std::vector<int> result;
  FILE* fp = fopen("/sys/devices/system/cpu/online", "re");
  if (fp == nullptr) {
    PLOG(ERROR) << "can't open online cpu information";
    return result;
  }

  LineReader reader(fp);
  char* line;
  if ((line = reader.ReadLine()) != nullptr) {
    result = GetCpusFromString(line);
  }
  CHECK(!result.empty()) << "can't get online cpu information";
  return result;
}

std::vector<int> GetCpusFromString(const std::string& s) {
  std::set<int> cpu_set;
  bool have_dash = false;
  const char* p = s.c_str();
  char* endp;
  int last_cpu;
  long cpu;
  // Parse line like: 0,1-3, 5, 7-8
  while ((cpu = strtol(p, &endp, 10)) != 0 || endp != p) {
    if (have_dash && !cpu_set.empty()) {
      for (int t = last_cpu + 1; t < cpu; ++t) {
        cpu_set.insert(t);
      }
    }
    have_dash = false;
    cpu_set.insert(cpu);
    last_cpu = cpu;
    p = endp;
    while (!isdigit(*p) && *p != '\0') {
      if (*p == '-') {
        have_dash = true;
      }
      ++p;
    }
  }
  return std::vector<int>(cpu_set.begin(), cpu_set.end());
}

bool ProcessKernelSymbols(const std::string& symbol_file,
                          std::function<bool(const KernelSymbol&)> callback) {
  FILE* fp = fopen(symbol_file.c_str(), "re");
  if (fp == nullptr) {
    PLOG(ERROR) << "failed to open file " << symbol_file;
    return false;
  }
  LineReader reader(fp);
  char* line;
  while ((line = reader.ReadLine()) != nullptr) {
    // Parse line like: ffffffffa005c4e4 d __warned.41698       [libsas]
    char name[reader.MaxLineSize()];
    char module[reader.MaxLineSize()];
    strcpy(module, "");

    KernelSymbol symbol;
    if (sscanf(line, "%" PRIx64 " %c %s%s", &symbol.addr, &symbol.type, name, module) < 3) {
      continue;
    }
    symbol.name = name;
    size_t module_len = strlen(module);
    if (module_len > 2 && module[0] == '[' && module[module_len - 1] == ']') {
      module[module_len - 1] = '\0';
      symbol.module = &module[1];
    } else {
      symbol.module = nullptr;
    }

    if (callback(symbol)) {
      return true;
    }
  }
  return false;
}

static std::vector<KernelMmap> GetLoadedModules() {
  std::vector<KernelMmap> result;
  FILE* fp = fopen("/proc/modules", "re");
  if (fp == nullptr) {
    // There is no /proc/modules on Android devices, so we don't print error if failed to open it.
    PLOG(DEBUG) << "failed to open file /proc/modules";
    return result;
  }
  LineReader reader(fp);
  char* line;
  while ((line = reader.ReadLine()) != nullptr) {
    // Parse line like: nf_defrag_ipv6 34768 1 nf_conntrack_ipv6, Live 0xffffffffa0fe5000
    char name[reader.MaxLineSize()];
    uint64_t addr;
    if (sscanf(line, "%s%*lu%*u%*s%*s 0x%" PRIx64, name, &addr) == 2) {
      KernelMmap map;
      map.name = name;
      map.start_addr = addr;
      result.push_back(map);
    }
  }
  return result;
}

static std::string GetLinuxVersion() {
  std::string content;
  if (android::base::ReadFileToString("/proc/version", &content)) {
    char s[content.size() + 1];
    if (sscanf(content.c_str(), "Linux version %s", s) == 1) {
      return s;
    }
  }
  PLOG(FATAL) << "can't read linux version";
  return "";
}

static void GetAllModuleFiles(const std::string& path,
                              std::unordered_map<std::string, std::string>* module_file_map) {
  std::vector<std::string> files;
  std::vector<std::string> subdirs;
  GetEntriesInDir(path, &files, &subdirs);
  for (auto& name : files) {
    if (android::base::EndsWith(name, ".ko")) {
      std::string module_name = name.substr(0, name.size() - 3);
      std::replace(module_name.begin(), module_name.end(), '-', '_');
      module_file_map->insert(std::make_pair(module_name, path + "/" + name));
    }
  }
  for (auto& name : subdirs) {
    GetAllModuleFiles(path + "/" + name, module_file_map);
  }
}

static std::vector<KernelMmap> GetModulesInUse() {
  // TODO: There is no /proc/modules or /lib/modules on Android, find methods work on it.
  std::vector<KernelMmap> module_mmaps = GetLoadedModules();
  std::string linux_version = GetLinuxVersion();
  std::string module_dirpath = "/lib/modules/" + linux_version + "/kernel";
  std::unordered_map<std::string, std::string> module_file_map;
  GetAllModuleFiles(module_dirpath, &module_file_map);
  for (auto& module : module_mmaps) {
    auto it = module_file_map.find(module.name);
    if (it != module_file_map.end()) {
      module.filepath = it->second;
    }
  }
  return module_mmaps;
}

void GetKernelAndModuleMmaps(KernelMmap* kernel_mmap, std::vector<KernelMmap>* module_mmaps) {
  kernel_mmap->name = DEFAULT_KERNEL_MMAP_NAME;
  kernel_mmap->start_addr = 0;
  kernel_mmap->filepath = kernel_mmap->name;
  *module_mmaps = GetModulesInUse();
  for (auto& map : *module_mmaps) {
    if (map.filepath.empty()) {
      map.filepath = "[" + map.name + "]";
    }
  }

  if (module_mmaps->size() == 0) {
    kernel_mmap->len = std::numeric_limits<unsigned long long>::max() - kernel_mmap->start_addr;
  } else {
    std::sort(
        module_mmaps->begin(), module_mmaps->end(),
        [](const KernelMmap& m1, const KernelMmap& m2) { return m1.start_addr < m2.start_addr; });
    // When not having enough privilege, all addresses are read as 0.
    if (kernel_mmap->start_addr == (*module_mmaps)[0].start_addr) {
      kernel_mmap->len = 0;
    } else {
      kernel_mmap->len = (*module_mmaps)[0].start_addr - kernel_mmap->start_addr - 1;
    }
    for (size_t i = 0; i + 1 < module_mmaps->size(); ++i) {
      if ((*module_mmaps)[i].start_addr == (*module_mmaps)[i + 1].start_addr) {
        (*module_mmaps)[i].len = 0;
      } else {
        (*module_mmaps)[i].len =
            (*module_mmaps)[i + 1].start_addr - (*module_mmaps)[i].start_addr - 1;
      }
    }
    module_mmaps->back().len =
        std::numeric_limits<unsigned long long>::max() - module_mmaps->back().start_addr;
  }
}

static bool ReadThreadNameAndTgid(const std::string& status_file, std::string* comm, pid_t* tgid) {
  FILE* fp = fopen(status_file.c_str(), "re");
  if (fp == nullptr) {
    return false;
  }
  bool read_comm = false;
  bool read_tgid = false;
  LineReader reader(fp);
  char* line;
  while ((line = reader.ReadLine()) != nullptr) {
    char s[reader.MaxLineSize()];
    if (sscanf(line, "Name:%s", s) == 1) {
      *comm = s;
      read_comm = true;
    } else if (sscanf(line, "Tgid:%d", tgid) == 1) {
      read_tgid = true;
    }
    if (read_comm && read_tgid) {
      return true;
    }
  }
  return false;
}

static std::vector<pid_t> GetThreadsInProcess(pid_t pid) {
  std::vector<pid_t> result;
  std::string task_dirname = android::base::StringPrintf("/proc/%d/task", pid);
  std::vector<std::string> subdirs;
  GetEntriesInDir(task_dirname, nullptr, &subdirs);
  for (const auto& name : subdirs) {
    int tid;
    if (!android::base::ParseInt(name.c_str(), &tid, 0)) {
      continue;
    }
    result.push_back(tid);
  }
  return result;
}

static bool GetThreadComm(pid_t pid, std::vector<ThreadComm>* thread_comms) {
  std::vector<pid_t> tids = GetThreadsInProcess(pid);
  for (auto& tid : tids) {
    std::string status_file = android::base::StringPrintf("/proc/%d/task/%d/status", pid, tid);
    std::string comm;
    pid_t tgid;
    // It is possible that the process or thread exited before we can read its status.
    if (!ReadThreadNameAndTgid(status_file, &comm, &tgid)) {
      continue;
    }
    CHECK_EQ(pid, tgid);
    ThreadComm thread;
    thread.tid = tid;
    thread.pid = pid;
    thread.comm = comm;
    thread_comms->push_back(thread);
  }
  return true;
}

bool GetThreadComms(std::vector<ThreadComm>* thread_comms) {
  thread_comms->clear();
  std::vector<std::string> subdirs;
  GetEntriesInDir("/proc", nullptr, &subdirs);
  for (auto& name : subdirs) {
    int pid;
    if (!android::base::ParseInt(name.c_str(), &pid, 0)) {
      continue;
    }
    if (!GetThreadComm(pid, thread_comms)) {
      return false;
    }
  }
  return true;
}

bool GetThreadMmapsInProcess(pid_t pid, std::vector<ThreadMmap>* thread_mmaps) {
  std::string map_file = android::base::StringPrintf("/proc/%d/maps", pid);
  FILE* fp = fopen(map_file.c_str(), "re");
  if (fp == nullptr) {
    PLOG(DEBUG) << "can't open file " << map_file;
    return false;
  }
  thread_mmaps->clear();
  LineReader reader(fp);
  char* line;
  while ((line = reader.ReadLine()) != nullptr) {
    // Parse line like: 00400000-00409000 r-xp 00000000 fc:00 426998  /usr/lib/gvfs/gvfsd-http
    uint64_t start_addr, end_addr, pgoff;
    char type[reader.MaxLineSize()];
    char execname[reader.MaxLineSize()];
    strcpy(execname, "");
    if (sscanf(line, "%" PRIx64 "-%" PRIx64 " %s %" PRIx64 " %*x:%*x %*u %s\n", &start_addr,
               &end_addr, type, &pgoff, execname) < 4) {
      continue;
    }
    if (strcmp(execname, "") == 0) {
      strcpy(execname, DEFAULT_EXECNAME_FOR_THREAD_MMAP);
    }
    ThreadMmap thread;
    thread.start_addr = start_addr;
    thread.len = end_addr - start_addr;
    thread.pgoff = pgoff;
    thread.name = execname;
    thread.executable = (type[2] == 'x');
    thread_mmaps->push_back(thread);
  }
  return true;
}

bool GetKernelBuildId(BuildId* build_id) {
  return GetBuildIdFromNoteFile("/sys/kernel/notes", build_id);
}

bool GetModuleBuildId(const std::string& module_name, BuildId* build_id) {
  std::string notefile = "/sys/module/" + module_name + "/notes/.note.gnu.build-id";
  return GetBuildIdFromNoteFile(notefile, build_id);
}

bool GetValidThreadsFromProcessString(const std::string& pid_str, std::set<pid_t>* tid_set) {
  std::vector<std::string> strs = android::base::Split(pid_str, ",");
  for (const auto& s : strs) {
    int pid;
    if (!android::base::ParseInt(s.c_str(), &pid, 0)) {
      LOG(ERROR) << "Invalid pid '" << s << "'";
      return false;
    }
    std::vector<pid_t> tids = GetThreadsInProcess(pid);
    if (tids.empty()) {
      LOG(ERROR) << "Non existing process '" << pid << "'";
      return false;
    }
    tid_set->insert(tids.begin(), tids.end());
  }
  return true;
}

bool GetValidThreadsFromThreadString(const std::string& tid_str, std::set<pid_t>* tid_set) {
  std::vector<std::string> strs = android::base::Split(tid_str, ",");
  for (const auto& s : strs) {
    int tid;
    if (!android::base::ParseInt(s.c_str(), &tid, 0)) {
      LOG(ERROR) << "Invalid tid '" << s << "'";
      return false;
    }
    if (!IsDir(android::base::StringPrintf("/proc/%d", tid))) {
      LOG(ERROR) << "Non existing thread '" << tid << "'";
      return false;
    }
    tid_set->insert(tid);
  }
  return true;
}

bool GetExecPath(std::string* exec_path) {
  char path[PATH_MAX];
  ssize_t path_len = readlink("/proc/self/exe", path, sizeof(path));
  if (path_len <= 0 || path_len >= static_cast<ssize_t>(sizeof(path))) {
    PLOG(ERROR) << "readlink failed";
    return false;
  }
  path[path_len] = '\0';
  *exec_path = path;
  return true;
}

/*
 * perf event paranoia level:
 *  -1 - not paranoid at all
 *   0 - disallow raw tracepoint access for unpriv
 *   1 - disallow cpu events for unpriv
 *   2 - disallow kernel profiling for unpriv
 *   3 - disallow user profiling for unpriv
 */
static bool ReadPerfEventParanoid(int* value) {
  std::string s;
  if (!android::base::ReadFileToString("/proc/sys/kernel/perf_event_paranoid", &s)) {
    PLOG(ERROR) << "failed to read /proc/sys/kernel/perf_event_paranoid";
    return false;
  }
  s = android::base::Trim(s);
  if (!android::base::ParseInt(s.c_str(), value)) {
    PLOG(ERROR) << "failed to parse /proc/sys/kernel/perf_event_paranoid: " << s;
    return false;
  }
  return true;
}

static const char* GetLimitLevelDescription(int limit_level) {
  switch (limit_level) {
    case -1: return "unlimited";
    case 0: return "disallowing raw tracepoint access for unpriv";
    case 1: return "disallowing cpu events for unpriv";
    case 2: return "disallowing kernel profiling for unpriv";
    case 3: return "disallowing user profiling for unpriv";
    default: return "unknown level";
  }
}

bool CheckPerfEventLimit() {
  // root is not limited by /proc/sys/kernel/perf_event_paranoid.
  if (IsRoot()) {
    return true;
  }
  int limit_level;
  if (!ReadPerfEventParanoid(&limit_level)) {
    return false;
  }
  if (limit_level <= 1) {
    return true;
  }
#if defined(__ANDROID__)
  // Try to enable perf_event_paranoid by setprop security.perf_harden=0.
  if (__system_property_set("security.perf_harden", "0") == 0) {
    sleep(1);
    if (ReadPerfEventParanoid(&limit_level) && limit_level <= 1) {
      return true;
    }
  }
  LOG(WARNING) << "/proc/sys/kernel/perf_event_paranoid is " << limit_level
      << ", " << GetLimitLevelDescription(limit_level) << ".";
  LOG(WARNING) << "Try using `adb shell setprop security.perf_harden 0` to allow profiling.";
#else
  LOG(WARNING) << "/proc/sys/kernel/perf_event_paranoid is " << limit_level
      << ", " << GetLimitLevelDescription(limit_level) << ".";
#endif
  return true;
}
