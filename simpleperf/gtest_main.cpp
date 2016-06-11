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

#include <gtest/gtest.h>

#include <memory>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/test_utils.h>
#include <ziparchive/zip_archive.h>

#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

#include "get_test_data.h"
#include "read_elf.h"
#include "utils.h"

static std::string testdata_dir;

#if defined(IN_CTS_TEST)
static const std::string testdata_section = ".testzipdata";

static bool ExtractTestDataFromElfSection() {
  if (!MkdirWithParents(testdata_dir)) {
    PLOG(ERROR) << "failed to create testdata_dir " << testdata_dir;
    return false;
  }
  std::string content;
  if (!ReadSectionFromElfFile("/proc/self/exe", testdata_section, &content)) {
    LOG(ERROR) << "failed to read section " << testdata_section;
    return false;
  }
  TemporaryFile tmp_file;
  if (!android::base::WriteStringToFile(content, tmp_file.path)) {
    PLOG(ERROR) << "failed to write file " << tmp_file.path;
    return false;
  }
  ArchiveHelper ahelper(tmp_file.fd, tmp_file.path);
  if (!ahelper) {
    LOG(ERROR) << "failed to open archive " << tmp_file.path;
    return false;
  }
  ZipArchiveHandle& handle = ahelper.archive_handle();
  void* cookie;
  int ret = StartIteration(handle, &cookie, nullptr, nullptr);
  if (ret != 0) {
    LOG(ERROR) << "failed to start iterating zip entries";
    return false;
  }
  std::unique_ptr<void, decltype(&EndIteration)> guard(cookie, EndIteration);
  ZipEntry entry;
  ZipString name;
  while (Next(cookie, &entry, &name) == 0) {
    std::string entry_name(name.name, name.name + name.name_length);
    std::string path = testdata_dir + entry_name;
    // Skip dir.
    if (path.back() == '/') {
      continue;
    }
    if (!MkdirWithParents(path)) {
      LOG(ERROR) << "failed to create dir for " << path;
      return false;
    }
    FileHelper fhelper = FileHelper::OpenWriteOnly(path);
    if (!fhelper) {
      PLOG(ERROR) << "failed to create file " << path;
      return false;
    }
    std::vector<uint8_t> data(entry.uncompressed_length);
    if (ExtractToMemory(handle, &entry, data.data(), data.size()) != 0) {
      LOG(ERROR) << "failed to extract entry " << entry_name;
      return false;
    }
    if (!android::base::WriteFully(fhelper.fd(), data.data(), data.size())) {
      LOG(ERROR) << "failed to write file " << path;
      return false;
    }
  }
  return true;
}

#if defined(__ANDROID__)
class SavedPerfHardenProperty {
 public:
  SavedPerfHardenProperty() {
    __system_property_get("security.perf_harden", prop_value_);
    if (!android::base::ReadFileToString("/proc/sys/kernel/perf_event_paranoid",
                                    &paranoid_value_)) {
      PLOG(ERROR) << "failed to read /proc/sys/kernel/perf_event_paranoid";
    }
  }

  ~SavedPerfHardenProperty() {
    if (strlen(prop_value_) != 0) {
      if (__system_property_set("security.perf_harden", prop_value_) != 0) {
        PLOG(ERROR) << "failed to set security.perf_harden";
        return;
      }
      // Sleep one second to wait for security.perf_harden changing
      // /proc/sys/kernel/perf_event_paranoid.
      sleep(1);
      std::string paranoid_value;
      if (!android::base::ReadFileToString("/proc/sys/kernel/perf_event_paranoid",
                                           &paranoid_value)) {
        PLOG(ERROR) << "failed to read /proc/sys/kernel/perf_event_paranoid";
        return;
      }
      if (paranoid_value_ != paranoid_value) {
        LOG(ERROR) << "failed to restore /proc/sys/kernel/perf_event_paranoid";
      }
    }
  }

 private:
  char prop_value_[PROP_VALUE_MAX];
  std::string paranoid_value_;
};
#endif  // defined(__ANDROID__)
#endif  // defined(IN_CTS_TEST)

int main(int argc, char** argv) {
  InitLogging(argv, android::base::StderrLogger);
  testing::InitGoogleTest(&argc, argv);
  android::base::LogSeverity log_severity = android::base::WARNING;

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
      testdata_dir = argv[i + 1];
      i++;
    } else if (strcmp(argv[i], "--log") == 0) {
      if (i + 1 < argc) {
        ++i;
        if (!GetLogSeverity(argv[i], &log_severity)) {
          LOG(ERROR) << "Unknown log severity: " << argv[i];
          return 1;
        }
      } else {
        LOG(ERROR) << "Missing argument for --log option.\n";
        return 1;
      }
    }
  }
  android::base::ScopedLogSeverity severity(log_severity);

#if defined(IN_CTS_TEST)
  std::unique_ptr<TemporaryDir> tmp_dir;
  if (!::testing::GTEST_FLAG(list_tests) && testdata_dir.empty()) {
    tmp_dir.reset(new TemporaryDir);
    testdata_dir = std::string(tmp_dir->path) + "/";
    if (!ExtractTestDataFromElfSection()) {
      LOG(ERROR) << "failed to extract test data from elf section";
      return 1;
    }
  }

#if defined(__ANDROID__)
  // A cts test PerfEventParanoidTest.java is testing if
  // /proc/sys/kernel/perf_event_paranoid is 3, so restore perf_harden
  // value after current test to not break that test.
  SavedPerfHardenProperty saved_perf_harden;
#endif
#endif
  if (!::testing::GTEST_FLAG(list_tests) && testdata_dir.empty()) {
    printf("Usage: %s -t <testdata_dir>\n", argv[0]);
    return 1;
  }
  if (testdata_dir.back() != '/') {
    testdata_dir.push_back('/');
  }
  LOG(INFO) << "testdata is in " << testdata_dir;
  return RUN_ALL_TESTS();
}

std::string GetTestData(const std::string& filename) {
  return testdata_dir + filename;
}

const std::string& GetTestDataDir() {
  return testdata_dir;
}
