/*
**
** Copyright 2015, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <sstream>

#include <android-base/file.h>

#include "configreader.h"
#include "perfprofdutils.h"

//
// Config file path
//
static const char *config_file_path =
    "/data/data/com.google.android.gms/files/perfprofd.conf";

ConfigReader::ConfigReader()
    : trace_config_read(false)
{
  addDefaultEntries();
}

ConfigReader::~ConfigReader()
{
}

const char *ConfigReader::getConfigFilePath()
{
  return config_file_path;
}

void ConfigReader::setConfigFilePath(const char *path)
{
  config_file_path = strdup(path);
  W_ALOGI("config file path set to %s", config_file_path);
}

//
// Populate the reader with the set of allowable entries
//
void ConfigReader::addDefaultEntries()
{
  // Average number of seconds between perf profile collections (if
  // set to 100, then over time we want to see a perf profile
  // collected every 100 seconds). The actual time within the interval
  // for the collection is chosen randomly.
  addUnsignedEntry("collection_interval", 14400, 100, UINT32_MAX);

  // Use the specified fixed seed for random number generation (unit
  // testing)
  addUnsignedEntry("use_fixed_seed", 0, 0, UINT32_MAX);

  // For testing purposes, number of times to iterate through main
  // loop.  Value of zero indicates that we should loop forever.
  addUnsignedEntry("main_loop_iterations", 0, 0, UINT32_MAX);

  // Destination directory (where to write profiles). This location
  // chosen since it is accessible to the uploader service.
  addStringEntry("destination_directory", "/data/misc/perfprofd");

  // Config directory (where to read configs).
  addStringEntry("config_directory", "/data/data/com.google.android.gms/files");

  // Full path to 'perf' executable.
  addStringEntry("perf_path", "/system/xbin/simpleperf");

  // Desired sampling period (passed to perf -c option). Small
  // sampling periods can perturb the collected profiles, so enforce
  // min/max.
  addUnsignedEntry("sampling_period", 500000, 5000, UINT32_MAX);

  // Length of time to collect samples (number of seconds for 'perf
  // record -a' run).
  addUnsignedEntry("sample_duration", 3, 2, 600);

  // If this parameter is non-zero it will cause perfprofd to
  // exit immediately if the build type is not userdebug or eng.
  // Currently defaults to 1 (true).
  addUnsignedEntry("only_debug_build", 1, 0, 1);

  // If the "mpdecision" service is running at the point we are ready
  // to kick off a profiling run, then temporarily disable the service
  // and hard-wire all cores on prior to the collection run, provided
  // that the duration of the recording is less than or equal to the value of
  // 'hardwire_cpus_max_duration'.
  addUnsignedEntry("hardwire_cpus", 1, 0, 1);
  addUnsignedEntry("hardwire_cpus_max_duration", 5, 1, UINT32_MAX);

  // Maximum number of unprocessed profiles we can accumulate in the
  // destination directory. Once we reach this limit, we continue
  // to collect, but we just overwrite the most recent profile.
  addUnsignedEntry("max_unprocessed_profiles", 10, 1, UINT32_MAX);

  // If set to 1, pass the -g option when invoking 'perf' (requests
  // stack traces as opposed to flat profile).
  addUnsignedEntry("stack_profile", 0, 0, 1);

  // For unit testing only: if set to 1, emit info messages on config
  // file parsing.
  addUnsignedEntry("trace_config_read", 0, 0, 1);

  // Control collection of various additional profile tags
  addUnsignedEntry("collect_cpu_utilization", 1, 0, 1);
  addUnsignedEntry("collect_charging_state", 1, 0, 1);
  addUnsignedEntry("collect_booting", 1, 0, 1);
  addUnsignedEntry("collect_camera_active", 0, 0, 1);
}

void ConfigReader::addUnsignedEntry(const char *key,
                                    unsigned default_value,
                                    unsigned min_value,
                                    unsigned max_value)
{
  std::string ks(key);
  if (u_entries.find(ks) != u_entries.end() ||
      s_entries.find(ks) != s_entries.end()) {
    W_ALOGE("internal error -- duplicate entry for key %s", key);
    exit(9);
  }
  values vals;
  vals.minv = min_value;
  vals.maxv = max_value;
  u_info[ks] = vals;
  u_entries[ks] = default_value;
}

void ConfigReader::addStringEntry(const char *key, const char *default_value)
{
  std::string ks(key);
  if (u_entries.find(ks) != u_entries.end() ||
      s_entries.find(ks) != s_entries.end()) {
    W_ALOGE("internal error -- duplicate entry for key %s", key);
    exit(9);
  }
  if (default_value == nullptr) {
    W_ALOGE("internal error -- bad default value for key %s", key);
    exit(9);
  }
  s_entries[ks] = std::string(default_value);
}

unsigned ConfigReader::getUnsignedValue(const char *key) const
{
  std::string ks(key);
  auto it = u_entries.find(ks);
  assert(it != u_entries.end());
  return it->second;
}

std::string ConfigReader::getStringValue(const char *key) const
{
  std::string ks(key);
  auto it = s_entries.find(ks);
  assert(it != s_entries.end());
  return it->second;
}

void ConfigReader::overrideUnsignedEntry(const char *key, unsigned new_value)
{
  std::string ks(key);
  auto it = u_entries.find(ks);
  assert(it != u_entries.end());
  values vals;
  auto iit = u_info.find(key);
  assert(iit != u_info.end());
  vals = iit->second;
  assert(new_value >= vals.minv && new_value <= vals.maxv);
  it->second = new_value;
  W_ALOGI("option %s overridden to %u", key, new_value);
}


//
// Parse a key=value pair read from the config file. This will issue
// warnings or errors to the system logs if the line can't be
// interpreted properly.
//
void ConfigReader::parseLine(const char *key,
                             const char *value,
                             unsigned linecount)
{
  assert(key);
  assert(value);

  auto uit = u_entries.find(key);
  if (uit != u_entries.end()) {
    unsigned uvalue = 0;
    if (isdigit(value[0]) == 0 || sscanf(value, "%u", &uvalue) != 1) {
      W_ALOGW("line %d: malformed unsigned value (ignored)", linecount);
    } else {
      values vals;
      auto iit = u_info.find(key);
      assert(iit != u_info.end());
      vals = iit->second;
      if (uvalue < vals.minv || uvalue > vals.maxv) {
        W_ALOGW("line %d: specified value %u for '%s' "
                "outside permitted range [%u %u] (ignored)",
                linecount, uvalue, key, vals.minv, vals.maxv);
      } else {
        if (trace_config_read) {
          W_ALOGI("option %s set to %u", key, uvalue);
        }
        uit->second = uvalue;
      }
    }
    trace_config_read = (getUnsignedValue("trace_config_read") != 0);
    return;
  }

  auto sit = s_entries.find(key);
  if (sit != s_entries.end()) {
    if (trace_config_read) {
      W_ALOGI("option %s set to %s", key, value);
    }
    sit->second = std::string(value);
    return;
  }

  W_ALOGW("line %d: unknown option '%s' ignored", linecount, key);
}

static bool isblank(const std::string &line)
{
  for (std::string::const_iterator it = line.begin(); it != line.end(); ++it)
  {
    if (isspace(*it) == 0) {
      return false;
    }
  }
  return true;
}

bool ConfigReader::readFile()
{
  std::string contents;
  if (! android::base::ReadFileToString(config_file_path, &contents)) {
    return false;
  }

  std::stringstream ss(contents);
  std::string line;
  for (unsigned linecount = 1;
       std::getline(ss,line,'\n');
       linecount += 1)
  {

    // comment line?
    if (line[0] == '#') {
      continue;
    }

    // blank line?
    if (isblank(line.c_str())) {
      continue;
    }

    // look for X=Y assignment
    auto efound = line.find('=');
    if (efound == std::string::npos) {
      W_ALOGW("line %d: line malformed (no '=' found)", linecount);
      continue;
    }

    std::string key(line.substr(0, efound));
    std::string value(line.substr(efound+1, std::string::npos));

    parseLine(key.c_str(), value.c_str(), linecount);
  }

  return true;
}
