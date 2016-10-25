/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <iostream>

#include <android-base/logging.h>
#include <android-base/strings.h>

#ifndef LOG_TAG
#define LOG_TAG "preopt2cachename"
#endif

static const char* kDalvikCacheDir = "/data/dalvik-cache/";
static const char* kCacheSuffix = "@classes.dex";

// Returns the ISA extracted from the odex_file_location.
// odex_file_location is formatted like /system/app/<app_name>/oat/<isa>/<app_name>.odex for all
// functions. We return an empty string "" in error cases.
static std::string ExtractISA(const std::string& odex_file_location) {
  std::vector<std::string> split_file_location = android::base::Split(odex_file_location, "/");
  if (split_file_location.size() <= 1) {
    return "";
  } else if (split_file_location.size() != 7) {
    LOG(WARNING) << "Unexpected length for odex-file-location. We expected 7 segments but found "
                 << split_file_location.size();
  }
  return split_file_location[split_file_location.size() - 2];
}

// Returns the apk name extracted from the odex_file_location.
// odex_file_location is formatted like /system/app/<app_name>/oat/<isa>/<app_name>.odex. We return
// the final <app_name> with the .odex replaced with .apk.
static std::string ExtractAPKName(const std::string& odex_file_location) {
  // Find and copy filename.
  size_t file_location_start = odex_file_location.rfind('/');
  if (file_location_start == std::string::npos) {
    return "";
  }
  size_t ext_start = odex_file_location.rfind('.');
  if (ext_start == std::string::npos || ext_start < file_location_start) {
    return "";
  }
  std::string apk_name = odex_file_location.substr(file_location_start + 1,
                                                   ext_start - file_location_start);

  // Replace extension with .apk.
  apk_name += "apk";
  return apk_name;
}

// The cache file name is /data/dalvik-cache/<isa>/ prior to this function
static bool OdexFilenameToCacheFile(const std::string& odex_file_location,
                                    /*in-out*/std::string& cache_file) {
  // Skip the first '/' in odex_file_location.
  size_t initial_position = odex_file_location[0] == '/' ? 1 : 0;
  size_t apk_position = odex_file_location.find("/oat", initial_position);
  if (apk_position == std::string::npos) {
    LOG(ERROR) << "Unable to find oat directory!";
    return false;
  }

  size_t cache_file_position = cache_file.size();
  cache_file += odex_file_location.substr(initial_position, apk_position);
  // '/' -> '@' up to where the apk would be.
  cache_file_position = cache_file.find('/', cache_file_position);
  while (cache_file_position != std::string::npos) {
    cache_file[cache_file_position] = '@';
    cache_file_position = cache_file.find('/', cache_file_position);
  }

  // Add <apk_name>.
  std::string apk_name = ExtractAPKName(odex_file_location);
  if (apk_name.empty()) {
    LOG(ERROR) << "Unable to determine apk name from odex file name '" << odex_file_location << "'";
    return false;
  }
  cache_file += apk_name;
  cache_file += kCacheSuffix;
  return true;
}

// Do the overall transformation from odex_file_location to output_file_location. Prior to this the
// output_file_location is empty.
static bool OdexToCacheFile(std::string& odex_file_location,
                            /*out*/std::string& output_file_location) {
  std::string isa = ExtractISA(odex_file_location);
  if (isa.empty()) {
    LOG(ERROR) << "Unable to determine isa for odex file '" << odex_file_location << "', skipping";
    return false;
  }
  output_file_location += isa;
  output_file_location += '/';
  return OdexFilenameToCacheFile(odex_file_location, output_file_location);
}

// This program is used to determine where in the /data directory the runtime will search for an
// odex file if it is unable to find one at the given 'preopt-name' location. This is used to allow
// us to store these preopted files in the unused system_b partition and copy them out on first
// boot of the device.
int main(int argc, char *argv[]) {
  if (argc != 2) {
    LOG(ERROR) << "usage: preopt2cachename preopt-location";
    return 2;
  }
  std::string odex_file_location(argv[1]);
  std::string output_file_location(kDalvikCacheDir);
  if (!OdexToCacheFile(odex_file_location, output_file_location)) {
    return 1;
  } else {
    std::cout << output_file_location;
  }
  return 0;
}
