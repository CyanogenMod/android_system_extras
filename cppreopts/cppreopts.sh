#!/system/bin/sh
#
# Copyright (C) 2016 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# create files with 644 (global read) permissions.
umask 022

if [ $# -ne 1 ]; then
  log -p e -t cppreopts "Usage: cppreopts <preopts-mount-point>"
  exit 1
fi

# Where the system_b is mounted that contains the preopt'd files
mountpoint=$1

if ! test -f ${mountpoint}/system-other-odex-marker ; then
  log -p i -t cppreopts "system_other partition does not appear have been built to contain preopted files."
  exit 1
fi

log -p i -t cppreopts "cppreopts from ${mountpoint}"
# For each odex file.
find ${mountpoint} -type f -name "*.odex" | while read odex_file; do
  real_odex_name=${odex_file/${mountpoint}/\/system}
  dest_name=$(preopt2cachename ${real_odex_name})
  # Move to a temporary file so we can do a rename and have the preopted file
  # appear atomically in the filesystem.
  temp_dest_name=${dest_name}.tmp
  if ! test $? -eq 0 ; then
    log -p i -t cppreopts "Unable to figure out destination for ${odex_file}"
    continue
  fi
  if ! cp ${odex_file} ${temp_dest_name} ; then
    log -p w -t cppreopts "Unable to copy odex file ${odex_file} to ${temp_dest_name}!"
  else
    log -p i -t cppreopts "Copied odex file from ${odex_file} to ${temp_dest_name}"
    sync
    if ! mv ${temp_dest_name} ${dest_name} ; then
      log -p w -t cppreopts "Unable to rename temporary odex file from ${temp_dest_name} to ${dest_name}"
    else
      log -p i -t cppreopts "Renamed temporary odex file from ${temp_dest_name} to ${dest_name}"
    fi
  fi
done

exit 0
