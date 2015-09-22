#!/system/bin/sh

#
# Copyright (C) 2015 The Android Open Source Project
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
#

# This is an example post-install script. This script will be executed by the
# update_engine right after finishing writing all the partitions, but before
# marking the new slot as active.
#
# This script receives no arguments. argv[0] will include the absolute path to
# the script, including the temporary directory where the new partition was
# mounted.
#
# This script will run in the context of the old kernel and old system. Note
# that the absolute path used in first line of this script (/system/bin/sh) is
# indeed the old system's sh binary. If you use a compiled program, you might
# want to link it statically or use a wrapper script to use the new ldso to run
# your program (see the --generate-wrappers option in lddtree.py for example).
#
# If the exit code of this program is an error code (different from 0), the
# update will fail and the new slot will not be marked as active.

exit 0
