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

LOCAL_PATH := $(call my-dir)

module := simpleperf_runtest_one_function
module_src_files := one_function.cpp
include $(LOCAL_PATH)/Android.build.mk

module := simpleperf_runtest_two_functions
module_src_files := two_functions.cpp
include $(LOCAL_PATH)/Android.build.mk

module := simpleperf_runtest_function_fork
module_src_files := function_fork.cpp
include $(LOCAL_PATH)/Android.build.mk

module := simpleperf_runtest_function_pthread
module_src_files := function_pthread.cpp
include $(LOCAL_PATH)/Android.build.mk

module := simpleperf_runtest_comm_change
module_src_files := comm_change.cpp
include $(LOCAL_PATH)/Android.build.mk

module := simpleperf_runtest_function_recursive
module_src_files := function_recursive.cpp
include $(LOCAL_PATH)/Android.build.mk

module := simpleperf_runtest_function_indirect_recursive
module_src_files := function_indirect_recursive.cpp
include $(LOCAL_PATH)/Android.build.mk