#
# Copyright (C) 2014 The Android Open Source Project
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

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  mmapPerf.cpp
LOCAL_MODULE := mmapPerf
LOCAL_MULTILIB := both
LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64
LOCAL_CLANG := true
LOCAL_CFLAGS += -g -Wall -Werror -std=c++11 -Wno-missing-field-initializers -Wno-sign-compare -O3
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_CXX_STL := libc++_static
LOCAL_STATIC_LIBRARIES := libc
include $(BUILD_NATIVE_BENCHMARK)
