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

simpleperf_src_files := \
  cmd_help.cpp \
  cmd_list.cpp \
  command.cpp \
  event_attr.cpp \
  event_fd.cpp \
  event_type.cpp \
  main.cpp \
  utils.cpp \

simpleperf_cppflags := -std=c++11 -Wall -Wextra -Werror -Wunused

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_CPPFLAGS := $(simpleperf_cppflags)
LOCAL_SRC_FILES := $(simpleperf_src_files)
LOCAL_STATIC_LIBRARIES := libbase libcutils liblog
LOCAL_MODULE := simpleperf
LOCAL_MODULE_TAGS := optional
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_EXECUTABLE)

ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_CPPFLAGS := $(simpleperf_cppflags)
LOCAL_SRC_FILES := $(simpleperf_src_files)
LOCAL_STATIC_LIBRARIES := libbase libcutils liblog
LOCAL_LDLIBS := -lrt
LOCAL_MODULE := simpleperf
LOCAL_MODULE_TAGS := optional
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
include $(BUILD_HOST_EXECUTABLE)
endif
