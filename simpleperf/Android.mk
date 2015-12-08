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

simpleperf_common_cppflags := -Wall -Wextra -Werror -Wunused \

simpleperf_cppflags_target := $(simpleperf_common_cppflags) \

simpleperf_cppflags_host := $(simpleperf_common_cppflags) \
                            -DUSE_BIONIC_UAPI_HEADERS -I bionic/libc/kernel \

simpleperf_cppflags_host_linux := $(simpleperf_cppflags_host) \

simpleperf_cppflags_host_darwin := $(simpleperf_cppflags_host) \
                                   -I $(LOCAL_PATH)/darwin_support/include \

LLVM_ROOT_PATH := external/llvm
include $(LLVM_ROOT_PATH)/llvm.mk

simpleperf_shared_libraries_target := \
  libbacktrace \
  libbase \
  libLLVM \

simpleperf_shared_libraries_host_linux := \
  libbacktrace \
  libbase \

simpleperf_shared_libraries_host_darwin := \
  libbase \
  libLLVM \

simpleperf_ldlibs_host_linux := -lrt \


# libsimpleperf
# =========================================================
libsimpleperf_src_files := \
  callchain.cpp \
  cmd_dumprecord.cpp \
  cmd_help.cpp \
  cmd_report.cpp \
  command.cpp \
  dso.cpp \
  event_attr.cpp \
  event_type.cpp \
  perf_regs.cpp \
  read_elf.cpp \
  record.cpp \
  record_file_reader.cpp \
  sample_tree.cpp \
  thread_tree.cpp \
  utils.cpp \

libsimpleperf_src_files_linux := \
  cmd_list.cpp \
  cmd_record.cpp \
  cmd_stat.cpp \
  dwarf_unwind.cpp \
  environment.cpp \
  event_fd.cpp \
  event_selection_set.cpp \
  record_file_writer.cpp \
  workload.cpp \

libsimpleperf_src_files_darwin := \
  darwin_support/darwin_support.cpp \

# libsimpleperf target
include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_CPPFLAGS := $(simpleperf_cppflags_target)
LOCAL_SRC_FILES := \
  $(libsimpleperf_src_files) \
  $(libsimpleperf_src_files_linux) \

LOCAL_SHARED_LIBRARIES := $(simpleperf_shared_libraries_target)
LOCAL_MULTILIB := first
LOCAL_MODULE := libsimpleperf
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
include $(LLVM_DEVICE_BUILD_MK)
include $(BUILD_STATIC_LIBRARY)

# libsimpleperf linux host
ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_CPPFLAGS := $(simpleperf_cppflags_host_linux)
LOCAL_SRC_FILES := \
  $(libsimpleperf_src_files) \
  $(libsimpleperf_src_files_linux) \

LOCAL_SHARED_LIBRARIES := $(simpleperf_shared_libraries_host_linux)
LOCAL_LDLIBS := $(simpleperf_ldlibs_host_linux)
LOCAL_MULTILIB := first
LOCAL_MODULE := libsimpleperf
LOCAL_MODULE_TAGS := optional
include $(LLVM_HOST_BUILD_MK)
include $(BUILD_HOST_STATIC_LIBRARY)
endif

# libsimpleperf darwin host
ifeq ($(HOST_OS),darwin)
include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_CPPFLAGS := $(simpleperf_cppflags_host_darwin)
LOCAL_SRC_FILES := \
  $(libsimpleperf_src_files) \
  $(libsimpleperf_src_files_darwin) \

LOCAL_SHARED_LIBRARIES := $(simpleperf_shared_libraries_host_darwin)
LOCAL_MULTILIB := first
LOCAL_MODULE := libsimpleperf
LOCAL_MODULE_TAGS := optional
include $(LLVM_HOST_BUILD_MK)
include $(BUILD_HOST_SHARED_LIBRARY)
endif


# simpleperf
# =========================================================

# simpleperf target
include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_CPPFLAGS := $(simpleperf_cppflags_target)
LOCAL_SRC_FILES := main.cpp
LOCAL_WHOLE_STATIC_LIBRARIES := libsimpleperf
LOCAL_SHARED_LIBRARIES := $(simpleperf_shared_libraries_target)
LOCAL_MULTILIB := first
LOCAL_MODULE := simpleperf
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
include $(BUILD_EXECUTABLE)

# simpleperf linux host
ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_CPPFLAGS := $(simpleperf_cppflags_host_linux)
LOCAL_SRC_FILES := main.cpp
LOCAL_WHOLE_STATIC_LIBRARIES := libsimpleperf
LOCAL_SHARED_LIBRARIES := $(simpleperf_shared_libraries_host_linux)
LOCAL_MULTILIB := first
LOCAL_LDLIBS := $(simpleperf_ldlibs_host_linux)
LOCAL_MODULE := simpleperf
LOCAL_MODULE_TAGS := optional
include $(BUILD_HOST_EXECUTABLE)
endif

# simpleperf darwin host
ifeq ($(HOST_OS),darwin)
include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_CPPFLAGS := $(simpleperf_cppflags_host_darwin)
LOCAL_SRC_FILES := main.cpp
LOCAL_SHARED_LIBRARIES := \
  libsimpleperf \
  $(simpleperf_shared_libraries_host_darwin) \

LOCAL_MULTILIB := first
LOCAL_MODULE := simpleperf
LOCAL_MODULE_TAGS := optional
include $(BUILD_HOST_EXECUTABLE)
endif


# simpleperf_unit_test
# =========================================================
simpleperf_unit_test_src_files := \
  command_test.cpp \
  gtest_main.cpp \
  record_test.cpp \
  sample_tree_test.cpp \

simpleperf_unit_test_src_files_linux := \
  cmd_dumprecord_test.cpp \
  cmd_list_test.cpp \
  cmd_record_test.cpp \
  cmd_report_test.cpp \
  cmd_stat_test.cpp \
  environment_test.cpp \
  read_elf_test.cpp \
  record_file_test.cpp \
  workload_test.cpp \

# simpleperf_unit_test target
include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_CPPFLAGS := $(simpleperf_cppflags_target)
LOCAL_SRC_FILES := \
  $(simpleperf_unit_test_src_files) \
  $(simpleperf_unit_test_src_files_linux) \

LOCAL_WHOLE_STATIC_LIBRARIES := libsimpleperf
LOCAL_SHARED_LIBRARIES := $(simpleperf_shared_libraries_target)
LOCAL_MULTILIB := first
LOCAL_MODULE := simpleperf_unit_test
LOCAL_MODULE_TAGS := optional
include $(BUILD_NATIVE_TEST)

# simpleperf_unit_test linux host
ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_CPPFLAGS := $(simpleperf_cppflags_host_linux)
LOCAL_SRC_FILES := \
  $(simpleperf_unit_test_src_files) \
  $(simpleperf_unit_test_src_files_linux) \

LOCAL_WHOLE_STATIC_LIBRARIES := libsimpleperf
LOCAL_SHARED_LIBRARIES := $(simpleperf_shared_libraries_host_linux)
LOCAL_MULTILIB := first
LOCAL_MODULE := simpleperf_unit_test
LOCAL_MODULE_TAGS := optional
include $(BUILD_HOST_NATIVE_TEST)
endif

# simpleperf_unit_test darwin host
ifeq ($(HOST_OS),darwin)
include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_CPPFLAGS := $(simpleperf_cppflags_host_darwin)
LOCAL_SRC_FILES := $(simpleperf_unit_test_src_files)
LOCAL_SHARED_LIBRARIES := \
  libsimpleperf \
  $(simpleperf_shared_libraries_host_darwin) \

LOCAL_MULTILIB := first
LOCAL_MODULE := simpleperf_unit_test
LOCAL_MODULE_TAGS := optional
include $(BUILD_HOST_NATIVE_TEST)
endif


# simpleperf_cpu_hotplug_test
# =========================================================
simpleperf_cpu_hotplug_test_src_files := \
  gtest_main.cpp \
  cpu_hotplug_test.cpp \

# simpleperf_cpu_hotplug_test target
include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_CPPFLAGS := $(simpleperf_cppflags_target)
LOCAL_SRC_FILES := $(simpleperf_cpu_hotplug_test_src_files)
LOCAL_WHOLE_STATIC_LIBRARIES := libsimpleperf
LOCAL_SHARED_LIBRARIES := $(simpleperf_shared_libraries_target)
LOCAL_MULTILIB := first
LOCAL_MODULE := simpleperf_cpu_hotplug_test
LOCAL_MODULE_TAGS := optional
include $(BUILD_NATIVE_TEST)

# simpleperf_cpu_hotplug_test linux host
ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_CPPFLAGS := $(simpleperf_cppflags_host_linux)
LOCAL_SRC_FILES := $(simpleperf_cpu_hotplug_test_src_files)
LOCAL_WHOLE_STATIC_LIBRARIES := libsimpleperf
LOCAL_SHARED_LIBRARIES := $(simpleperf_shared_libraries_host_linux)
LOCAL_MULTILIB := first
LOCAL_MODULE := simpleperf_cpu_hotplug_test
LOCAL_MODULE_TAGS := optional
include $(BUILD_HOST_NATIVE_TEST)
endif

include $(call first-makefiles-under,$(LOCAL_PATH))