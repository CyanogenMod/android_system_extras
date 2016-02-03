# Copyright (C) 2008 The Android Open Source Project
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

LOCAL_PATH := $(call my-dir)

pagemap_src_files := \
    pm_kernel.c \
    pm_process.c \
    pm_map.c \
    pm_memusage.c \

include $(CLEAR_VARS)
LOCAL_MODULE := libpagemap
LOCAL_MODULE_TAGS := debug
LOCAL_SRC_FILES := $(pagemap_src_files)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CFLAGS := -Wno-unused-parameter
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := pagemap_test
LOCAL_SRC_FILES := pagemap_test.cpp
LOCAL_SHARED_LIBRARIES := libpagemap
include $(BUILD_NATIVE_TEST)
