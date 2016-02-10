# Copyright 2016 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

# -----------------------------------------------------------------------------
# Unit tests.
# -----------------------------------------------------------------------------

test_c_flags := \
    -fstack-protector-all \
    -g \
    -Wall -Wextra \
    -Werror \
    -fno-builtin \
    -std=gnu++11

test_src_files := \
    multicast_test.cpp \
    mmc_max_speed_test.cpp \
    pstore_test.cpp \
    sysvipc_test.cpp

include $(CLEAR_VARS)
LOCAL_MODULE := kernel-config-unit-tests
LOCAL_MODULE_TAGS := tests
LOCAL_CFLAGS += $(test_c_flags)
LOCAL_SRC_FILES := $(test_src_files)
include $(BUILD_NATIVE_TEST)

